import hmac
import struct
import zlib
from dataclasses import dataclass

from proxy.world.world_crypto import CONTINUED_SEED, decrypt, derive_session, mac
from .world_packets import decode_game_packets

AUTH_SESSION = 0x440001
AUTH_CONTINUED = 0x440003
ENCRYPTED_ACK = 0x440005
AUTH_CHALLENGE = 0x4C0000
ENTER_ENCRYPTED = 0x4C0004
COMPRESSED = 0x4C000E

NAMES = {
    AUTH_SESSION: "CMSG_AUTH_SESSION",
    AUTH_CONTINUED: "CMSG_AUTH_CONTINUED_SESSION",
    ENCRYPTED_ACK: "CMSG_ENTER_ENCRYPTED_MODE_ACK",
    AUTH_CHALLENGE: "SMSG_AUTH_CHALLENGE",
    ENTER_ENCRYPTED: "SMSG_ENTER_ENCRYPTED_MODE",
    COMPRESSED: "SMSG_COMPRESSED_PACKET",
}

LIMIT = 16 * 1024 * 1024
ADLER_SEED = 0x9827D8F1


class WireStream:
    def __init__(self):
        self.buffers = {True: bytearray(), False: bytearray()}
        self.greeted = {True: False, False: False}
        self.counters = {True: 0, False: 0}

    def feed(self, client: bool, data: bytes):
        buffer = self.buffers[client]
        buffer.extend(data)

        if not self.greeted[client]:
            direction = "CLIENT TO SERVER" if client else "SERVER TO CLIENT"
            greeting = (
                f"WORLD OF WARCRAFT CONNECTION - {direction} - V2\n"
            ).encode()

            if len(buffer) < len(greeting):
                if not greeting.startswith(buffer):
                    raise ValueError("Missing WoW V2 greeting")
                return

            if buffer[:len(greeting)] != greeting:
                raise ValueError("Unexpected greeting or incomplete capture")

            del buffer[:len(greeting)]
            self.greeted[client] = True

        while len(buffer) >= 16:
            size = int.from_bytes(buffer[:4], "little")
            if not 4 <= size <= LIMIT:
                raise ValueError(f"Invalid world frame size: {size}")
            if len(buffer) < 16 + size:
                return

            tag = bytes(buffer[4:16])
            body = bytes(buffer[16:16 + size])
            del buffer[:16 + size]

            # Считаются также кадры ДО включения шифрования.
            counter = self.counters[client]
            self.counters[client] += 1
            yield counter, tag, body


@dataclass(frozen=True)
class Handshake:
    kind: int
    server: bytes
    client: bytes
    proof: bytes
    connection_key: bytes


def handshake(messages) -> Handshake | None:
    wire = WireStream()
    server, auth = None, None

    for message in messages:
        for _, tag, body in wire.feed(message.from_client, message.content):
            opcode = int.from_bytes(body[:4], "little")
            payload = body[4:]

            if not message.from_client and opcode == AUTH_CHALLENGE:
                if len(payload) != 65:
                    raise ValueError("Unsupported AuthChallenge layout")
                server = payload[32:64]

            elif message.from_client and opcode == AUTH_SESSION:
                if len(payload) < 76:
                    raise ValueError("Short AuthSession")
                auth = (
                    opcode,
                    payload[20:52],
                    payload[52:76],
                    b"",
                )

            elif message.from_client and opcode == AUTH_CONTINUED:
                if len(payload) < 72:
                    raise ValueError("Short AuthContinuedSession")
                auth = (
                    opcode,
                    payload[8:40],
                    payload[40:64],
                    payload[64:72],
                )

            if server is not None and auth is not None:
                kind, client, proof, connection_key = auth
                return Handshake(kind, server, client, proof, connection_key)

    return None


def session_for(target: Handshake, key_data: bytes, flows) -> bytes:
    if target.kind == AUTH_SESSION:
        return derive_session(key_data, target.server, target.client)

    # Продолжение сессии использует session key первого соединения.
    for flow in flows:
        try:
            initial = handshake(flow.messages)
        except ValueError:
            continue

        if initial is None or initial.kind != AUTH_SESSION:
            continue

        candidate = derive_session(key_data, initial.server, initial.client)
        proof = mac(
            candidate,
            target.connection_key
            + target.client
            + target.server
            + CONTINUED_SEED,
        )
        if hmac.compare_digest(proof[:24], target.proof):
            return candidate

    raise ValueError(
        "No matching initial realm session: "
        "load its 3724 flow and use the same login secrets"
    )


class WorldSession:
    def __init__(self, encryption_key: bytes):
        self.key = encryption_key
        self.wire = WireStream()
        self.armed = False
        self.encrypted = False
        self.inflater = zlib.decompressobj(-15)

    def feed(self, client: bool, data: bytes) -> list[dict]:
        result = []

        for counter, tag, body in self.wire.feed(client, data):
            encrypted = self.encrypted
            if encrypted:
                body = decrypt(self.key, client, counter, tag, body)
            elif any(tag):
                raise ValueError("Nonzero tag before encryption ACK")

            opcode = int.from_bytes(body[:4], "little")
            payload = body[4:]
            compressed = not client and opcode == COMPRESSED

            if compressed:
                if len(payload) < 12:
                    raise ValueError("Short compression header")

                size, plain_sum, packed_sum = struct.unpack_from("<III", payload)
                packed = payload[12:]

                if (
                        not 4 <= size <= LIMIT
                        or zlib.adler32(packed, ADLER_SEED) != packed_sum
                ):
                    raise ValueError("Invalid compressed packet size/checksum")

                body = self.inflater.decompress(packed, size + 1)
                if (
                        len(body) != size
                        or self.inflater.unconsumed_tail
                        or self.inflater.unused_data
                        or zlib.adler32(body, ADLER_SEED) != plain_sum
                ):
                    raise ValueError("Invalid decompressed packet size/checksum")

                opcode = int.from_bytes(body[:4], "little")
                payload = body[4:]

            if not encrypted:
                if not client and opcode == ENTER_ENCRYPTED:
                    if len(payload) != 69:
                        raise ValueError("Unsupported EnterEncryptedMode layout")
                    self.armed = bool(payload[-1] & 0x80)

                elif client and opcode == ENCRYPTED_ACK:
                    if not self.armed:
                        raise ValueError("Encryption ACK without EnterEncryptedMode")
                    self.encrypted = True

            result.append({
                "direction": "client -> server" if client else "server -> client",
                "counter": counter,
                "encryption": "AES-GCM verified" if encrypted else "plaintext",
                "compressed": compressed,
                "opcode": f"0x{opcode:06X}",
                "name": NAMES.get(opcode),
                "payload_size": len(payload),
                # "preview_hex": payload[:256].hex(),
                "preview_truncated": len(payload) > 256,
                "messages": decode_game_packets(opcode, payload) if not client else [],
            })

        return result
