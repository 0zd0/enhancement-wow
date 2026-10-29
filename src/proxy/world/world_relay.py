import hmac
import struct
import zlib
from dataclasses import dataclass
from typing import Callable

from .world_crypto import (
    CONTINUED_SEED,
    decrypt,
    derive_encryption,
    derive_session,
    encrypt,
    mac,
)
from .world_packets import MULTIPLE, split_messages
from .world_protocol import (
    ADLER_SEED,
    AUTH_CHALLENGE,
    AUTH_CONTINUED,
    AUTH_SESSION,
    COMPRESSED,
    ENCRYPTED_ACK,
    ENTER_ENCRYPTED,
    LIMIT,
    WireStream,
)


@dataclass(frozen=True)
class GamePacket:
    flow_id: str
    from_client: bool
    opcode: int
    payload: bytes


Transform = Callable[[GamePacket], GamePacket | list[GamePacket]]


class WorldRelay:
    def __init__(self, flow_id: str, keys, transform: Transform):
        self.flow_id = flow_id
        self.keys = keys
        self.transform = transform
        self.wire = WireStream()
        self.server = b""
        self.candidates = []
        self.key = None
        self.armed = False
        self.encrypted = False

        # Раздельные словари исходного и изменённого серверного потока.
        self.inflater = zlib.decompressobj(-15)
        self.compressor = zlib.compressobj(wbits=-15)

    def _learn(self, client: bool, opcode: int, payload: bytes):
        if not client and opcode == AUTH_CHALLENGE:
            if len(payload) != 65:
                raise ValueError("Unsupported AuthChallenge")
            self.server = payload[32:64]

        elif client and opcode in (AUTH_SESSION, AUTH_CONTINUED):
            if len(self.server) != 32:
                raise ValueError("AuthChallenge is missing")

            if opcode == AUTH_SESSION:
                if len(payload) < 76:
                    raise ValueError("Short AuthSession")
                local = payload[20:52]
                sessions = [
                    derive_session(data, self.server, local)
                    for data in self.keys.key_data
                ]
            else:
                if len(payload) < 72:
                    raise ValueError("Short AuthContinuedSession")
                local = payload[8:40]
                proof = payload[40:64]
                connection_key = payload[64:72]

                sessions = [
                    session
                    for session in self.keys.sessions
                    if hmac.compare_digest(
                        mac(
                            session,
                            connection_key
                            + local
                            + self.server
                            + CONTINUED_SEED,
                        )[:24],
                        proof,
                    )
                ]

            if not sessions:
                raise ValueError(
                    "No session secrets: start proxy before WoW login"
                )

            for session in sessions:
                self.keys.add_session(session)

            self.candidates = [
                derive_encryption(session, self.server, local)
                for session in sessions
            ]

        elif not client and opcode == ENTER_ENCRYPTED:
            if len(payload) != 69:
                raise ValueError("Unsupported EnterEncryptedMode")
            self.armed = bool(payload[-1] & 0x80)

        elif client and opcode == ENCRYPTED_ACK:
            if not self.armed or not self.candidates:
                raise ValueError("Encryption ACK without keys")
            self.encrypted = True

    def _decrypt(self, client, counter, tag, body):
        if self.key is not None:
            return decrypt(self.key, client, counter, tag, body)

        for candidate in self.candidates:
            try:
                plain = decrypt(candidate, client, counter, tag, body)
            except ValueError:
                continue

            self.key = candidate
            return plain

        raise ValueError(
            f"No AES key passed GCM verification: counter={counter}"
        )

    def _map(self, client: bool, opcode: int, payload: bytes) -> bytes:
        output = []
        source = (
            [(opcode, payload)]
            if client
            else split_messages(opcode, payload)
        )

        for code, data in source:
            packet = GamePacket(self.flow_id, client, code, data)
            changed = self.transform(packet)
            if isinstance(changed, GamePacket):
                changed = [changed]

            if not isinstance(changed, list) or not changed:
                raise ValueError(
                    "Callback must return GamePacket or nonempty list"
                )

            for item in changed:
                if not isinstance(item, GamePacket):
                    raise TypeError("Callback returned an invalid packet")
                if (
                        item.flow_id != self.flow_id
                        or item.from_client != client
                ):
                    raise ValueError(
                        "Callback changed packet connection/direction"
                    )

            output.extend(changed)

        if client and len(output) != 1:
            raise ValueError("Client packet expansion is unsupported")

        if not client and (opcode == MULTIPLE or len(output) != 1):
            body = bytearray(struct.pack("<I", MULTIPLE))
            for item in output:
                if len(item.payload) > 65535:
                    raise ValueError("Inner packet exceeds uint16 size")
                body.extend(
                    struct.pack("<HI", len(item.payload), item.opcode)
                )
                body.extend(item.payload)
            return bytes(body)

        item = output[0]
        return struct.pack("<I", item.opcode) + item.payload

    def feed(self, client: bool, data: bytes) -> bytes:
        greeted = self.wire.greeted[client]
        frames = list(self.wire.feed(client, data))
        output = bytearray()

        if not greeted and self.wire.greeted[client]:
            direction = (
                "CLIENT TO SERVER" if client else "SERVER TO CLIENT"
            )
            output.extend(
                f"WORLD OF WARCRAFT CONNECTION - {direction} - V2\n".encode()
            )

        for counter, tag, body in frames:
            if not self.encrypted:
                if any(tag):
                    raise ValueError("Encrypted data before ACK")

                self._learn(
                    client,
                    int.from_bytes(body[:4], "little"),
                    body[4:],
                )
                output.extend(
                    struct.pack("<I", len(body)) + tag + body
                )
                continue

            plain = self._decrypt(client, counter, tag, body)
            opcode = int.from_bytes(plain[:4], "little")
            payload = plain[4:]
            compressed = not client and opcode == COMPRESSED

            if compressed:
                if len(payload) < 12:
                    raise ValueError("Short compression header")

                size, plain_sum, packed_sum = struct.unpack_from(
                    "<III", payload
                )
                packed = payload[12:]

                if (
                        not 4 <= size <= LIMIT
                        or zlib.adler32(packed, ADLER_SEED) != packed_sum
                ):
                    raise ValueError("Invalid compressed packet")

                plain = self.inflater.decompress(packed, size + 1)
                if (
                        len(plain) != size
                        or self.inflater.unconsumed_tail
                        or self.inflater.unused_data
                        or zlib.adler32(plain, ADLER_SEED) != plain_sum
                ):
                    raise ValueError("Invalid decompressed packet")

                opcode = int.from_bytes(plain[:4], "little")
                payload = plain[4:]

            changed = self._map(client, opcode, payload)

            if compressed:
                packed = (
                        self.compressor.compress(changed)
                        + self.compressor.flush(zlib.Z_SYNC_FLUSH)
                )
                info = struct.pack(
                    "<III",
                    len(changed),
                    zlib.adler32(changed, ADLER_SEED),
                    zlib.adler32(packed, ADLER_SEED),
                )
                changed = (
                        struct.pack("<I", COMPRESSED) + info + packed
                )

            if len(changed) > LIMIT:
                raise ValueError("Rewritten packet exceeds size limit")

            tag, ciphertext = encrypt(
                self.key, client, counter, changed
            )
            output.extend(
                struct.pack("<I", len(ciphertext)) + tag + ciphertext
            )

        return bytes(output)
