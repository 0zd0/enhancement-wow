import struct


MULTIPLE = 0x4C000D
LOGIN_TIME = 0x4501B8
GAME_TIME_SET = 0x4501B7
GAME_TIME_UPDATE = 0x4501B6
PRINT_NOTIFICATION = 0x45006E

NAMES = {
    LOGIN_TIME: "SMSG_LOGIN_SET_TIME_SPEED",
    GAME_TIME_SET: "SMSG_GAME_TIME_SET",
    GAME_TIME_UPDATE: "SMSG_GAME_TIME_UPDATE",
    PRINT_NOTIFICATION: "SMSG_PRINT_NOTIFICATION",
}


def split_messages(opcode: int, payload: bytes, depth: int = 0):
    if depth > 8:
        raise ValueError("Too many nested SMSG_MULTIPLE_PACKETS")

    if opcode != MULTIPLE:
        yield opcode, payload
        return

    offset = 0
    while offset < len(payload):
        if len(payload) - offset < 6:
            raise ValueError("Incomplete MULTIPLE_PACKETS header")

        size, child_opcode = struct.unpack_from("<HI", payload, offset)
        offset += 6
        end = offset + size

        if end > len(payload):
            raise ValueError("Incomplete MULTIPLE_PACKETS body")

        yield from split_messages(
            child_opcode, payload[offset:end], depth + 1
        )
        offset = end


def packed_time(value: int) -> dict:
    return {
        "year": 2000 + ((value >> 24) & 31),
        "month": 1 + ((value >> 20) & 15),
        "day": 1 + ((value >> 14) & 63),
        "hour": (value >> 6) & 31,
        "minute": value & 63,
    }


def decode_game_packets(opcode: int, payload: bytes) -> list[dict]:
    result = []

    for code, data in split_messages(opcode, payload):
        item = {
            "opcode": f"0x{code:06X}",
            "name": NAMES.get(code),
            "payload_size": len(data),
        }

        if code == LOGIN_TIME:
            if len(data) != 20:
                raise ValueError(
                    f"Unexpected LOGIN_SET_TIME_SPEED size: {len(data)}"
                )

            server, game, speed, server_offset, game_offset = (
                struct.unpack("<IIfii", data)
            )
            item["fields"] = {
                "ServerTime": packed_time(server),
                "GameTime": packed_time(game),
                "NewSpeed": speed,
                "ServerTimeHolidayOffset": server_offset,
                "GameTimeHolidayOffset": game_offset,
            }

        elif code in (GAME_TIME_SET, GAME_TIME_UPDATE):
            if len(data) != 16:
                raise ValueError(f"Unexpected GAME_TIME size: {len(data)}")

            server, game, server_offset, game_offset = (
                struct.unpack("<IIii", data)
            )
            item["fields"] = {
                "ServerTime": packed_time(server),
                "GameTime": packed_time(game),
                "ServerTimeHolidayOffset": server_offset,
                "GameTimeHolidayOffset": game_offset,
            }

        elif code == PRINT_NOTIFICATION:
            if len(data) < 2:
                raise ValueError("Short notification")

            length = int.from_bytes(data[:2], "big") >> 4
            if len(data) != length + 2:
                raise ValueError("Invalid notification length")

            item["fields"] = {
                "NotifyText": data[2:].decode("utf-8", errors="replace")
            }

        result.append(item)

    return result
