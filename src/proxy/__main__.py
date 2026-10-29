import argparse
import asyncio
import logging
import math
import struct
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

from .game_proxy import GameProxy
from .world.world_packets import (
    GAME_TIME_SET,
    GAME_TIME_UPDATE,
    LOGIN_TIME,
    PRINT_NOTIFICATION,
)
from .world.world_relay import GamePacket

logging.getLogger().setLevel(logging.INFO)


def clock_modifier(
    factor: float,
    hour: int | None,
    minute: int,
    notify: bool,
    force_hour: bool = False,
):
    def change(packet: GamePacket):
        if packet.from_client or packet.opcode not in (
            LOGIN_TIME,
            GAME_TIME_SET,
            GAME_TIME_UPDATE,
        ):
            return packet

        expected = 20 if packet.opcode == LOGIN_TIME else 16
        if len(packet.payload) != expected:
            raise ValueError("Unsupported time packet layout")

        data = bytearray(packet.payload)

        if packet.opcode == LOGIN_TIME:
            old_speed = struct.unpack_from("<f", data, 8)[0]
            new_speed = old_speed * factor
            if not math.isfinite(new_speed):
                raise ValueError("Invalid time speed")
            struct.pack_into("<f", data, 8, new_speed)
            logging.info(
                "CLOCK speed: %g -> %g",
                old_speed,
                new_speed,
            )

        if hour is not None and (
                packet.opcode == LOGIN_TIME or force_hour
        ):
            for offset in (0, 4):  # ServerTime, GameTime
                old_time = struct.unpack_from("<I", data, offset)[0]
                new_time = (old_time & ~0x7FF) | (hour << 6) | minute
                struct.pack_into("<I", data, offset, new_time)

            logging.info(
                "CLOCK opcode=0x%06X flow=%s -> %02d:%02d",
                packet.opcode, packet.flow_id[:8], hour, minute,
            )

        changed = replace(packet, payload=bytes(data))

        if notify and packet.opcode == LOGIN_TIME:
            text = b"Proxy: time patch applied"
            notification = (
                (len(text) << 4).to_bytes(2, "big") + text
            )
            return [
                changed,
                replace(
                    packet,
                    opcode=PRINT_NOTIFICATION,
                    payload=notification,
                ),
            ]

        return changed

    return change


async def run(args):
    options = Options(
        mode=[f"local:{args.process}"],
        tcp_hosts=[".*"],
        ssl_insecure=True,
    )
    master = DumpMaster(options, with_dumper=False)
    master.addons.add(
        GameProxy(
            clock_modifier(
                args.factor,
                args.hour,
                args.minute,
                args.notify,
                force_hour=args.force_hour,
            )
        )
    )

    output = (
        Path("dumps")
        / f"{datetime.now():%Y%m%d-%H%M%S-%f}.mitm"
    )
    options.update(save_stream_file=str(output))
    logging.info("Saving forwarded traffic to %s", output)
    await master.run()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--process", default="World of Warcraft"
    )
    parser.add_argument("--factor", type=float, default=1.0)
    parser.add_argument("--hour", type=int)
    parser.add_argument("--minute", type=int, default=0)
    parser.add_argument("--notify", action="store_true")
    parser.add_argument("--force-hour", action="store_true")
    args = parser.parse_args()

    if not math.isfinite(args.factor) or args.factor <= 0:
        parser.error("--factor must be finite and positive")
    if args.hour is not None and not 0 <= args.hour <= 23:
        parser.error("--hour must be 0..23")
    if not 0 <= args.minute <= 59:
        parser.error("--minute must be 0..59")

    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
