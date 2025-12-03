# -*- coding: utf-8 -*-

"""
# windows 安装 PCAN 驱动：https://www.peak-system.com/Drivers.523.0.html

pip install python-can boofuzz psutil

# Windows
python peakcan-windows.py -s 15 # 侦听 15 秒
python peakcan-windows.py -c PCAN_USBBUS1 -b 500000 -i 0x10 -s 30 # 指定通道，波特率，信息号，侦听 30 秒

# 指定 channel 为 PCAN_USBBUS2
python peakcan-windows.py -c PCAN_USBBUS2

# 指定 ARBITRATION_ID 为 0x123
python peakcan-windows.py -i 0x123

# 指定 bitrate 为 250000
python peakcan-windows.py -b 250000
"""

import time
import can
from boofuzz import *

INTERFACE = "pcan"
# 在设备管理器找对应 peakcan 设备，查看详情里有 CHANNEL 名称
CHANNEL = "PCAN_USBBUS1"
BITRATE = 500000
ARBITRATION_ID = 0x123


class PeakCANConnection(ITargetConnection):
    def __init__(
        self,
        channel=CHANNEL,
        bitrate=BITRATE,
        arbitration_id=ARBITRATION_ID,
        is_extended_id=False,
    ):
        self.channel = channel
        self.bitrate = bitrate
        self.arbitration_id = arbitration_id
        self.is_extended_id = is_extended_id
        self.bus = None

    def open(self):
        self.bus = can.interface.Bus(
            channel=self.channel,
            interface=INTERFACE,
            bitrate=self.bitrate,
        )

    def close(self):
        if self.bus:
            self.bus.shutdown()
            self.bus = None

    def send(self, data):
        if not self.bus:
            raise Exception("CAN bus not opened")

        payload = bytes(data)[:8]
        msg = can.Message(
            arbitration_id=self.arbitration_id,
            data=payload,
            is_extended_id=self.is_extended_id,
        )
        try:
            self.bus.send(msg)
        except can.CanError as e:
            raise Exception(f"CAN send failed: {e}")

    def recv(self, max_bytes=8):
        if not self.bus:
            return b""
        msg = self.bus.recv(timeout=1.0)
        if msg:
            return bytes(msg.data)
        return b""

    @property
    def info(self):
        return f"PEAK CAN ({self.channel}, {self.bitrate}bps, ID=0x{self.arbitration_id:X})"


def define_can_protocol():
    s_initialize("peakcan_protocol")

    with s_block("frame"):
        s_byte(0x01, name="function_code", fuzzable=True)
        s_word(0x0000, name="address", endian=BIG_ENDIAN, fuzzable=True)
        s_word(0x0001, name="quantity", endian=BIG_ENDIAN, fuzzable=True)
        s_bytes(b"\x00\x00", name="data", size=2, max_len=4, fuzzable=True)

    return s_get("peakcan_protocol")


def define_extended_protocol():
    s_initialize("peakcan_extended")

    with s_block("header"):
        s_byte(0x00, name="msg_type", fuzzable=True)
        s_byte(0x00, name="flags", fuzzable=True)

    with s_block("payload"):
        s_bytes(b"\x00" * 6, name="raw_data", size=6, max_len=6, fuzzable=True)

    return s_get("peakcan_extended")


def create_session(
    channel=CHANNEL,
    bitrate=500000,
    arb_id=ARBITRATION_ID,
    web_port=26000,
    extended=False,
):
    connection = PeakCANConnection(
        channel=channel, bitrate=bitrate, arbitration_id=arb_id
    )

    target = Target(connection=connection)

    session = Session(
        target=target,
        web_port=web_port,
        crash_threshold_request=10,
        crash_threshold_element=5,
    )

    if extended:
        protocol = define_extended_protocol()
    else:
        protocol = define_can_protocol()

    session.connect(protocol)

    return session


def run_receiver(channel=CHANNEL, bitrate=500000, timeout=None):
    bus = can.interface.Bus(channel=channel, interface=INTERFACE, bitrate=bitrate)
    print(f"Listening on {channel}...")

    start_time = time.time()
    try:
        for msg in bus:
            print(
                f"ID=0x{msg.arbitration_id:03X} Data={msg.data.hex().upper()} "
                f"Ext={msg.is_extended_id} TS={msg.timestamp:.3f}"
            )
            if timeout and (time.time() - start_time) > timeout:
                break
    except KeyboardInterrupt:
        pass
    finally:
        bus.shutdown()


def run_listener(channel=CHANNEL, bitrate=500000, duration=10):
    bus = can.interface.Bus(channel=channel, interface=INTERFACE, bitrate=bitrate)
    print(f"Analyzing CAN traffic on {channel} for {duration}s...")
    print("-" * 70)

    messages = {}
    start_time = time.time()

    try:
        while (time.time() - start_time) < duration:
            msg = bus.recv(timeout=0.5)
            if msg is None:
                continue

            arb_id = msg.arbitration_id
            if arb_id not in messages:
                messages[arb_id] = {
                    "count": 0,
                    "extended": msg.is_extended_id,
                    "dlc_set": set(),
                    "samples": [],
                }
            messages[arb_id]["count"] += 1
            messages[arb_id]["dlc_set"].add(len(msg.data))
            if len(messages[arb_id]["samples"]) < 5:
                messages[arb_id]["samples"].append(bytes(msg.data))
    except KeyboardInterrupt:
        pass
    finally:
        bus.shutdown()

    if not messages:
        print("No CAN messages captured.")
        return

    print("\n" + "=" * 70)
    print("CAN 链路信息搜集")
    print("=" * 70 + "\n")

    for arb_id in sorted(messages.keys()):
        info = messages[arb_id]
        print(
            f"Arbitration ID: 0x{arb_id:03X} {'(Extended)' if info['extended'] else ''}"
        )
        print(f"  Message Count: {info['count']}")
        print(f"  DLC Values: {sorted(info['dlc_set'])}")
        print("  Sample Data:")
        for i, sample in enumerate(info["samples"]):
            byte_str = " ".join(f"{b:02X}" for b in sample)
            print(f"    [{i + 1}] {byte_str} (len={len(sample)})")
        print()

    print("=" * 70)
    print("boofuzz 协议定义建议参考")
    print("=" * 70 + "\n")

    for arb_id in sorted(messages.keys()):
        info = messages[arb_id]
        max_dlc = max(info["dlc_set"])
        sample = info["samples"][0] if info["samples"] else b"\x00" * max_dlc

        print(f"# Protocol for ID 0x{arb_id:03X}")
        print(f's_initialize("can_0x{arb_id:03X}")')
        print('with s_block("frame"):')

        if max_dlc >= 1:
            print(f'    s_byte(0x{sample[0]:02X}, name="byte_0", fuzzable=True)')
        if max_dlc >= 2:
            print(f'    s_byte(0x{sample[1]:02X}, name="byte_1", fuzzable=True)')
        if max_dlc > 2:
            remaining = sample[2:max_dlc]
            hex_init = 'b"' + "".join(f"\\x{b:02x}" for b in remaining) + '"'
            print(
                f'    s_bytes({hex_init}, name="payload", size={len(remaining)}, fuzzable=True)'
            )

        print(
            f"\n# Usage: arbitration_id=0x{arb_id:03X}, is_extended_id={info['extended']}"
        )
        print()


def main():
    import argparse

    parser = argparse.ArgumentParser(description="PEAK CAN Fuzzer via PCAN (Windows)")
    parser.add_argument(
        "-c",
        "--channel",
        default=CHANNEL,
        help="CAN interface (PCAN_USBBUS1, PCAN_USBBUS2, etc.)",
    )
    parser.add_argument("-b", "--bitrate", type=int, default=500000, help="Bitrate")
    parser.add_argument(
        "-i",
        "--arb-id",
        type=lambda x: int(x, 0),
        default=ARBITRATION_ID,
        help="Arbitration ID (like hex: 0x123)",
    )
    parser.add_argument("-p", "--port", type=int, default=26000, help="Web UI port")
    parser.add_argument(
        "-e", "--extended", action="store_true", help="Use extended protocol"
    )
    parser.add_argument(
        "-m", "--monitor", action="store_true", help="Monitor mode (receive only)"
    )
    parser.add_argument(
        "-s",
        "--listen",
        type=int,
        metavar="SEC",
        help="Analyze CAN traffic for SEC seconds and suggest boofuzz protocol",
    )

    args = parser.parse_args()

    if args.listen:
        run_listener(args.channel, args.bitrate, args.listen)
    elif args.monitor:
        run_receiver(args.channel, args.bitrate)
    else:
        session = create_session(
            channel=args.channel,
            bitrate=args.bitrate,
            arb_id=args.arb_id,
            web_port=args.port,
            extended=args.extended,
        )
        print(
            f"Starting fuzzing on {args.channel} @ {args.bitrate}bps, ID=0x{args.arb_id:X}"
        )
        print(f"Web UI: http://localhost:{args.port}")
        session.fuzz()


if __name__ == "__main__":
    main()
