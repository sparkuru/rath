# -*- coding: utf-8 -*-

"""
pip install python-can boofuzz

# Linux
python peakcan.py -s 15        # 侦听 15 秒
python peakcan.py -c can1 -s 30   # 指定通道，侦听 30 秒

指定 channel 为 can1
python peakcan.py -c can1

指定 ARBITRATION_ID 为 0x123
python peakcan.py -b 250000 -i 0x123

指定 bitrate 为 250000
python peakcan.py -b 250000
"""

import subprocess
import time
import can
from boofuzz import *

# 定义 can 类型, `sudo ip link set can0 up type can bitrate 500000`
INTERFACE = "socketcan"
# peakcan 总线通道名, `ip -br a`
CHANNEL = "can0"
# peakcan 总线波特率
BITRATE = 500000
# can 总线订阅的信息号
ARBITRATION_ID = 0x123


class PeakCANConnection(ITargetConnection):
    """PEAK CAN connection for boofuzz fuzzing via SocketCAN interface."""

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
        self._setup_interface()
        self.bus = can.interface.Bus(channel=self.channel, interface=INTERFACE)

    def close(self):
        if self.bus:
            self.bus.shutdown()
            self.bus = None

    def send(self, data):
        if not self.bus:
            raise Exception("CAN bus not opened")

        payload = bytes(data)[:8]  # CAN frame max 8 bytes
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

    def _setup_interface(self):
        try:
            subprocess.run(
                ["ip", "link", "set", self.channel, "down"],
                capture_output=True,
                check=False,
            )
            subprocess.run(
                [
                    "ip",
                    "link",
                    "set",
                    self.channel,
                    "type",
                    "can",
                    "bitrate",
                    str(self.bitrate),
                ],
                capture_output=True,
                check=True,
            )
            subprocess.run(
                ["ip", "link", "set", self.channel, "up"],
                capture_output=True,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to setup CAN interface: {e}")

    def _check_interface(self):
        result = subprocess.run(
            ["ip", "link", "show", self.channel], capture_output=True, text=True
        )
        return "UP" in result.stdout


def define_can_protocol():
    """Define CAN protocol structure for fuzzing."""
    s_initialize("peakcan_protocol")

    with s_block("frame"):
        s_byte(0x01, name="function_code", fuzzable=True)
        s_word(0x0000, name="address", endian=BIG_ENDIAN, fuzzable=True)
        s_word(0x0001, name="quantity", endian=BIG_ENDIAN, fuzzable=True)
        s_bytes(b"\x00\x00", name="data", size=2, max_len=4, fuzzable=True)

    return s_get("peakcan_protocol")


def define_extended_protocol():
    """Extended CAN protocol with more fuzz targets."""
    s_initialize("peakcan_extended")

    with s_block("header"):
        s_byte(0x00, name="msg_type", fuzzable=True)
        s_byte(0x00, name="flags", fuzzable=True)

    with s_block("payload"):
        s_bytes(b"\x00" * 6, name="raw_data", size=6, max_len=6, fuzzable=True)

    return s_get("peakcan_extended")


def create_session(
    channel=CHANNEL, bitrate=BITRATE, arb_id=ARBITRATION_ID, web_port=26000, extended=False
):
    """Create boofuzz fuzzing session for PEAK CAN."""
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


def run_receiver(channel=CHANNEL, timeout=None):
    """Monitor CAN bus for incoming messages."""
    bus = can.interface.Bus(channel=channel, interface=INTERFACE)
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


def run_listener(channel=CHANNEL, duration=10):
    """Analyze CAN bus traffic and generate boofuzz protocol suggestions."""
    bus = can.interface.Bus(channel=channel, interface=INTERFACE)
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
    print("CAN Traffic Analysis Report")
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
    print("Suggested boofuzz Protocol Definition")
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

    parser = argparse.ArgumentParser(description="PEAK CAN Fuzzer via SocketCAN")
    parser.add_argument("-c", "--channel", default=CHANNEL, help="CAN interface")
    parser.add_argument("-b", "--bitrate", type=int, default=BITRATE, help="Bitrate")
    parser.add_argument(
        "-i",
        "--arb-id",
        type=lambda x: int(x, 0),
        default=ARBITRATION_ID,
        help="Arbitration ID (hex: 0x123)",
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
        run_listener(args.channel, args.listen)
    elif args.monitor:
        run_receiver(args.channel)
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
