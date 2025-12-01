# -*- coding: utf-8 -*-

from boofuzz import *
import can

class CANTarget:
    def __init__(self, channel='can0', arbitration_id=0x123):
        self.bus = can.interface.Bus(channel=channel, bustype='socketcan')
        self.arbitration_id = arbitration_id

    def send(self, data):
        try:
            msg = can.Message(
                arbitration_id=self.arbitration_id,
                data=data[:8]  # CAN 帧最大 8 字节
            )
            self.bus.send(msg)
            return True
        except Exception as e:
            print(f"发送失败: {e}")
            return False

def define_your_protocol():

    s_initialize("can_protocol")

    with s_block("frame"):
        s_byte(0x01, name="function_code")
        s_word(0x0000, name="address")
        s_word(0x0001, name="quantity")
        s_bytes(b'\x00\x00', name="data", max_len=4)

    return s_get("can_protocol")

def main():

    protocol = define_your_protocol()
    target = Target(connection=CANTarget('can0'))
    session = Session(target=target)

    session.connect(protocol)
    session.fuzz()

if __name__ == "__main__":
    main()
