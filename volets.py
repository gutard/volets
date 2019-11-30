#!env/bin/python

from serial import Serial
from serial.threaded import Packetizer, ReaderThread
from time import sleep


def encode(command, data):
    checksum = command ^ len(data)
    for b in data:
        checksum ^= b

    data = bytearray(command.to_bytes(2, 'big') + len(data).to_bytes(2, 'big') + bytes((checksum, )) + data)

    encoded = bytearray([0x01])
    for b in data:
        if b < 0x10:
            encoded.extend([0x02, 0x10 ^ b])
        else:
            encoded.append(b)
    encoded.append(0x03)
    return encoded


class Reader(Packetizer):
    TERMINATOR = b'\x03'

    def connecton_made(self, transport):
        self.transport = transport

    def send(self, command, data):
        packet = encode(command, data)
        print("send:", packet.hex())
        self.transport.write(packet)
        print("sent")

    def handle_packet(self, packet):
        print("received:", packet.hex())


serial = Serial('/dev/ttyS0', 115200)
with ReaderThread(serial, Reader) as protocol:
    protocol.send(0x0015, b'')
    sleep(2)
