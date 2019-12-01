#!env/bin/python

from serial import Serial
from serial.threaded import Packetizer, ReaderThread
from struct import unpack
from time import sleep


devices = {
    'salon': b'\x24\xbe',
    'sam': b'\x4a\xfb',
    'cuisine': b'\x5e\x81',
    'bureau': b'\xb3\x84',
    'chambre': b'\xc5\xee',
}


def chunker(data, size):
    for i in range(0, len(data), size):
        yield data[i:i + size]


class Command:
    payload = b''

    def __bytes__(self):
        # Length
        length = len(self.payload).to_bytes(2, 'big')

        # Checksum
        checksum = self.code[0] ^ self.code[1]
        checksum ^= length[0] ^ length[1]
        for byte in self.payload:
            checksum ^= byte
        checksum = bytes([checksum])

        # Raw data
        data = self.code + length + checksum + self.payload

        # Encoded data
        encoded = bytearray([0x01])
        for byte in data:
            if byte < 0x10:
                encoded.extend([0x02, byte ^ 0x10])
            else:
                encoded.append(byte)
        encoded.append(0x03)
        return bytes(encoded)


class GetNetworkState(Command):
    code = b'\x00\x09'


class GetVersion(Command):
    code = b'\x00\x10'


class Reset(Command):
    code = b'\x00\x11'


class GetDevicesList(Command):
    code = b'\x00\x15'


class PermitJoining(Command):
    code = b'\x00\x49'
    target = b'\xff\xfc'  # broadcast
    interval = b'\x3c'  # 60 seconds
    significance = b'\x00'  # no change in authentication
    payload = target + interval + significance


class OnOff(Command):
    code = b'\x00\x92'
    DOWN = b'\00'
    UP = b'\01'
    TOGGLE = b'\02'

    def __init__(self, target, cmd):
        mode = b'\x02'
        src = b'\01'
        dst = b'\01'
        self.payload = mode + target + src + dst + cmd


class Response:
    def __new__(cls, packet):
        assert packet[0] == 0x01
        data = bytearray()
        alt = False
        for byte in packet[1:]:
            if byte == 0x02:
                alt = True
            elif alt:
                data.append(byte ^ 0x10)
                alt = False
            else:
                data.append(byte)
        actual_length = len(data) - 6
        code, length, checksum, payload, lqi = unpack(f'!HHB{actual_length}sB', data)
        assert length == actual_length + 1
        # TODO: assert checksum
        actual_class = {
            0x8015: GetDevicesListResponse,
        }.get(code, GenericResponse)
        return actual_class(code, payload)


class GenericResponse:
    def __init__(self, code, payload):
        self.code = code
        self.payload = payload

    def __str__(self):
        return f"GenericResponse: code=0x{self.code:x}, payload=0x{self.payload.hex()}"


class Device:
    def __init__(self, data):
        self.id, self.addr, self.mac, self.power, self.lqi = unpack('!BHQBB', data)

    def __str__(self):
        return f"id=0x{self.id:x}, addr=0x{self.addr:x}, mac=0x{self.mac:x}, power=0x{self.power:x}, lqi=0x{self.lqi:x}"


class GetDevicesListResponse:
    def __init__(self, code, payload):
        assert code == 0x8015
        self.devices = [Device(data) for data in chunker(payload, 13)]

    def __str__(self):
        return f"GetDevicesListResponse:\n" + "\n".join([str(device) for device in self.devices])


class Reader(Packetizer):
    TERMINATOR = b'\x03'

    def connection_made(self, transport):
        print('connected')
        self.transport = transport

    def send(self, command):
        print("send:", bytes(command).hex())
        self.transport.write(bytes(command))
        print("sent")

    def handle_packet(self, packet):
        print("received:", packet.hex())
        response = Response(packet)
        print("decoded:", response)


serial = Serial('/dev/ttyS0', 115200)
with ReaderThread(serial, Reader) as protocol:
    # protocol.send(PermitJoining())
    # sleep(1000)
    protocol.send(GetDevicesList())
    sleep(1)
    # protocol.send(OnOff(devices['salon'], OnOff.UP))
    # sleep(1)
    # protocol.send(OnOff(devices['sam'], OnOff.UP))
    # sleep(1)
    # protocol.send(OnOff(devices['cuisine'], OnOff.UP))
    # sleep(1)
    # protocol.send(OnOff(devices['bureau'], OnOff.UP))
    # sleep(1)
    # protocol.send(OnOff(devices['chambre'], OnOff.UP))
    # sleep(1)
