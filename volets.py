#!env/bin/python

from serial import Serial
from struct import pack, unpack


devices = {
    'salon': 0x24be,
    'sam': 0x4afb,
    'cuisine': 0x5e81,
    'bureau': 0xb384,
    'chambre': 0xc5ee,
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
        code = self.code.to_bytes(2, 'big')
        checksum = code[0] ^ code[1]
        checksum ^= length[0] ^ length[1]
        for byte in self.payload:
            checksum ^= byte
        checksum = bytes([checksum])

        # Raw data
        data = code + length + checksum + self.payload

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
    code = 0x0009

    def __str__(self):
        return "GetNetworkState"


class GetVersion(Command):
    code = 0x0010

    def __str__(self):
        return "GetVersion"


class Reset(Command):
    code = 0x0011

    def __str__(self):
        return "Reset"


class GetDevicesList(Command):
    code = 0x0015

    def __str__(self):
        return "GetDevicesList"


class SimpleDescriptorRequest(Command):
    code = 0x0043

    def __init__(self, target, endpoint):
        self.target = target
        self.endpoint = endpoint
        self.payload = pack('!HB', target, endpoint)

    def __str__(self):
        return f"SimpleDescriptorRequest(target=0x{self.target:x}, endpoint=0x{self.endpoint:x})"


class ActiveEndpointsRequest(Command):
    code = 0x0045

    def __init__(self, target):
        self.target = target
        self.payload = pack('!H', target)

    def __str__(self):
        return f"ActiveEndpointsRequest(target=0x{self.target:x})"


class PermitJoining(Command):
    code = 0x0049
    target = 0xfffc  # broadcast
    interval = 60  # 60 seconds
    significance = 0x00  # no change in authentication
    payload = pack('!HBB', target, interval, significance)

    def __str__(self):
        return "PermitJoining"


class AddGroup(Command):
    code = 0x0060

    def __init__(self, target, group):
        self.target = target
        self.group = group
        mode = 0x02
        src = 0x01
        dst = 0x01
        self.payload = pack('!BHBBH', mode, target, src, dst, group)

    def __str__(self):
        return f"AddGroup(target=0x{self.target:x}, group=0x{self.group:x})"


class OnOff(Command):
    code = 0x0092
    DOWN = 0x00
    UP = 0x01
    TOGGLE = 0x02

    def __init__(self, target, cmd, group=False):
        self.target = target
        self.cmd = cmd
        self.mode = 0x01 if group else 0x02  # 0=bound 1=group 2=short 3=ieee
        src = 0x01
        dst = 0x01
        self.payload = pack('!BHBBB', self.mode, target, src, dst, cmd)

    def __str__(self):
        cmd = {self.DOWN: "Down", self.UP: "Up", self.TOGGLE: "Toggle"}[self.cmd]
        mode = {0x01: "Group", 0x02: "Addr"}[self.mode]
        return f"OnOff(target=0x{self.target:x}, mode={mode}, cmd={cmd})"


class Response:
    def __new__(cls, packet):
        assert packet[0] == 0x01
        assert packet[-1] == 0x03
        data = bytearray()
        alt = False
        for byte in packet[1:-1]:
            if byte == 0x02:
                alt = True
            elif alt:
                data.append(byte ^ 0x10)
                alt = False
            else:
                data.append(byte)
        payload_length = len(data) - 6
        code, length, checksum, payload, lqi = unpack(f'!HHB{payload_length}sB', data)
        assert length == payload_length + 1  # payload + LQI
        # TODO: assert checksum
        actual_class = {
            0x004d: DeviceAnnounceResponse,
            0x8000: StatusResponse,
            0x8015: GetDevicesListResponse,
            0x8043: SimpleDescriptorResponse,
            0x8045: ActiveEndpointsResponse,
            0x8060: AddGroupResponse,
            0x8102: AttributeReportResponse,
            0x8701: RouteDiscoveryConfirmReponse,
        }.get(code, GenericResponse)
        return actual_class(code, payload)


class GenericResponse:
    def __init__(self, code, payload):
        self.code = code
        self.payload = payload

    def __str__(self):
        return f"GenericResponse: code=0x{self.code:x}, payload=0x{self.payload.hex()}"


class DeviceAnnounceResponse:
    def __init__(self, code, payload):
        assert code == 0x004d
        self.addr, self.mac, self.capability = unpack('!HQB', payload)

    def __str__(self):
        return f"DeviceAnnounceResponse: addr=0x{self.addr:x}, mac=0x{self.mac:x}, capability=0x{self.capability:x}"


class Device:
    def __init__(self, data):
        self.id, self.addr, self.mac, self.power, self.lqi = unpack('!BHQBB', data)

    def __str__(self):
        return f"id=0x{self.id:x}, addr=0x{self.addr:x}, mac=0x{self.mac:x}, power=0x{self.power:x}, lqi=0x{self.lqi:x}"


class StatusResponse:
    def __init__(self, code, payload):
        assert code == 0x8000
        self.status, self.sqn, self.code = unpack('!BBH', payload)

    def __str__(self):
        return f"StatusResponse: status=0x{self.status:x}, sqn=0x{self.sqn:x}, code=0x{self.code:x}"


class GetDevicesListResponse:
    def __init__(self, code, payload):
        assert code == 0x8015
        self.devices = [Device(data) for data in chunker(payload, 13)]

    def __str__(self):
        return f"GetDevicesListResponse:\n" + "\n".join([str(device) for device in self.devices])


class Endpoint:
    def __init__(self, data):
        self.id, = unpack('!B', data)

    def __str__(self):
        return f"Endpoint: id=0x{self.id:x}"


class Cluster:
    def __init__(self, data):
        self.id, = unpack('!H', data)

    def __str__(self):
        return f"Cluster: id=0x{self.id:x}"


class SimpleDescriptorResponse:
    def __init__(self, code, payload):
        assert code == 0x8043
        (
            self.sqn,
            self.status,
            self.address,
            self.length,
            self.endpoint,
            self.profile,
            self.id,
            self.bitfields,
            self.in_count,
        ) = unpack('!BBHBBHHBB', payload[:12])
        out_count_offset = 12 + 2 * self.in_count
        self.in_clusters = [Cluster(data) for data in chunker(payload[12:out_count_offset], 2)]
        self.out_count = payload[out_count_offset]
        self.out_clusters = [Cluster(data) for data in chunker(payload[out_count_offset + 1:], 2)]
        assert len(self.in_clusters) == self.in_count
        assert len(self.out_clusters) == self.out_count

    def __str__(self):
        return f"SimpleDescriptorResponse: sqn=0x{self.sqn:x}, status=0x{self.status:x}, address=0x{self.address:x}, endpoint=0x{self.endpoint:x}, profile=0x{self.profile:x}, id=0x{self.id:x}, in_count=0x{self.in_count:x}, out_count=0x{self.out_count:x}, in_clusters=\n" + "\n".join([str(cluster) for cluster in self.in_clusters]) + "\nout_clusters=\n" + "\n".join([str(cluster) for cluster in self.out_clusters])


class ActiveEndpointsResponse:
    def __init__(self, code, payload):
        assert code == 0x8045
        self.sqn, self.status, self.address, self.count = unpack('!BBHB', payload[:5])
        self.endpoints = [Endpoint(data) for data in chunker(payload[5:], 1)]
        assert len(self.endpoints) == self.count

    def __str__(self):
        return f"ActiveEndpointsResponse: sqn=0x{self.sqn:x}, status=0x{self.status:x}, address=0x{self.address:x}, count=0x{self.count:x}\n" + "\n".join([str(endpoint) for endpoint in self.endpoints])


class AddGroupResponse:
    def __init__(self, code, payload):
        assert code == 0x8060
        self.sqn, self.endpoint, self.cluster, self.status, self.group, self.address = unpack('!BBHBHH', payload)

    def __str__(self):
        return f"AddGroupResponse: sqn=0x{self.sqn:x}, endpoint=0x{self.endpoint:x}, cluster=0x{self.cluster:x}, status=0x{self.status:x}, group=0x{self.group:x}, address=0x{self.address:x}"


class AttributeReportResponse:
    def __init__(self, code, payload):
        assert code == 0x8102
        self.sqn, self.address, self.ep, self.cluster, self.id, self.type, self.size = unpack('!BHBHHHH', payload[:12])
        self.data = payload[12:]
        if self.cluster == 0x0000 and self.id == 0x0005:
            self.decoded = f", identification={self.data.decode()}"
        elif self.cluster == 0x0402 and self.id==0x0000:
            self.decoded = f", temperature={unpack('!h', self.data)[0] / 100}°C"
        elif self.cluster == 0x0405 and self.id==0x0000:
            self.decoded = f", humidité={unpack('!H', self.data)[0] / 100}%"
        elif self.cluster == 0x0403 and self.id==0x0000:
            self.decoded = f", pression={unpack('!h', self.data)[0]}mbar"
        elif self.cluster == 0x0403 and self.id==0x0010:
            self.decoded = f", pression={unpack('!h', self.data)[0] / 10}mbar"
        else:
            self.decoded = ""

    def __str__(self):
        return f"AttributeReportResponse: sqn=0x{self.sqn:x}, address=0x{self.address:x}, ep=0x{self.ep:x}, cluster=0x{self.cluster:x}, id=0x{self.id:x}, size=0x{self.size:x}, type=0x{self.type:x}, data=0x{self.data.hex()}{self.decoded}"


class RouteDiscoveryConfirmReponse:
    def __init__(self, code, payload):
        assert code == 0x8701
        self.sqn, self.status = unpack('!BB', payload)

    def __str__(self):
        return f"RouteDiscoveryConfirmReponse: sqn=0x{self.sqn:x}, status=0x{self.status:x}"


class ZigbeeTimeout(Exception):
    pass


class Zigbee(Serial):
    devices = []

    def __init__(self, port='/dev/ttyS0', baudrate=115200, timeout=5, **kwargs):
        super().__init__(port, baudrate, timeout=timeout, **kwargs)

    def receive(self):
        packet = bytearray()
        while not packet or packet[-1] != 0x03:
            byte = self.read()
            if not byte:
                raise ZigbeeTimeout("Read timeout")
            packet.extend(byte)
        print(f"Received packet 0x{packet.hex()}")
        response = Response(packet)
        print(f"Received response {response}")
        return response

    def send(self, command):
        print(f"Send command {command}")
        packet = bytes(command)
        print(f"Send packet 0x{packet.hex()}")
        self.write(packet)

    def get_devices_list(self):
        self.send(GetDevicesList())
        response = zigbee.receive()
        assert isinstance(response, StatusResponse)
        assert response.status == 0x00
        response = zigbee.receive()
        assert isinstance(response, GetDevicesListResponse)
        self.devices = response.devices

    def get_active_endpoints(self, device):
        self.send(ActiveEndpointsRequest(device.addr))
        response = zigbee.receive()
        assert isinstance(response, StatusResponse)
        if response.status != 0x00:
            print(f"Error status 0x{response.status:x} when getting endpoint for device 0x{device.addr:x}")
            device.endpoints = []
            return
        try:
            response = zigbee.receive()
        except ZigbeeTimeout:
            print(f"Timeout when getting endpoints for device 0x{device.addr:x}")
            device.endpoints = []
            return
        assert isinstance(response, ActiveEndpointsResponse)
        device.endpoints = response.endpoints

    def get_simple_descriptor(self, device, endpoint):
        self.send(SimpleDescriptorRequest(device.addr, endpoint.id))
        response = zigbee.receive()
        assert isinstance(response, StatusResponse)
        assert response.status == 0x00
        try:
            response = zigbee.receive()
            assert isinstance(response, SimpleDescriptorResponse)
            endpoint.in_clusters = response.in_clusters
            endpoint.out_clusters = response.out_clusters
        except ZigbeeTimeout:
            print(f"Failed to get descriptor for device 0x{device.addr:x}, endpoint 0x{endpoint.id:x}")

    def discover(self):
        zigbee.get_devices_list()
        for device in self.devices:
            print("=> DEVICE", device)
            zigbee.get_active_endpoints(device)
            for endpoint in device.endpoints:
                print("  => ENDPOINT", endpoint)
                self.get_simple_descriptor(device, endpoint)

    def add_group(self, device, group):
        self.send(AddGroup(device.addr, group))
        response = zigbee.receive()
        assert isinstance(response, StatusResponse)
        assert response.status == 0x00
        response = zigbee.receive()
        assert isinstance(response, AddGroupResponse)

    def up(self, device):
        self.send(OnOff(device.addr, OnOff.UP))
        response = zigbee.receive()
        assert isinstance(response, StatusResponse)
        assert response.status == 0x00

    def down(self, device):
        self.send(OnOff(device.addr, OnOff.DOWN))
        response = zigbee.receive()
        assert isinstance(response, StatusResponse)
        assert response.status == 0x00

    def all_up(self):
        self.send(OnOff(0x01, OnOff.UP, group=True))
        response = zigbee.receive()
        assert isinstance(response, StatusResponse)
        assert response.status == 0x00

    def all_down(self):
        self.send(OnOff(0x01, OnOff.DOWN, group=True))
        response = zigbee.receive()
        assert isinstance(response, StatusResponse)
        assert response.status == 0x00

    def all_toggle(self):
        self.send(OnOff(0x01, OnOff.TOGGLE, group=True))
#        response = zigbee.receive()
#        assert isinstance(response, StatusResponse)
#        assert response.status == 0x00


zigbee = Zigbee()
# zigbee.discover()
# for device in zigbee.devices:
#     if device.power == 1:
#         zigbee.add_group(device, 1)
# zigbee.down(zigbee.devices[0])
# zigbee.all_down()
# zigbee.all_up()
zigbee.all_toggle()
# zigbee.send(PermitJoining())

while False:
# while True:
    try:
        zigbee.receive()
    except ZigbeeTimeout:
        print(".", end="", flush=True)
        pass
