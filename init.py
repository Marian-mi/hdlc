from scapy.all import *
import crcmod
import time

MAX_PAYLOAD_SIZE = 100
WINDOWS_SIZE = 3
IFACE = 'Ethernet 2'

class parse_result:
    def __init__(self, send_sequence, p_f, data, fcs):
        self.send_sequence = send_sequence
        self.p_f = p_f
        self.data = data
        self.fcs = fcs


eth_packet = Ether(src="fc:34:97:69:7f:d9", dst="2c:4d:54:38:33:dc")


class hdlc:
    def __init__(self):
        self.send_sequence = 10
        self.recv_sequence = 3
        self.in_buffer = []

    def send_iframe(self, data):
        frame = self.craft_iframe(data)

        packet = eth_packet / Raw(frame)

        sendp(packet, iface=IFACE)

    def send_sframe(data):
        return

    def craft_iframe(self, data):
        control = 8
        control |= ((self.send_sequence & 7) << 4)
        control |= (self.recv_sequence & 7)

        return self.finalize_frame(control, data)

    def craft_sframe(self):
        control = 128
        control |= (self.recv_sequence & 7)

        return self.finalize_frame(control, None)

    def finalize_frame(self, control, data):
        flag = b'\x7e'
        address = b'\xff'

        crc = crcmod.mkCrcFun(0x18005, rev=True, initCrc=0xFFFF, xorOut=0xFFFF)

        if (data is None):
            frame = address + \
                control.to_bytes(1, 'big') + crc(control.to_bytes(1, 'big') + b'\x00\x00').to_bytes(2, 'big')
        else:
            frame = address + \
                control.to_bytes(1, 'big') + data.encode() + crc(control.to_bytes(1, 'big') + data.encode() + b'\x00\x00').to_bytes(2, 'big')

        return flag + frame + flag

    def start_sniffing(self):
        sniff(iface=IFACE, prn=lambda pck: self.in_buffer.append(pck))
        return

    def packet_handler(self):
        while (True):
            if (self.in_buffer.count == 0):
                time.sleep(0.5)
                continue

            packet = self.in_buffer.pop(0)

            packet_parse_result: parse_result = self.parse_packet(
                bytes(packet[Raw]))

            if (packet_parse_result.send_sequence != self.recv_sequence):
                # handle error
                print("Error")
                return

            print(packet_parse_result.data.decode())

            self.recv_sequence += 1

            if (self.recv_sequence % WINDOWS_SIZE):
                self.send_sframe()

    def parse_packet(bytes):
        res = parse_result()

        bytes_count = len(bytes)

        control_int = int.from_bytes(bytes[1])
        res.send_sequence = ((control_int & 0b01110000) >> 4)
        res.p_f = ((control_int & 0b00001000) > 0)

        res.data = bytes[2:bytes_count - 3]

        res.fcs = bytes_count[bytes_count - 3: bytes_count - 1]

        return res


hh = hdlc()

hh.send_iframe("sex")


# eth_packet = Ether(src="fc:34:97:69:7f:d9",dst="2c:4d:54:38:33:dc")

# sendp(eth_packet / "sex",iface='Ethernet 2')

# Call the function to send a raw packet
