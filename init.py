from scapy.all import *
import crcmod
import time
import threading

MAX_PAYLOAD_SIZE = 3
WINDOWS_SIZE = 3
IFACE = "Ethernet"


class parse_result:
    def __init__(self, send_sequence, recv_sequence, p_f, data, fcs):
        self.send_sequence = send_sequence
        self.recv_sequence = recv_sequence
        self.p_f = p_f
        self.data = data
        self.fcs = fcs


eth_packet = Ether(src="2c:4d:54:38:33:dc", dst="fc:34:97:69:7f:d9", type=0x88B6)

# the hdlc class is used by both the send and the receiver
# senders use the `send_stream` method which crafts I-frames and send them over the wire
# senders may also invoke the `start_sniffing_async` method to receive the acknowledgements
#
# receievers invoke the `start_sniffing` method method, which synchronously listens for incoming packets
# the packets are then processed by the `receiver` method

class hdlc:
    def __init__(self):
        self.send_sequence = 0
        self.recv_sequence = 0
        self.in_buffer = []

    def send_stream(self, stream: io.TextIOWrapper):
        while True:
            data = stream.read(MAX_PAYLOAD_SIZE)

            if self.send_sequence > 0 and self.send_sequence % WINDOWS_SIZE == 0:
                while True:
                    if len(self.in_buffer) == 0:
                        continue

                    packet = self.in_buffer.pop(0)
                    packet_parse_result = self.parse_packet(packet)

                    if (self.send_sequence & 0b00000111) == packet_parse_result.recv_sequence:
                        break

            if not data:
                break

            self.send_iframe(data)
            self.send_sequence += 1

    def send_iframe(self, data):
        frame = self.craft_iframe(data)
        packet = eth_packet / Raw(frame)

        sendp(packet, iface=IFACE)

    def send_sframe(self):
        frame = self.craft_sframe()

        sendp(eth_packet / Raw(frame), iface=IFACE)

    def craft_iframe(self, data):
        control = 8
        control |= (self.send_sequence & 7) << 4
        control |= self.recv_sequence & 7

        return self.finalize_frame(control, data)

    def craft_sframe(self):
        control = 128
        control |= self.recv_sequence & 7

        return self.finalize_frame(control, None)

    def finalize_frame(self, control, data):
        flag = b"\x7e"
        address = b"\xff"

        crc = crcmod.mkCrcFun(0x18005, rev=True, initCrc=0xFFFF, xorOut=0xFFFF)

        if data is None:
            frame = address + control.to_bytes(1, "big") + crc(control.to_bytes(1, "big") + b"\x00\x00").to_bytes(2, "big")
        else:
            frame = address + control.to_bytes(1, "big") + data.encode() + crc(control.to_bytes(1, "big") + data.encode() + b"\x00\x00").to_bytes(2, "big")

        return flag + frame + flag

    def start_sniffing_async(self):
        ass = AsyncSniffer(iface=IFACE, prn=self.enqeue_packet, filter="ether proto 0x88B6")
        ass.start()

    def enqeue_packet(self, packet):
        if (packet[Ether].src == "fc:34:97:69:7f:d9"):
            return
        
        self.in_buffer.append(packet)

    def start_sniffing(self):
        sniff(iface=IFACE, prn=self.receiver, filter="ether proto 0x88B6")
        # threading.Thread(target=lambda: sniff(iface=IFACE, prn=lambda pck:self.in_buffer.append(pck), filter="ether proto 0x88B6")1).start()

    def enqueue_packet(self, packet):
        self.in_buffer.append(packet)

    def receiver(self,packet):
        if packet[Ether].src != "fc:34:97:69:7f:d9":
            return

        packet_parse_result: parse_result = self.parse_packet(packet, "I")

        if packet_parse_result.send_sequence != (self.recv_sequence & 0b00000111):
            # handle error
            print("Error")
            return
        
        print(packet_parse_result.data.decode())

        self.recv_sequence += 1

        if self.recv_sequence > 0 and self.recv_sequence % WINDOWS_SIZE == 0:
            self.send_sframe()    

    def parse_packet(self, packet):
        res = parse_result(0, 0, False, None, None)

        raw_data = bytes(packet[Raw]).rstrip(b"\x00")

        bytes_count = len(raw_data)

        control_int = raw_data[2]

        type = (control_int & 0b10000000) > 0 

        res.p_f = (control_int & 0b00001000) > 0

        if type:
            res.recv_sequence = control_int & 0b00000111
            res.fcs = raw_data[3 : bytes_count - 1]
        else:
            res.send_sequence = (control_int & 0b01110000) >> 4
            res.data = raw_data[3 : bytes_count - 3]
            res.fcs = raw_data[bytes_count - 3 : bytes_count - 1]

        return res


hh = hdlc()

hh.start_sniffing()
hh.receiver()