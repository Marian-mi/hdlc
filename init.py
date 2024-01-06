from scapy.all import *
import crcmod

class hdlc:
    def __init__(self):
        self.send_sequence = 10
        self.recv_sequence = 3

    def send_iframe(data):
        return
    
    def craft_iframe(self, data):
        flag = b'\x7e'
        address = b'\xff'

        control = 8
        control |= ((self.send_sequence & 7) << 4)
        control |= (self.recv_sequence & 7)

        crc_place_holder = b'\x00\x00'

        frame = address + control.to_bytes(1, 'big') + data.encode() + crc_place_holder

        crc_ccitt = crcmod.mkCrcFun(0x11021, initCrc=0xFFFF, xorOut=0x0000)

        computed_fcs = crc_ccitt(frame)

        frame = address + control.to_bytes(1, 'big') + data.encode() + computed_fcs.to_bytes(2, 'big')

        frame = flag + frame + flag

        for bb in frame:
            print(format(bb, '08b'))

hh = hdlc()

hh.craft_iframe("sexy")


# eth_packet = Ether(src="fc:34:97:69:7f:d9",dst="2c:4d:54:38:33:dc") 

# sendp(eth_packet / "sex",iface='Ethernet 2')
    
# Call the function to send a raw packet