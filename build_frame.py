from scapy.all import *
import time

mac_chip_usb = '70:3a:d8:4e:9b:70'

mac_addresses = {'mac_xbox': "BC:83:85:71:90:23",
                 'mac_chip': "CC:79:CF:20:6D:D1",
                 'mac_sony': "40:B8:37:0D:63:5D",
                 'mac_router': '70:3a:d8:4e:9b:70'}
                 
DOT11_FC_SUBTYPE_RTS  = 0x0B 
class Dot11RTS(Dot11): 
    """IEEE 802.11 Request-To-Send message. 
    This class inherits from the `Dot11` class from Scapy. 
    ------------------------------ 
    | FC | Duration/ID | RA | TA | 
    ------------------------------ 
    """ 
    name = "802.11 RTS" 
    fields_desc = [] 
    def __init__(self, *args, **kwargs): 
        """Constructor; initialize header parameters for RTS.""" 
        Dot11.__init__(self, *args, **kwargs) 
        self.type = "Control" 
        self.subtype = DOT11_FC_SUBTYPE_RTS 
    @staticmethod 
    def _init_fields_desc(): 
        """Internal method to redefine `Dot11RTS.fields_desc`; this removes 
        unnecessary fields from `Dot11`.""" 
        Dot11RTS.fields_desc = Dot11.fields_desc[0:7] 

Dot11RTS._init_fields_desc() 
bind_layers( Dot11,         Dot11RTS,        subtype=11, type=1)

packet = Dot11(addr1=mac_addresses['mac_sony'], addr2=mac_chip_usb, addr3=mac_chip_usb, type=2, subtype=12) / Dot11QoS(TID=0, EOSP=0, Reserved=0, TXOP=0 )
packet = Dot11(addr1=mac_addresses['mac_sony'], addr2=mac_chip_usb, addr3=mac_chip_usb, type=2, subtype=12, FCfield=2) / Dot11QoS(TID=0, EOSP=0, Reserved=0, TXOP=0 )
packet = RadioTap() / Dot11(addr1=mac_addresses['mac_sony'], addr2=mac_chip_usb, addr3='aa:bb:cc:dd:ee:ff', type=1, subtype=11, FCfield=0)

raw_packet = '00001a002f4800002d25c19400000000100ca809c000c6000000b400fc005c51888cd379703ad84e9b703897f169'
import binascii
raw_pkt_str = binascii.unhexlify(raw_packet)

print raw_pkt_str
packet = Raw(load=raw_pkt_str)
# Dot11Addr2MACField
packet.show()



wireshark(packet)
