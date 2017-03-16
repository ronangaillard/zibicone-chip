from scapy.all import *
import time

mac_chip_usb = '70:3a:d8:4e:9b:70'

mac_addresses = {'mac_xbox': "BC:83:85:71:90:23",
                 'mac_chip': "CC:79:CF:20:6D:D1",
                 'mac_sony': "40:B8:37:0D:63:5D",
                 'mac_router': '70:3a:d8:4e:9b:70'}

packet = Dot11(addr1=mac_addresses['mac_sony'], addr2=mac_chip_usb, addr3=mac_chip_usb, type=2, subtype=12) / Dot11QoS(TID=0, EOSP=0, Reserved=0, TXOP=0 )

packet.show()
    
wireshark(packet)
