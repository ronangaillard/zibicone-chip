#!/usr/bin/python
# 
from scapy.all import *


mac_addresses = {'mac_xbox': "BC:83:85:71:90:23",
                 'mac_chip': "CC:79:CF:20:6D:D1",
                 'mac_sony': "40:b8:37:0d:63:5d",
                 'mac_router': '70:3a:d8:4e:9b:70',
                 'mac_broadcast' : 'ff:ff:ff:ff:ff:ff',
                 'mac_3d_printer': '60:01:94:09:ED:44',
                 'mac_router_3d_printer_ap' : '72:3a:d8:5e:9b:70'}

mac_chip_usb= "e8:4e:06:24:a6:e0"
mac_chip_usb = mac_addresses['mac_router_3d_printer_ap']


def PacketHandler(pkt) :

        #if (pkt.addr2 == '70:3a:d8:4e:9b:70' or pkt.addr3 == '70:3a:d8:4e:9b:70') and pkt.addr1 == '40:b8:37:0d:63:5d':
        #if (pkt.addr2 == '70:3a:d8:4e:9b:70' or pkt.addr3 == '70:3a:d8:4e:9b:70'):
        #    print pkt.addr1, 'LENGTH', len(pkt)

        
    pkt.summary()


sniff(offline="capture.log", prn = PacketHandler, store=0, filter="subtype cts or subtype rts")