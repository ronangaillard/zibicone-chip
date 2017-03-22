#!/usr/bin/python

# wlan.sa == e8:4e:06:24:a6:e0 or wlan.ra == e8:4e:06:24:a6:e0

from scapy.all import *
import time

mac_addresses = {'mac_xbox': "BC:83:85:71:90:23",
                 'mac_chip': "CC:79:CF:20:6D:D1",
                 'mac_sony': "40:b8:37:0d:63:5d",
                 'mac_router': '70:3a:d8:4e:9b:70',
                 'mac_broadcast' : 'ff:ff:ff:ff:ff:ff',
                 'mac_3d_printer': '60:01:94:09:ED:44',
                 'mac_router_3d_printer_ap' : '72:3a:d8:5e:9b:70'}

mac_chip_usb= "e8:4e:06:24:a6:e0"
mac_chip_usb = mac_addresses['mac_router']
#mac_chip_usb = 'aa:bb:cc:dd:ee:ff'



#for _, mac_add in mac_addresses.items():
#    packet = Dot11(addr1=mac_add, addr2=mac_chip_usb, 
#                    addr3=mac_chip_usb, type=2, subtype=4)
#    sendp(packet, iface="wlan0")

raw_packet = '00001a002f4800002d25c19400000000100ca809c000c6000000b400fc0040b8370d635d703ad84e9b70f7a54cdf'
import binascii
raw_pkt_str = binascii.unhexlify(raw_packet)

for i in range(0,1):
    # Request to send
    packet = Dot11(addr1=mac_addresses['mac_sony'], addr2=mac_chip_usb, addr3=mac_chip_usb, type=1, subtype=11, FCfield=0) 
    sendp(packet, iface="wlan0")
    packet = Raw(load=raw_pkt_str)
    #sendp(packet, iface="wlan0")
    packet = Dot11(addr1='aa:bb:cc:dd:ee:ff', addr2='aa:bb:cc:dd:ee:ff', addr3='aa:bb:cc:dd:ee:ff', type=1, subtype=11, FCfield=0) 
    sendp(packet, iface="wlan0")
    #packet = RadioTap() / Dot11(addr1=mac_addresses['mac_sony'], addr2=mac_chip_usb,addr3=mac_chip_usb, type=2, subtype=4)  
    #packet = Dot11(addr1=mac_addresses['mac_3d_printer'], addr2=mac_chip_usb, addr3=mac_chip_usb, type=2, subtype=12, FCfield=2) / Dot11QoS(TID=0, EOSP=0, Reserved=0, TXOP=0 )
    
    #ans, unans = srp(packet, iface="wlan0")
    #print 'answer :', ans, 'unans :', unans
    
    time.sleep(1)

# packet.show()
