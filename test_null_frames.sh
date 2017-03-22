#!/bin/sh
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode managed
sudo ifconfig wlan0 up
sudo iwconfig wlan0 channel 13
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up
sudo iwconfig wlan0 channel 13


#sudo ./scanner.py &
#sudo tcpdump -i wlan0 -n --time-stamp-precision=nano  -vvv -w capture.log "subtype cts or subtype rts" &
sudo tcpdump -i wlan0 -n --time-stamp-precision=nano  -vvv -w capture.log &

sleep 5
sudo ./send_null.py
sleep  5
killall tcpdump
killall scanner.py
#(\d{2}):(\d{2}):(\d{2}\.\d*).*RA:((Clear-To-Send)|(Request-To-Send))