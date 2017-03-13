#!/bin/sh
rm log.txt
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up
sudo tcpdump -i wlan0 -n --time-stamp-precision=nano  -vvv> log.txt &
sleep 1
./main
sleep 2
killall tcpdump
cat log.txt 