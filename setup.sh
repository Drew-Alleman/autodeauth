#!/bin/bash

echo "[*] Creating directories and installing tools..."

sudo mkdir -p /var/log/autodeauth/loot/

output=`sudo pip3 install wifi scapy 2>&1` || echo $output
output=`sudo pip3 install rpi.gpio 2>&1` || echo $output
output=`sudo apt install python3 python3-pip wireless-tools macchanger 2>&1` || echo $output

chmod +x autodeauth.py

sudo cp autodeauth.py /usr/local/bin/autodeauth
echo "[*] Check the README for more infomation about configuring/starting the service"
read -p "[?] Enter your WiFi interface to use with the autodeauth service: " interface

sudo cat >/etc/systemd/system/autodeauth.service <<EOL
[Unit]
Description=Auto Deauth Service
After=multi-user.target
Type=simple
[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/autodeauth -i $interface
[Install]
WantedBy=multi-user.target
... 
EOL
echo -e "[*] Installed!, you can use sudo autodeauth -h to see available options."
