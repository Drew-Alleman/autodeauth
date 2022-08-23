#!/bin/bash
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

mkdir /var/log/autodeauth
mkdir /var/log/autodeauth/loot

apt install python3 python3-pip wireless-tools macchanger
sudo pip3 install wifi scapy rpi.gpio

chmod +x autodeauth.py
cp autodeauth.py /usr/local/bin/autodeauth

read -p "Please enter your WiFi interface name e.g: wlan0 ->  " interface

cat >/etc/systemd/system/autodeauth.service <<EOL
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
echo autodeauth installed
echo "type sudo autodeauth -h to see options or systemctl start autodeauth"
echo "to edit service setting please edit: service file: /etc/systemd/system/autodeauth.service"