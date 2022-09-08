#!/bin/bash
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

echo "[*] Creating directories and installing tools..."

mkdir -p /var/log/autodeauth/loot/

output=`pip3 install wifi scapy rpi.gpio 2>&1` || echo $output
output=`apt install python3 python3-pip wireless-tools macchanger 2>&1` || echo $output

chmod +x autodeauth.py

cp autodeauth.py /usr/local/bin/autodeauth
echo "[*] Check the README for more infomation about configuring/starting the service"
read -p "[?] Enter your WiFi interface to use with the autodeauth service: " interface

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
echo -e "[*] Installed!, you can use sudo autodeauth -h to see available options."
