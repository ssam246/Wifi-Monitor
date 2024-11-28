import argparse
import os
import socket
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11, RadioTap
from tabulate import tabulate


def list_interfaces():
    """List all available network interfaces."""
    try:
        interfaces = [i[1] for i in socket.if_nameindex()]
        if not interfaces:
            raise ValueError("No network interfaces found.")
        return interfaces
    except Exception as e:
        print(f"Error listing interfaces: {e}")
        exit(1)


def select_interface(interfaces):
    """Prompt user to select an interface from available ones."""
    print("\nAvailable Interfaces:")
    for idx, iface in enumerate(interfaces, 1):
        print(f"{idx}. {iface}")
    try:
        selection = int(input("Select an interface by number: "))
        if 1 <= selection <= len(interfaces):
            return interfaces[selection - 1]
        else:
            raise ValueError("Invalid selection. Please select a valid number.")
    except (ValueError, IndexError):
        print("Invalid input. Exiting.")
        exit(1)


def is_in_monitor_mode(interface):
    """Check if the selected interface is in monitor mode."""
    result = os.popen(f"iwconfig {interface}").read()
    return "Mode:Monitor" in result


def put_in_monitor_mode(interface):
    """Enable monitor mode on the selected interface."""
    if not is_in_monitor_mode(interface):
        print(f"Switching {interface} to monitor mode...")
        os.system(f"sudo ifconfig {interface} down")
        os.system(f"sudo iwconfig {interface} mode monitor")
        os.system(f"sudo ifconfig {interface} up")
        print(f"{interface} is now in monitor mode.")
    else:
        print(f"{interface} is already in monitor mode.")


def parse_arguments():
    """Parse command-line arguments."""
    interfaces = list_interfaces()
    parser = argparse.ArgumentParser(description="WiFi Monitor Tool")
    parser.add_argument(
        "-i", "--interface", 
        default=select_interface(interfaces), 
        help="Network interface to use for monitoring."
    )
    parser.add_argument(
        "-t", "--timeout", 
        type=int, 
        default=30, 
        help="Duration (in seconds) to monitor WiFi networks (default: 30 seconds)."
    )
    return parser.parse_args()


def format_packet_info(packet):
    """Extract relevant information from a WiFi packet."""
    try:
        if Dot11Beacon in packet:
            ssid = packet[Dot11Elt].info.decode(errors="ignore")
            bssid = packet[Dot11].addr3
            signal_strength = getattr(packet, "dBm_AntSignal", "N/A")
            channel = packet[RadioTap].ChannelFrequency if hasattr(packet[RadioTap], "ChannelFrequency") else "N/A"
            data_rate = packet[RadioTap].Rate if hasattr(packet[RadioTap], "Rate") else "N/A"
            return [ssid, bssid, signal_strength, channel, data_rate]
    except Exception:
        pass  # Ignore malformed packets
    return None


def monitor_wifi(interface, timeout):
    """Monitor nearby WiFi networks and display results."""
    wifi_data = []
    unique_ssids = set()

    def packet_handler(packet):
        packet_info = format_packet_info(packet)
        if packet_info and packet_info[1] not in unique_ssids:  # Avoid duplicate BSSIDs
            wifi_data.append(packet_info)
            unique_ssids.add(packet_info[1])

    try:
        put_in_monitor_mode(interface)
        print(f"\nMonitoring WiFi on interface {interface}... (Timeout: {timeout}s)")
        print("Press Ctrl+C to stop early.")
        sniff(iface=interface, prn=packet_handler, timeout=timeout)
        if wifi_data:
            headers = ["SSID", "BSSID", "Signal Strength (dBm)", "Frequency (MHz)", "Data Rate (Mbps)"]
            print(tabulate(wifi_data, headers=headers, tablefmt="grid"))
        else:
            print("No networks detected. Try increasing the monitoring duration.")
    except PermissionError:
        print("Permission denied. Please run this script as root or with sudo privileges.")
    except KeyboardInterrupt:
        print("\nMonitoring interrupted by user.")
    except Exception as e:
        print(f"An error occurred: {e}")


def main():
    """Main function."""
    args = parse_arguments()
    try:
        monitor_wifi(args.interface, args.timeout)
    except Exception as e:
        print(f"Error: {e}")
        exit(1)


if __name__ == "__main__":
    main()
