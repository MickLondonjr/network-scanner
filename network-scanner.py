#!/usr/bin/env python3

import scapy.all as scapy
import optparse
import socket
from mac_vendor_lookup import MacLookup, VendorNotFoundError


def list_interfaces():
    try:
        ifconfig_result = subprocess.check_output(["ifconfig"]).decode('utf-8')
        interfaces = re.findall(r'(\w+):.*?\n.*?ether ((?:\w{2}:){5}\w{2})', ifconfig_result, re.DOTALL)

        if interfaces:
            print("[+] Available network interfaces and their MAC addresses:")
            for interface, mac in interfaces:
                print(f"    Interface: {interface}, MAC: {mac}")
        else:
            print("[-] No network interfaces with MAC addresses found.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Error occurred while running ifconfig: {e}")


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP / IP range.")
    (options, arguments) = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target IP range, use --help for more info.")
    return options


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        mac_address = element[1].hwsrc
        try:
            vendor = MacLookup().lookup(mac_address)
        except VendorNotFoundError:
            vendor = "Unknown Vendor"
        client_dict = {
            "ip": element[1].psrc,
            "mac": mac_address,
            "vendor": vendor,
            "hostname": get_hostname(element[1].psrc)
        }
        clients_list.append(client_dict)
    return clients_list


def print_result(results_list):
    print("IP\t\t\tMAC Address\t\t\tVendor\t\t\tHost Name")
    print("-----------------------------------------------------------------------------------------------")
    for client in results_list:
        print(f"{client['ip']}\t\t{client['mac']}\t\t{client['vendor']}\t\t{client['hostname']}")


def update_mac_vendor_list():
    print("[+] Updating MAC vendor list...")
    MacLookup().update_vendors()
    print("[+] MAC vendor list updated successfully.")


if __name__ == "__main__":
    options = get_arguments()

    # Update the MAC vendor list before scanning
    update_mac_vendor_list()

    scan_result = scan(options.target)
    print_result(scan_result)
