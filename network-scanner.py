
#!/usr/bin/env python

import scapy.all as scapy
import optparse
import socket
import json
from mac_vendor_lookup import MacLookup


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP / IP range.")
    parser.add_option("-o", "--output", dest="output", help="Output file to save results (e.g., results.json).")
    parser.add_option("-f", "--format", dest="format", help="Output format: table, json, or csv.", default="table")
    (options, arguments) = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target IP/IP range, use --help for more info.")
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        mac_address = element[1].hwsrc
        try:
            hostname = socket.gethostbyaddr(element[1].psrc)[0]
        except socket.herror:
            hostname = "Unknown"
        client_dict = {
            "ip": element[1].psrc,
            "mac": mac_address,
            "vendor": MacLookup().lookup(mac_address),
            "hostname": hostname
        }
        clients_list.append(client_dict)
    return clients_list

def print_result(results_list, format):
    if format == "table":
        print("IP\t\t\tMAC Address\t\t\tVendor\t\t\tHostname")
        print("---------------------------------------------------------------------------------------------------")
        for client in results_list:
            print(f"{client['ip']}\t\t{client['mac']}\t\t{client['vendor']}\t\t{client['hostname']}")
    elif format == "json":
        print(json.dumps(results_list, indent=4))
    elif format == "csv":
        print("IP,MAC,Vendor,Hostname")
        for client in results_list:
            print(f"{client['ip']},{client['mac']},{client['vendor']},{client['hostname']}")

def save_result(results_list, filename):
    with open(filename, 'w') as f:
        json.dump(results_list, f, indent=4)
    print(f"[+] Results saved to {filename}")

options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result, options.format)

if options.output:
    save_result(scan_result, options.output)
