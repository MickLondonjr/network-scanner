---

# Network Scanner

This Python script scans a specified network for active devices and retrieves their IP addresses, MAC addresses, vendor information, and host names.

## Features

- Scans the network for active devices.
- Retrieves MAC addresses and resolves their vendors using the `mac-vendor-lookup` library.
- Resolves host names for discovered IP addresses.

## Requirements

- Python 3.x
- `scapy`
- `mac-vendor-lookup`

## Setup

### Clone the Repository

```bash
git clone git@github.com:YourUsername/network-scanner.git
cd network-scanner
```

### Create and Activate a Virtual Environment

```bash
python3 -m venv network-scanner-env
source network-scanner-env/bin/activate
```

### Install the Required Packages

```bash
pip install scapy mac-vendor-lookup
```

## Usage

To run the script, use the following command:

```bash
sudo ~/path/to/network-scanner-env/bin/python3 network-scanner.py -t [Target IP Range]
```

Replace `[Target IP Range]` with the actual IP range you want to scan, for example:

```bash
sudo ~/network-scanner/network-scanner-env/bin/python3 network-scanner.py -t 192.168.1.0/24
```

### Example Output

```
[+] Updating MAC vendor list...
[+] MAC vendor list updated successfully.
IP                      MAC Address                     Vendor                  Host Name
-----------------------------------------------------------------------------------------------
192.168.1.1             00:1c:42:00:00:18               Parallels, Inc.         prl-local-ns-server.shared
192.168.1.2             52:ed:3c:f3:78:64               Unknown Vendor          Unknown
```

## Notes

- **Direct Python Interpreter Call**: Due to the requirement of using `sudo`, make sure to call the Python interpreter directly from your virtual environment as shown in the usage instructions.
- **MAC Vendor List**: The script automatically updates the MAC vendor list before scanning.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
