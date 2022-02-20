import ipaddress
import sys

try:
    ipaddr=input("\nEnter the Target IP Address (Default: 127.0.0.1): ")
    ipaddress.ip_address(ipaddr)
except ValueError:
    print("\nInvalid IP Address Entered...")
    sys.exit()