import ipaddress
import sys

try:
    ipaddr=input("\nEnter the Target IP Address (Default: 127.0.0.1): ")
    ipaddress.ip_address(ipaddr)
except ValueError:
    output=open("error.hop", "w")
    output.close()
    sys.exit()