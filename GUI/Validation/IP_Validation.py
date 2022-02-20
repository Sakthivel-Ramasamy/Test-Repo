import ipaddress
import json
import os
import sys

try:
    file=open(os.path.dirname(__file__)+"/../input.json", "r")
    json_data=json.load(file)
    ipaddr=json_data["IP_Address"]
    ipaddress.ip_address(ipaddr)
except ValueError:
    output=open(os.path.dirname(__file__)+"/../error.hop", "a")
    output.truncate(0)
    output.write("Error")
    output.close()
    sys.exit()