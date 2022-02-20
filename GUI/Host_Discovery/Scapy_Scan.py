import datetime
import ipaddress
import os
import prettytable
from scapy.all import *
import sys
from termcolor import colored

#Start of Host Discovery Scanner

def host_discovery_scanner_using_scapy(network):
    counthost=0
    host_discovery_scanner_using_scapy_start_time=datetime.now()
    a=Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24")
    result=srp(a,timeout=3,verbose=False)[0]
    host_discovery_using_scapy_output_table = prettytable.PrettyTable(["Number", "IP Address", "MAC Address", "Vendor"])
    for element in result:
        counthost+=1
        macaddress=element[1].hwsrc
        macaddress=macaddress.replace(":", "").replace("-", "").replace(".","").upper()
        macaddress_file_contents=open("Mac-Vendors", "r").read()
        for macaddr in macaddress_file_contents.split("\n"):
            if macaddr[0:6] == macaddress[0:6]:
                vendor=macaddr[7:].strip()
                break
        host_discovery_using_scapy_output_table.add_row([counthost, element[1].psrc, element[1].hwsrc, vendor])
    host_discovery_scanner_using_scapy_stop_time=datetime.now()
    output=open("output.hop", "a")
    output.truncate(0)
    output.write("Host Discovery using Scay Scan started at {}".format(host_discovery_scanner_using_scapy_start_time))
    output.write("\n\nScanning Please Wait...")
    output.write("\n(Note: This may take negligible time)")
    output.write("\n\nHost Discovery Using Scapy Result:\n")
    output.write(str(host_discovery_using_scapy_output_table))
    output.write("\n\nTotal {} hosts are alive in the given network {}".format(counthost, network))
    output.write("\nHost Discovery using Scapy Scan ended at {}".format(host_discovery_scanner_using_scapy_stop_time))
    output.write("\nTotal Scan Duration in Seconds = {}".format(abs(host_discovery_scanner_using_scapy_stop_time-host_discovery_scanner_using_scapy_start_time).total_seconds()))
    output.close()    

#End of Host Discovery Scanner

#Start of main Function

if __name__=="__main__": 

    #Start of Color Code

    os_type=sys.platform
    if os_type=='win32':
        os.system('color')
    
    #End of Color Code
    
    try:
        network=input("\nEnter the IP in CIDR Notation (Format: 192.168.1.0/24): ")    
        ipaddress.ip_network(network)
        host_discovery_scanner_using_scapy(network)
    except ValueError:
        print("\nInvalid IP CIDR Address Entered...")

#End of main Function
