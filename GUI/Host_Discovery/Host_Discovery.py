import datetime
import ipaddress
import json
import nmap
import os
import prettytable
from scapy.all import *
import sys

#Start of Host Discovery Scanner

def gettime():
    try:
        current_time=datetime.datetime.now()
    except Exception:
        current_time=datetime.now()
    return current_time

def host_discovery_scanner_using_nmap(network):
    counthost=0
    host_discovery_scanner_using_nmap_start_time=gettime()
    nm=nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn')
    host_list=list(nm.all_hosts())
    host_list=sorted(host_list, key=ipaddress.IPv4Address)
    host_discovery_using_nmap_output_table = prettytable.PrettyTable(["Number", "IP Address", "MAC Address", "Vendor"])
    for host in host_list:
        counthost+=1
        try:
            macaddress=nm[host]['addresses']['mac']
        except:
            macaddress="Might be a local interface /\nNot running as a super user /\nError in getting it..."
        try:
            manufacturer=nm[host]['vendor']
            vendor=manufacturer[macaddress]
        except:
            vendor="Might be a local interface /\nNot running as a super user /\nError in getting it..."
        host_discovery_using_nmap_output_table.add_row([counthost, host, macaddress, vendor])
    host_discovery_scanner_using_nmap_stop_time=gettime()
    output=open(os.path.dirname(__file__)+"/../output.hop", "a")
    output.truncate(0)
    output.write("Host Discovery using Nmap Scan started at {}".format(host_discovery_scanner_using_nmap_start_time))
    output.write("\n\nHost Discovery Using Nmap Result:\n")
    output.write(str(host_discovery_using_nmap_output_table))
    output.write("\n\nTotal {} hosts are alive in the given network {}".format(counthost, network))    
    output.write("\nHost Discovery using Nmap Scan ended at {}".format(host_discovery_scanner_using_nmap_stop_time))
    output.write("\nTotal Scan Duration in Seconds = {}".format(abs(host_discovery_scanner_using_nmap_stop_time-host_discovery_scanner_using_nmap_start_time).total_seconds()))
    output.close()

def host_discovery_scanner_using_scapy(network):
    counthost=0
    host_discovery_scanner_using_scapy_start_time=gettime()
    a=Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24")
    result=srp(a,timeout=3,verbose=False)[0]
    host_discovery_using_scapy_output_table = prettytable.PrettyTable(["Number", "IP Address", "MAC Address", "Vendor"])
    for element in result:
        counthost+=1
        macaddress=element[1].hwsrc
        macaddress=macaddress.replace(":", "").replace("-", "").replace(".","").upper()
        macaddress_file_contents=open(os.path.dirname(__file__)+"/../Mac-Vendors", "r").read()
        for macaddr in macaddress_file_contents.split("\n"):
            if macaddr[0:6] == macaddress[0:6]:
                vendor=macaddr[7:].strip()
                break
        if len(vendor)!=0:
            host_discovery_using_scapy_output_table.add_row([counthost, element[1].psrc, element[1].hwsrc, vendor])
        else:
            vendor="Error Occurred"
            host_discovery_using_scapy_output_table.add_row([counthost, element[1].psrc, element[1].hwsrc, vendor])
    host_discovery_scanner_using_scapy_stop_time=gettime()
    output=open(os.path.dirname(__file__)+"/../output.hop", "a")
    output.truncate(0)
    output.write("Host Discovery using Scay Scan started at {}".format(host_discovery_scanner_using_scapy_start_time))
    output.write("\n\nHost Discovery Using Scapy Result:\n")
    output.write(str(host_discovery_using_scapy_output_table))
    output.write("\n\nTotal {} hosts are alive in the given network {}".format(counthost, network))
    output.write("\nHost Discovery using Scapy Scan ended at {}".format(host_discovery_scanner_using_scapy_stop_time))
    output.write("\nTotal Scan Duration in Seconds = {}".format(abs(host_discovery_scanner_using_scapy_stop_time-host_discovery_scanner_using_scapy_start_time).total_seconds()))
    output.close()

#End of Host Discovery Scanner

#Start of main Function

if __name__=="__main__": 
    
    file=open(os.path.dirname(__file__)+"/../input.json", "r")
    json_data=json.load(file)
    feature=json_data["Method"]
    network=json_data["IP_Address"]
    drop_down=json_data["Drop_Down"]
    if feature=="Host Discovery":
        if drop_down=="Nmap":
            host_discovery_scanner_using_nmap(network)
        elif drop_down=="Scapy":
            host_discovery_scanner_using_scapy(network)
    sys.exit()

#End of main Function