import datetime
import ipaddress
import nmap
import os
import prettytable
import sys
from termcolor import colored

#Start of Host Discovery Scanner

def host_discovery_scanner_using_nmap(network):
    counthost=0
    host_discovery_scanner_using_nmap_start_time=datetime.datetime.now()
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
    host_discovery_scanner_using_nmap_stop_time=datetime.datetime.now()
    output=open("host_nmap_out.hop", "a")
    output.truncate(0)
    output.write("Host Discovery using Nmap Scan started at {}".format(host_discovery_scanner_using_nmap_start_time))
    output.write("\n\nScanning Please Wait...")
    output.write("\n(Note: This may take some time)")
    output.write("\n\nHost Discovery Using Nmap Result:\n")
    output.write(str(host_discovery_using_nmap_output_table))
    output.write("\n\nTotal {} hosts are alive in the given network {}".format(counthost, network))    
    output.write("\nHost Discovery using Nmap Scan ended at {}".format(host_discovery_scanner_using_nmap_stop_time))
    output.write("\nTotal Scan Duration in Seconds = {}".format(abs(host_discovery_scanner_using_nmap_stop_time-host_discovery_scanner_using_nmap_start_time).total_seconds()))
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
        host_discovery_scanner_using_nmap(network)
    except ValueError:
        print("\nInvalid IP CIDR Address Entered...")

#End of main Function
