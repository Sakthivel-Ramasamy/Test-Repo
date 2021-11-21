import ipaddress
import nmap
import prettytable
from scapy.all import *
import sys
from termcolor import colored

#Start of Host Discovery Scanner

def host_discovery_scanner_using_nmap(network):
    counthost=0
    host_discovery_scanner_using_nmap_start_time=datetime.now()
    print("\nHost Discovery using Nmap Scan started at {}".format(host_discovery_scanner_using_nmap_start_time))
    print("\nScanning Please Wait...")
    print("(Note: This may take some time)")
    nm=nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn')
    host_list=list(nm.all_hosts())
    #host_list=sorted(ipaddress.ip_address(ipaddr) for ipaddr in host_list)
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
        #type_of_response=nm[host]['status']['reason']
        host_discovery_using_nmap_output_table.add_row([counthost, host, macaddress, vendor])
    print("\nHost Discovery Using Nmap Result:")
    print(host_discovery_using_nmap_output_table)
    print("\nTotal {} hosts are alive in the given network {}".format(counthost, network))
    host_discovery_scanner_using_nmap_stop_time=datetime.now()
    print("Host Discovery using Nmap Scan ended at {}".format(host_discovery_scanner_using_nmap_stop_time))
    print("Total Scan Duration in Seconds = {}".format(abs(host_discovery_scanner_using_nmap_stop_time-host_discovery_scanner_using_nmap_start_time).total_seconds()))

def host_discovery_scanner_using_scapy(network):
    counthost=0
    host_discovery_scanner_using_scapy_start_time=datetime.now()
    print("\nHost Discovery using Scay Scan started at {}".format(host_discovery_scanner_using_scapy_start_time))
    print("\nScanning Please Wait...")
    print("(Note: This may take negligible time)")
    a=Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24")
    result=srp(a,timeout=3,verbose=False)[0]
    host_discovery_using_scapy_output_table = prettytable.PrettyTable(["Number", "IP Address", "MAC Address", "Vendor"])
    for element in result:
        #print("IP Address: {} MAC Address: {}".format(element[1].psrc, element[1].hwsrc))
        counthost+=1
        macaddress=element[1].hwsrc
        macaddress=macaddress.replace(":", "").replace("-", "").replace(".","").upper()
        macaddress_file_contents=open("Mac-Vendors", "r").read()
        for macaddr in macaddress_file_contents.split("\n"):
            if macaddr[0:6] == macaddress[0:6]:
                vendor=macaddr[7:].strip()
                break
        host_discovery_using_scapy_output_table.add_row([counthost, element[1].psrc, element[1].hwsrc, vendor])
    print("\nHost Discovery Using Scapy Result:")
    print(host_discovery_using_scapy_output_table)
    print("\nTotal {} hosts are alive in the given network {}".format(counthost, network))
    host_discovery_scanner_using_scapy_stop_time=datetime.now()
    print("Host Discovery using Scapy Scan ended at {}".format(host_discovery_scanner_using_scapy_stop_time))
    print("Total Scan Duration in Seconds = {}".format(abs(host_discovery_scanner_using_scapy_stop_time-host_discovery_scanner_using_scapy_start_time).total_seconds()))

#End of Host Discovery Scanner

#Start of main Function

if __name__=="__main__": 
    os_type=sys.platform
    if os_type=='win32':
        os.system('color')   
    print("\nEnter 1 to scan using Nmap (Speed of Scan: Moderate)\n      2 to scan using Scapy (Speed of Scan: Fast)\n")
    print(colored("$ hopperjet(", "green", attrs=['bold']), end="")
    print(colored("menu->hostdiscovery", "blue", attrs=['bold']), end="")
    print(colored(") >", "green", attrs=['bold']), end=" ")
    choice=int(input())
    if(choice==1):
        host_discovery_scanner_using_nmap()
    elif(choice==2):
        host_discovery_scanner_using_scapy()

#End of main Function
