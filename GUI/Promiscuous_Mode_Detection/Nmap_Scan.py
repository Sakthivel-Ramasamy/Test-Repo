import datetime
import ipaddress
import nmap
import os
import prettytable
from scapy.all import *
import sys
from termcolor import colored

#Start of Promiscuous Mode Detection Scanner

def promiscuous_response_identifier(ip):
    a=Ether(dst="FF:FF:FF:FF:FF:FE")/ARP(pdst=ip)
    result = srp(a,timeout=3,verbose=False)[0]
    return result[0][1].hwsrc

def promiscuous_devices_scanner_using_nmap(network):
    promiscuous_devices_scanner_using_nmap_start_time=datetime.now()
    nm=nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn')
    host_list=list(nm.all_hosts())
    #host_list=sorted(ipaddress.ip_address(ipaddr) for ipaddr in host_list)
    host_list=sorted(host_list, key=ipaddress.IPv4Address)
    counthost=0
    countpromiscuoushost=0
    countnotpromiscuoushost=0
    countpromiscuoushost=0
    countnotpromiscuoushost=0
    promiscuous_mode_detection_using_nmap_output_table = prettytable.PrettyTable(["Number", "IP Address", "MAC Address", "Status"])
    for host in host_list:
        counthost+=1
        ip=host
        try:
            macaddress=nm[host]['addresses']['mac']
        except:
            macaddress="Might be a local interface /\nNot running as a super user /\nError in getting it..."
        try:
            result=promiscuous_response_identifier(ip)
            countpromiscuoushost+=1
            #print(colored("The ip {}".format(ip) + " is in promiscuous mode", "white", "on_red", attrs=['bold']))
            status="Promiscuous Mode Suspected"
        except:
            countnotpromiscuoushost+=1
            #print(colored("The ip {}".format(ip) + " is not in promiscuous mode", "white", "on_green", attrs=['bold']))
            status="No Promiscuous Mode Suspected"
        promiscuous_mode_detection_using_nmap_output_table.add_row([counthost, ip, macaddress, status])
    promiscuous_devices_scanner_using_nmap_stop_time=datetime.now()
    output=open("output.hop", "a")
    output.truncate(0)
    output.write("Promiscuous Devices Scanner using Nmap started at {}".format(promiscuous_devices_scanner_using_nmap_start_time))
    output.write("\n\nPromiscuous Mode Detection Using Nmap Results:\n")
    output.write(str(promiscuous_mode_detection_using_nmap_output_table))
    output.write("\n\nTotal {} hosts are alive in the given network {}".format(counthost, network))
    output.write("\nNumber of Hosts in Promisucous Mode = {}\nNumber of Hosts not in Promisucous Mode = {}".format(countpromiscuoushost, countnotpromiscuoushost))
    output.write("\nPromiscuous Devices Scanner using Nmap ended at {}".format(promiscuous_devices_scanner_using_nmap_stop_time))
    output.write("\nTotal Scan Duration in Seconds = {}".format(abs(promiscuous_devices_scanner_using_nmap_stop_time-promiscuous_devices_scanner_using_nmap_start_time).total_seconds()))
    output.close()

#End of Promiscuous Mode Detection Scanner

#Start of Exit Process

def exit_process():
    sys.exit()

#End of Exit Process

#Start of main Function

if __name__=="__main__":

    #Start of Color Code

    os_type=sys.platform
    if os_type=='win32':
        os.system('color')
    
    #End of Color Code

    try:
        network=input("\nEnter the IP in CIDR Notation (Default: 192.168.1.0/24): ")
        if len(network)==0:
            network='192.168.1.0/24'
        ipaddress.ip_network(network)
        print("\nScanning Please Wait...")
        print("(Note: This may take some time)")
        promiscuous_devices_scanner_using_nmap(network)
    except ValueError:
        print("\nInvalid IP CIDR Address Entered...")
        exit_process()

#End of main Function
