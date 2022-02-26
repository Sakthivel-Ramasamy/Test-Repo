import datetime
import ipaddress
import json
import nmap
import os
import prettytable
from scapy.all import *
import sys

#Start of Promiscuous Mode Detection Scanner

def gettime():
    try:
        current_time=datetime.datetime.now()
    except Exception:
        current_time=datetime.now()
    return current_time

def promiscuous_response_identifier(ip):
    a=Ether(dst="FF:FF:FF:FF:FF:FE")/ARP(pdst=ip)
    result = srp(a,timeout=3,verbose=False)[0]
    return result[0][1].hwsrc
    
def promiscuous_device_scanner_using_ip_address(ip):
    counthost=1
    countpromiscuoushost=0
    countnotpromiscuoushost=0
    promiscuous_device_scanner_using_ip_address_start_time=gettime()
    promiscuous_mode_detection_using_ip_address_output_table = prettytable.PrettyTable(["Number", "IP Address", "MAC Address", "Status"])
    macaddress="Error"
    try:
        result=promiscuous_response_identifier(ip)
        countpromiscuoushost+=1
        #print(colored("The ip {}".format(ip) + " is in promiscuous mode", "white", "on_red", attrs=['bold']))
        status="Promiscuous Mode Suspected"
        attack_output=open(os.path.dirname(__file__)+"/../error.hop", "w")
        attack_output.close()
    except:
        countnotpromiscuoushost+=1
        #print(colored("The ip {}".format(ip) + " is not in promiscuous mode", "white", "on_green", attrs=['bold']))
        status="No Promiscuous Mode Suspected"
    promiscuous_mode_detection_using_ip_address_output_table.add_row([counthost, ip, macaddress, status])
    promiscuous_device_scanner_using_ip_address_stop_time=gettime()
    output=open(os.path.dirname(__file__)+"/../output.hop", "a")
    output.truncate(0)
    output.write("Promiscuous Device Scanner using IP Address started at {}".format(promiscuous_device_scanner_using_ip_address_start_time))
    output.write("\n\nPromiscuous Mode Detection Using IP Address Result:\n")
    output.write(str(promiscuous_mode_detection_using_ip_address_output_table))
    output.write("\n\nPromiscuous Device Scanner using IP Address ended at {}".format(promiscuous_device_scanner_using_ip_address_stop_time))
    output.write("\nTotal Scan Duration in Seconds = {}".format(abs(promiscuous_device_scanner_using_ip_address_stop_time-promiscuous_device_scanner_using_ip_address_start_time).total_seconds()))
    output.close()

def promiscuous_devices_scanner_using_nmap(network):
    promiscuous_devices_scanner_using_nmap_start_time=gettime()
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
    promiscuous_devices_scanner_using_nmap_stop_time=gettime()
    output=open(os.path.dirname(__file__)+"/../output.hop", "a")
    output.truncate(0)
    output.write("Promiscuous Devices Scanner using Nmap started at {}".format(promiscuous_devices_scanner_using_nmap_start_time))
    output.write("\n\nPromiscuous Mode Detection Using Nmap Results:\n")
    output.write(str(promiscuous_mode_detection_using_nmap_output_table))
    output.write("\n\nTotal {} hosts are alive in the given network {}".format(counthost, network))
    output.write("\nNumber of Hosts in Promisucous Mode = {}\nNumber of Hosts not in Promisucous Mode = {}".format(countpromiscuoushost, countnotpromiscuoushost))
    output.write("\nPromiscuous Devices Scanner using Nmap ended at {}".format(promiscuous_devices_scanner_using_nmap_stop_time))
    output.write("\nTotal Scan Duration in Seconds = {}".format(abs(promiscuous_devices_scanner_using_nmap_stop_time-promiscuous_devices_scanner_using_nmap_start_time).total_seconds()))
    output.close()

def promiscuous_devices_scanner_using_scapy(network):
    promiscuous_devices_scanner_using_scapy_start_time=gettime()
    a=Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network)
    result=srp(a,timeout=3,verbose=False)[0]
    counthost=0
    countpromiscuoushost=0
    countnotpromiscuoushost=0
    countpromiscuoushost=0
    countnotpromiscuoushost=0
    promiscuous_mode_detection_using_scapy_output_table = prettytable.PrettyTable(["Number", "IP Address", "MAC Address", "Status"])
    for element in result:        
        counthost+=1
        ip=element[1].psrc
        macaddress=element[1].hwsrc
        #print("\nIP Address: {} MAC Address: {}".format(element[1].psrc, element[1].hwsrc))
        try:
            result=promiscuous_response_identifier(ip)
            countpromiscuoushost+=1
            #print(colored("The ip {}".format(ip) + " is in promiscuous mode", "white", "on_red", attrs=['bold']))
            status="Promiscuous Mode Suspected"
        except:
            countnotpromiscuoushost+=1
            #print(colored("The ip {}".format(ip) + " is not in promiscuous mode", "white", "on_green", attrs=['bold']))
            status="No Promiscuous Mode Suspected"
        promiscuous_mode_detection_using_scapy_output_table.add_row([counthost, ip, macaddress, status])
    promiscuous_devices_scanner_using_scapy_stop_time=gettime()
    output=open(os.path.dirname(__file__)+"/../output.hop", "a")
    output.truncate(0)
    output.write("Promiscuous Devices Scanner using Scapy started at {}".format(promiscuous_devices_scanner_using_scapy_start_time))
    output.write("\n\nPromiscuous Mode Detection Using Scapy Results:\n")
    output.write(str(promiscuous_mode_detection_using_scapy_output_table))
    output.write("\n\nTotal {} hosts are alive in the given network {}".format(counthost, network))
    output.write("\nNumber of Hosts in Promisucous Mode = {}\nNumber of Hosts not in Promisucous Mode = {}".format(countpromiscuoushost, countnotpromiscuoushost))
    output.write("\nPromiscuous Devices Scanner using Scapy ended at {}".format(promiscuous_devices_scanner_using_scapy_stop_time))
    output.write("Total Scan Duration in Seconds = {}".format(abs(promiscuous_devices_scanner_using_scapy_stop_time-promiscuous_devices_scanner_using_scapy_start_time).total_seconds()))
    output.close()

#End of Promiscuous Mode Detection Scanner

#Start of Exit Process

def exit_process():
    sys.exit()

#End of Exit Process

#Start of main Function

if __name__=="__main__":

    file=open(os.path.dirname(__file__)+"/../input.json", "r")
    json_data=json.load(file)
    feature=json_data["Method"]
    scan_ip=json_data["IP_Address"]
    drop_down=json_data["Drop_Down"]
    if feature=="Promiscuous Detection":
        if drop_down=="IP Address Scan":
            promiscuous_device_scanner_using_ip_address(scan_ip)
        elif drop_down=="Nmap Subnet Scan":
            promiscuous_devices_scanner_using_nmap(scan_ip)
        elif drop_down=="Scapy Subnet Scan":
            promiscuous_devices_scanner_using_scapy(scan_ip)
    sys.exit()

#End of main Function