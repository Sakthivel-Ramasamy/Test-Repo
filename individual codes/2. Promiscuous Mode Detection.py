import ipaddress
import nmap
import prettytable
from scapy.all import *
import sys
from termcolor import colored

#Start of Promiscuous Mode Detection Scanner

def promiscuous_response_identifier(ip):
    a=Ether(dst="FF:FF:FF:FF:FF:FE")/ARP(pdst=ip)
    result = srp(a,timeout=3,verbose=False)[0]
    return result[0][1].hwsrc
    
def promiscuous_device_scanner_using_ip_address(ip):
    promiscuous_device_scanner_using_ip_address_start_time=datetime.now()
    print("\nPromiscuouc Device Scanner using IP Address started at {}".format(promiscuous_device_scanner_using_ip_address_start_time))
    counthost=1
    global countpromiscuoushost
    global countnotpromiscuoushost
    promiscuous_mode_detection_using_ip_address_output_table = prettytable.PrettyTable(["Number", "IP Address", "MAC Address", "Status"])
    macaddress="Error"
    try:
        result=promiscuous_response_identifier(ip)
        countpromiscuoushost+=1
        #print(colored("The ip {}".format(ip) + " is in promiscuous mode", "white", "on_red", attrs=['bold']))
        status="Promiscuous Mode Suspected"
    except:
        countnotpromiscuoushost+=1
        #print(colored("The ip {}".format(ip) + " is not in promiscuous mode", "white", "on_green", attrs=['bold']))
        status="No Promiscuous Mode Suspected"
    promiscuous_mode_detection_using_ip_address_output_table.add_row([counthost, ip, macaddress, status])
    print("\nPromiscuous Mode Detection Using IP Address Result:")
    print(promiscuous_mode_detection_using_ip_address_output_table)
    promiscuous_device_scanner_using_ip_address_stop_time=datetime.now()
    print("\nPromiscuous Device Scanner using IP Address ended at {}".format(promiscuous_device_scanner_using_ip_address_stop_time))
    print("\nTotal Scan Duration in Seconds = {}".format(abs(promiscuous_device_scanner_using_ip_address_stop_time-promiscuous_device_scanner_using_ip_address_start_time).total_seconds()))

def promiscuous_devices_scanner_using_nmap(network):
    promiscuous_devices_scanner_using_nmap_start_time=datetime.now()
    print("\nPromiscuous Devices Scanner using Nmap started at {}".format(promiscuous_devices_scanner_using_nmap_start_time))
    nm=nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn')
    host_list=list(nm.all_hosts())
    #host_list=sorted(ipaddress.ip_address(ipaddr) for ipaddr in host_list)
    host_list=sorted(host_list, key=ipaddress.IPv4Address)
    counthost=0
    global countpromiscuoushost
    global countnotpromiscuoushost
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
    print("\nPromiscuous Mode Detection Using Nmap Results:")
    print(promiscuous_mode_detection_using_nmap_output_table)
    print("\nTotal {} hosts are alive in the given network {}".format(counthost, network))
    print("Number of Hosts in Promisucous Mode = {}\nNumber of Hosts not in Promisucous Mode = {}".format(countpromiscuoushost, countnotpromiscuoushost))
    promiscuous_devices_scanner_using_nmap_stop_time=datetime.now()
    print("\npromiscuous Devices Scanner using Nmap ended at {}".format(promiscuous_devices_scanner_using_nmap_stop_time))
    print("Total Scan Duration in Seconds = {}".format(abs(promiscuous_devices_scanner_using_nmap_stop_time-promiscuous_devices_scanner_using_nmap_start_time).total_seconds()))

def promiscuous_devices_scanner_using_scapy(network):
    promiscuous_devices_scanner_using_scapy_start_time=datetime.now()
    print("\nPromiscuous Devices Scanner using Scapy started at {}".format(promiscuous_devices_scanner_using_scapy_start_time))
    a=Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24")
    result=srp(a,timeout=3,verbose=False)[0]
    counthost=0
    global countpromiscuoushost
    global countnotpromiscuoushost
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
    print("\nPromiscuous Mode Detection Using Scapy Results:")
    print(promiscuous_mode_detection_using_scapy_output_table)
    print("\nTotal {} hosts are alive in the given network {}".format(counthost, network))
    print("Number of Hosts in Promisucous Mode = {}\nNumber of Hosts not in Promisucous Mode = {}".format(countpromiscuoushost, countnotpromiscuoushost))
    promiscuous_devices_scanner_using_scapy_stop_time=datetime.now()
    print("\nPromiscuous Devices Scanner using Scapy ended at {}".format(promiscuous_devices_scanner_using_scapy_stop_time))
    print("Total Scan Duration in Seconds = {}".format(abs(promiscuous_devices_scanner_using_scapy_stop_time-promiscuous_devices_scanner_using_scapy_start_time).total_seconds()))

#End of Promiscuous Mode Detection Scanner

#Start of Exit Process

def exit_process():
    sys.exit()

#End of Exit Process

#Start of main Function

if __name__=="__main__":
    os_type=sys.platform
    if os_type=='win32':
        os.system('color')    
    print("\nEnter 1 for Individual IPScan\n      2 for Subnet Scan\n")
    print(colored("$ hopperjet(", "green", attrs=['bold']), end="")
    print(colored("menu->promiscuousmodedetection", "blue", attrs=['bold']), end="")
    print(colored(") >", "green", attrs=['bold']), end=" ")
    countpromiscuoushost=0
    countnotpromiscuoushost=0
    suboption=int(input())
    if(suboption==1):
        try:
            ipaddr=input("\nEnter the Target IP Address (Default: 127.0.0.1): ")
            if len(ipaddr)==0:
                ip='127.0.0.1'
            else:
                ip=ipaddr
            ipaddress.ip_address(ip)
            promiscuous_device_scanner_using_ip_address(ip)
        except ValueError:
                print("\nInvalid IP Address Entered...")
                exit_process()
    elif(suboption==2):
        print("\nEnter 1 to scan using Nmap (Speed of Scan: Moderate)\n      2 to scan using Scapy (Speed of Scan: Fast)\n")
        print(colored("$ hopperjet(", "green", attrs=['bold']), end="")
        print(colored("hopperjetmenu->promiscuousmodedetection->selectmethod", "blue", attrs=['bold']), end="")
        print(colored(") >", "green", attrs=['bold']), end=" ")
        choice=int(input())
        if(choice==1):
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
        elif(choice==2):
            try:
                network=input("\nEnter the IP in CIDR Notation (Default: 192.168.1.0/24): ")
                if len(network)==0:
                    network='192.168.1.0/24'
                ipaddress.ip_network(network)
                print("\nScanning Please Wait...")
                print("(Note: This may take negligible time)")
                promiscuous_devices_scanner_using_scapy(network)
            except ValueError:
                print("\nInvalid IP CIDR Address Entered...")
                exit_process()

#End of main Function
