import datetime
import ipaddress
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
    
def promiscuous_device_scanner_using_ip_address(ip):
    counthost=1
    countpromiscuoushost=0
    countnotpromiscuoushost=0
    promiscuous_device_scanner_using_ip_address_start_time=datetime.now()
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
    promiscuous_device_scanner_using_ip_address_stop_time=datetime.now()
    output=open("promiscuous_ip_address_out.hop", "a")
    output.truncate(0)
    output.write("Promiscuous Device Scanner using IP Address started at {}".format(promiscuous_device_scanner_using_ip_address_start_time))
    output.write("\n\nPromiscuous Mode Detection Using IP Address Result:\n")
    output.write(str(promiscuous_mode_detection_using_ip_address_output_table))
    output.write("\n\nPromiscuous Device Scanner using IP Address ended at {}".format(promiscuous_device_scanner_using_ip_address_stop_time))
    output.write("\nTotal Scan Duration in Seconds = {}".format(abs(promiscuous_device_scanner_using_ip_address_stop_time-promiscuous_device_scanner_using_ip_address_start_time).total_seconds()))
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

#End of main Function
