import datetime
import ipaddress
import os
import prettytable
from scapy.all import *
import sys
from termcolor import colored

#Start of Port Scanner

def udp_scan(dst_ip,dst_port,dst_timeout):
    udp_scan_resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout)
    if (udp_scan_resp is None):
        retrans = []
        for count in range(0,3):
            retrans.append(sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout))
        for item in retrans:
            if (item is not None):
                udp_scan(dst_ip,dst_port,dst_timeout)
        return ("Open|Filtered")
    elif (udp_scan_resp.haslayer(UDP)):
        return ("Open")
    elif(udp_scan_resp.haslayer(ICMP)):
        if(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code)==3):
            return ("Closed")
        elif(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code) in [1,2,9,10,13]):
            return ("Filtered")
    else:
        return ("Error")

def udp_scan_port_scanner(ip, port_list, timeout):
    output=open("udp_scan_out.hop", "a")
    output.truncate(0)
    udp_scan_port_scanner_start_time=datetime.now()
    output.write("UDP Scan Port Scanner started at {}".format(udp_scan_port_scanner_start_time))
    udp_scan_port_scanner_output_table = prettytable.PrettyTable(["Port", "UDP Scan"])
    output.write("\n\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, port_list))    
    for i in port_list:
        output.write("\n\nStarting UDP Scan for {}:{}...".format(ip, i))
        udp_scan_res = udp_scan(ip,int(i),int(timeout))
        output.write("\nUDP Scan Completed for {}:{}".format(ip, i))
        udp_scan_port_scanner_output_table.add_row([i, udp_scan_res])
    output.write("\n\n[*] Scan Completed for the Target: {}\n\nUDP Scan Result:\n".format(ip))
    output.write(str(udp_scan_port_scanner_output_table))
    udp_scan_port_scanner_stop_time=datetime.now()
    output.write("\n\nUDP Scan Port Scanner ended at {}".format(udp_scan_port_scanner_stop_time))
    output.write("\nTotal Scan Duration in Seconds = {}".format(abs(udp_scan_port_scanner_stop_time-udp_scan_port_scanner_start_time).total_seconds()))

#End of Port Scanner

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
    except ValueError:
        print("\nInvalid IP Address Entered...")
        exit_process()
    try:
        port=input("\nEnter the Port(s) to Scan: ")
    except ValueError:
        print("\nNo Ports Entered...")
        exit_process()
    try:
        timeout=int(input("\nEnter the Timeout Duration (Default: 2): "))
    except ValueError:
        timeout=2
    try:
        verbose=int(input("\nEnter the Level of Verbosity [From 0 (almost mute) to 3 (verbose)] (Default: 0): "))
    except ValueError:
        verbose=0
    conf.verb=verbose
    port_list=[]
    if "," in port:
        port=port.split(",")
        port.sort()
        port_list+=port
    elif "-" in port:
        port=port.split("-")
        port.sort()
        portlow=int(port[0])
        porthigh=int(port[1])
        portrange=range(portlow, porthigh)
        port_list+=portrange
    else:
        port_list.append(port)
    port_list=list(set(port_list))
    temp_ports=[]
    for item in port_list:
            temp_ports.append(int(item))
    port_list = temp_ports
    port_list.sort()
    udp_scan_port_scanner(ip, port_list, timeout)

#End of main Functions
