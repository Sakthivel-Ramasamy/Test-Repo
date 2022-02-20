import datetime
import ipaddress
import os
import prettytable
from scapy.all import *
import sys
from termcolor import colored

#Start of Port Scanner

def tcp_window_scan(dst_ip,dst_port,dst_timeout):
    window_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="A"),timeout=dst_timeout)
    if (window_scan_resp is None):
        return ("No response")
    elif(window_scan_resp.haslayer(TCP)):
        if(window_scan_resp.getlayer(TCP).window == 0):
            return ("Closed")
        elif(window_scan_resp.getlayer(TCP).window > 0):
            return ("Open")
    else:
        return ("Error")

def tcp_window_scan_port_scanner(ip, port_list, timeout):
    output=open("output.hop", "a")
    output.truncate(0)
    tcp_window_scan_port_scanner_start_time=datetime.now()
    output.write("TCP Window Scan Port Scanner started at {}".format(tcp_window_scan_port_scanner_start_time))
    tcp_window_scan_port_scanner_output_table = prettytable.PrettyTable(["Port", "TCP Window Scan"])
    output.write("\n\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, port_list))    
    for i in port_list:
        output.write("\n\nStarting TCP Window Scan for {}:{}...".format(ip, i))
        tcp_window_scan_res = tcp_window_scan(ip,int(i),int(timeout))
        output.write("\nTCP Window Scan Completed for {}:{}".format(ip, i))
        tcp_window_scan_port_scanner_output_table.add_row([i, tcp_window_scan_res])
    output.write("\n\n[*] Scan Completed for the Target: {}\n\nTCP Window Scan Result:\n".format(ip))
    output.write(str(tcp_window_scan_port_scanner_output_table))
    tcp_window_scan_port_scanner_stop_time=datetime.now()
    output.write("\n\nTCP Window Scan Port Scanner ended at {}".format(tcp_window_scan_port_scanner_stop_time))
    output.write("\nTotal Scan Duration in Seconds = {}".format(abs(tcp_window_scan_port_scanner_stop_time-tcp_window_scan_port_scanner_start_time).total_seconds()))
    output.close()

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
    tcp_window_scan_port_scanner(ip, port_list, timeout)

#End of main Function
