import datetime
import ipaddress
import os
from black import out
import prettytable
from scapy.all import *
import sys
from termcolor import colored

#Start of Port Scanner

def tcp_connect_scan(dst_ip,dst_port,dst_timeout):
    src_port = RandShort()
    tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=dst_timeout)
    if(tcp_connect_scan_resp is None):
        return ("Closed")
    elif(tcp_connect_scan_resp.haslayer(TCP)):
        if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=dst_timeout)
            return ("Open")
        elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
            return ("Closed")
    else:
        return ("Error")

def tcp_connect_scan_port_scanner(ip, port_list, timeout):
    output=open("tcp_connect_scan_out.hop", "a")
    output.truncate(0)
    tcp_connect_scan_port_scanner_start_time=datetime.now()
    output.write("TCP Connect Scan Port Scanner started at {}".format(tcp_connect_scan_port_scanner_start_time))
    tcp_connect_scan_port_scanner_output_table = prettytable.PrettyTable(["Port", "TCP Connect Scan"])    
    output.write("\n\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, port_list))    
    for i in port_list:
        output.write("\n\nStarting TCP Connect Scan for {}:{}...".format(ip, i))
        tcp_connect_scan_res = tcp_connect_scan(ip,int(i),int(timeout))
        output.write("\nTCP Connect Scan Completed for {}:{}".format(ip, i))
        tcp_connect_scan_port_scanner_output_table.add_row([i, tcp_connect_scan_res])
    output.write("\n\n[*] Scan Completed for the Target: {}\n\nTCP Connect Scan Result:\n".format(ip))
    output.write(str(tcp_connect_scan_port_scanner_output_table))
    tcp_connect_scan_port_scanner_stop_time=datetime.now()
    output.write("\n\nTCP Connect Scan Port Scanner ended at {}".format(tcp_connect_scan_port_scanner_stop_time))
    output.write("\nTotal Scan Duration in Seconds = {}".format(abs(tcp_connect_scan_port_scanner_stop_time-tcp_connect_scan_port_scanner_start_time).total_seconds()))
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
    tcp_connect_scan_port_scanner(ip, port_list, timeout)

#End of main Function
