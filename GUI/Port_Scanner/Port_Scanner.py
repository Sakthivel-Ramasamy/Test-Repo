import datetime
import ipaddress
import json
import nmap
import os
import prettytable
from scapy.all import *
import sys

#Start of Port Scanner

def gettime():
    try:
        current_time=datetime.datetime.now()
    except Exception:
        current_time=datetime.now()
    return current_time

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

def tcp_stealth_scan(dst_ip,dst_port,dst_timeout):
    src_port = RandShort()
    stealth_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=dst_timeout)
    if(stealth_scan_resp is None):
        return ("Filtered")
    elif(stealth_scan_resp.haslayer(TCP)):
        if(stealth_scan_resp.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=dst_timeout)
            return ("Open")
        elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
            return ("Closed")
    elif(stealth_scan_resp.haslayer(ICMP)):
        if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            return ("Filtered")
    else:
        return ("Error")

def tcp_ack_scan(dst_ip,dst_port,dst_timeout):
    ack_flag_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="A"),timeout=dst_timeout)
    if (ack_flag_scan_resp is None):
        return ("Stateful firewall present\n(Filtered)")
    elif(ack_flag_scan_resp.haslayer(TCP)):
        if(ack_flag_scan_resp.getlayer(TCP).flags == 0x4):
            return ("No firewall\n(Unfiltered)")
    elif(ack_flag_scan_resp.haslayer(ICMP)):
        if(int(ack_flag_scan_resp.getlayer(ICMP).type)==3 and int(ack_flag_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            return ("Stateful firewall present\n(Filtered)")
    else:
        return ("Error")

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

def xmas_scan(dst_ip,dst_port,dst_timeout):
    xmas_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="FPU"),timeout=dst_timeout)
    if (xmas_scan_resp is None):
        return ("Open|Filtered")
    elif(xmas_scan_resp.haslayer(TCP)):
        if(xmas_scan_resp.getlayer(TCP).flags == 0x14):
            return ("Closed")
    elif(xmas_scan_resp.haslayer(ICMP)):
        if(int(xmas_scan_resp.getlayer(ICMP).type)==3 and int(xmas_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            return ("Filtered")
    else:
        return ("Error")

def fin_scan(dst_ip,dst_port,dst_timeout):
    fin_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="F"),timeout=dst_timeout)
    if (fin_scan_resp is None):
        return ("Open|Filtered")
    elif(fin_scan_resp.haslayer(TCP)):
        if(fin_scan_resp.getlayer(TCP).flags == 0x14):
            return ("Closed")
    elif(fin_scan_resp.haslayer(ICMP)):
        if(int(fin_scan_resp.getlayer(ICMP).type)==3 and int(fin_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            return ("Filtered")
    else:
        return ("Error")

def null_scan(dst_ip,dst_port,dst_timeout):
    null_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags=""),timeout=dst_timeout)
    if (null_scan_resp is None):
        return ("Open|Filtered")
    elif(null_scan_resp.haslayer(TCP)):
        if(null_scan_resp.getlayer(TCP).flags == 0x14):
            return ("Closed")
    elif(null_scan_resp.haslayer(ICMP)):
        if(int(null_scan_resp.getlayer(ICMP).type)==3 and int(null_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            return ("Filtered")
    else:
        return ("Error")

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

def tcp_connect_scan_port_scanner(ip, port_list, timeout):
    tcp_connect_scan_port_scanner_start_time=gettime()
    output=open(os.path.dirname(__file__)+"/../output.hop", "a")
    output.truncate(0)
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
    tcp_connect_scan_port_scanner_stop_time=gettime()
    output.write("\n\nTCP Connect Scan Port Scanner ended at {}".format(tcp_connect_scan_port_scanner_stop_time))
    output.write("\nTotal Scan Duration in Seconds = {}".format(abs(tcp_connect_scan_port_scanner_stop_time-tcp_connect_scan_port_scanner_start_time).total_seconds()))
    output.close()

def tcp_stealth_scan_port_scanner(ip, port_list, timeout):
    tcp_stealth_scan_port_scanner_start_time=gettime()
    output=open(os.path.dirname(__file__)+"/../output.hop", "a")
    output.truncate(0)
    output.write("TCP Stealth Scan port Scanner started at {}".format(tcp_stealth_scan_port_scanner_start_time))
    tcp_stealth_scan_port_scanner_output_table = prettytable.PrettyTable(["Port", "TCP Stealth Scan"])
    output.write("\n\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, port_list))
    for i in port_list:
        output.write("\n\nStarting TCP Stealth Scan for {}:{}...".format(ip, i))
        tcp_stealth_scan_res = tcp_stealth_scan(ip,int(i),int(timeout))
        output.write("\nTCP Stealth Scan Completed for {}:{}".format(ip, i))
        tcp_stealth_scan_port_scanner_output_table.add_row([i, tcp_stealth_scan_res])
    output.write("\n\n[*] Scan Completed for the Target: {}\n\nTCP Stealth Scan Result:\n".format(ip))
    output.write(str(tcp_stealth_scan_port_scanner_output_table))
    tcp_stealth_scan_port_scanner_stop_time=gettime()
    output.write("\n\nTCP Stealth Scan Port Scanner ended at {}".format(tcp_stealth_scan_port_scanner_stop_time))
    output.write("\nTotal Scan Duration in Seconds = {}".format(abs(tcp_stealth_scan_port_scanner_stop_time-tcp_stealth_scan_port_scanner_start_time).total_seconds()))
    output.close()

def tcp_ack_scan_port_scanner(ip, port_list, timeout):
    tcp_ack_scan_port_scanner_start_time=gettime()
    output=open(os.path.dirname(__file__)+"/../output.hop", "a")
    output.truncate(0)
    output.write("TCP ACK Scan Port Scanner started at {}".format(tcp_ack_scan_port_scanner_start_time))
    tcp_ack_scan_port_scanner_output_table = prettytable.PrettyTable(["Port", "TCP ACK Scan"])
    output.write("\n\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, port_list))    
    for i in port_list:        
        output.write("\n\nStaring TCP ACK Scan for {}:{}...".format(ip, i))
        tcp_ack_flag_scan_res = tcp_ack_scan(ip,int(i),int(timeout))
        output.write("\nTCP ACK Scan Completed for {}:{}".format(ip, i))
        tcp_ack_scan_port_scanner_output_table.add_row([i, tcp_ack_flag_scan_res])
    output.write("\n\n[*] Scan Completed for the Target: {}\n\nTCP ACK Scan Result:\n".format(ip))
    output.write(str(tcp_ack_scan_port_scanner_output_table))
    tcp_ack_scan_port_scanner_stop_time=gettime()
    output.write("\nTCP ACK Scan Port Scanner ended at {}".format(tcp_ack_scan_port_scanner_stop_time))
    output.write("Total Scan Duration in Seconds = {}".format(abs(tcp_ack_scan_port_scanner_stop_time-tcp_ack_scan_port_scanner_start_time).total_seconds()))
    output.close()

def tcp_window_scan_port_scanner(ip, port_list, timeout):
    tcp_window_scan_port_scanner_start_time=gettime()
    output=open(os.path.dirname(__file__)+"/../output.hop", "a")
    output.truncate(0)
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
    tcp_window_scan_port_scanner_stop_time=gettime()
    output.write("\n\nTCP Window Scan Port Scanner ended at {}".format(tcp_window_scan_port_scanner_stop_time))
    output.write("\nTotal Scan Duration in Seconds = {}".format(abs(tcp_window_scan_port_scanner_stop_time-tcp_window_scan_port_scanner_start_time).total_seconds()))
    output.close()

def xmas_scan_port_scanner(ip, port_list, timeout):
    xmas_scan_port_scanner_start_time=gettime()
    output=open(os.path.dirname(__file__)+"/../output.hop", "a")
    output.truncate(0)
    output.write("XMAS Scan Port Scanner started at {}".format(xmas_scan_port_scanner_start_time))
    xmas_scan_port_scanner_output_table = prettytable.PrettyTable(["Port", "XMAS Scan"])
    output.write("\n\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, port_list))    
    for i in port_list:
        output.write("\n\nStarting XMAS Scan for {}:{}...".format(ip, i))
        xmas_scan_res = xmas_scan(ip,int(i),int(timeout))
        output.write("\nXMAS Scan Completed for {}:{}".format(ip, i))
        xmas_scan_port_scanner_output_table.add_row([i, xmas_scan_res])
    output.write("\n\n[*] Scan Completed for the Target: {}\n\nXMAS Scan Result:\n".format(ip))
    output.write(str(xmas_scan_port_scanner_output_table))
    xmas_scan_port_scanner_stop_time=gettime()
    output.write("\n\nXMAS Scan Port Scanner ended at {}".format(xmas_scan_port_scanner_stop_time))
    output.write("\nTotal Scan Duration in Seconds = {}".format(abs(xmas_scan_port_scanner_stop_time-xmas_scan_port_scanner_start_time).total_seconds()))
    output.close()

def fin_scan_port_scanner(ip, port_list, timeout):
    fin_scan_port_scanner_start_time=gettime()
    output=open(os.path.dirname(__file__)+"/../output.hop", "a")
    output.truncate(0)
    output.write("FIN Scan Port Scanner started at {}".format(fin_scan_port_scanner_start_time))
    fin_scan_port_scanner_output_table = prettytable.PrettyTable(["Port", "FIN Scan"])
    output.write("\n\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, port_list))    
    for i in port_list: 
        output.write("\n\nStarting FIN Scan for {}:{}...".format(ip, i))
        fin_scan_res = fin_scan(ip,int(i),int(timeout))
        output.write("\nFIN Scan Completed for {}:{}".format(ip, i))
        fin_scan_port_scanner_output_table.add_row([i, fin_scan_res])
    output.write("\n\n[*] Scan Completed for the Target: {}\n\nFIN Scan Result:\n".format(ip))
    output.write(str(fin_scan_port_scanner_output_table))
    fin_scan_port_scanner_stop_time=gettime()
    output.write("\n\nFIN Scan Port Scanner ended at {}".format(fin_scan_port_scanner_stop_time))
    output.write("\nTotal Scan Duration in Seconds = {}".format(abs(fin_scan_port_scanner_stop_time-fin_scan_port_scanner_start_time).total_seconds()))
    output.close()

def null_scan_port_scanner(ip, port_list, timeout):
    null_scan_port_scanner_start_time=gettime()
    output=open(os.path.dirname(__file__)+"/../output.hop", "a")
    output.truncate(0)
    output.write("NULL Scan Port Scanner started at {}".format(null_scan_port_scanner_start_time))
    null_scan_port_scanner_output_table = prettytable.PrettyTable(["Port", "NULL Scan"])
    output.write("\n\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, port_list))    
    for i in port_list:
        output.write("\n\nStarting NULL Scan for {}:{}...".format(ip, i))
        null_scan_res = null_scan(ip,int(i),int(timeout))
        output.write("\nNULL Scan Completed for {}:{}".format(ip, i))      
        null_scan_port_scanner_output_table.add_row([i, null_scan_res])
    output.write("\n\n[*] Scan Completed for the Target: {}\n\nNULL Scan Result:\n".format(ip))
    output.write(str(null_scan_port_scanner_output_table))
    null_scan_port_scanner_stop_time=gettime()
    output.write("\n\nNULL Scan Port Scanner ended at {}".format(null_scan_port_scanner_stop_time))
    output.write("\nTotal Scan Duration in Seconds = {}".format(abs(null_scan_port_scanner_stop_time-null_scan_port_scanner_start_time).total_seconds()))
    output.close()

def udp_scan_port_scanner(ip, port_list, timeout):
    udp_scan_port_scanner_start_time=gettime()
    output=open(os.path.dirname(__file__)+"/../output.hop", "a")
    output.truncate(0)
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
    udp_scan_port_scanner_stop_time=gettime()
    output.write("\n\nUDP Scan Port Scanner ended at {}".format(udp_scan_port_scanner_stop_time))
    output.write("\nTotal Scan Duration in Seconds = {}".format(abs(udp_scan_port_scanner_stop_time-udp_scan_port_scanner_start_time).total_seconds()))
    output.close()

def all_methods_port_scanner(ip, port_list, timeout):
    all_methods_port_scanner_start_time=gettime()
    output=open(os.path.dirname(__file__)+"/../output.hop", "a")
    output.truncate(0)
    output.write("Port Scanner (All Methods) started at {}".format(all_methods_port_scanner_start_time))
    all_methods_port_scanner_output_table = prettytable.PrettyTable(["Port", "TCP Connect Scan", "TCP Stealth Scan", "TCP ACK Scan", "TCP Window Scan", "XMAS Scan", "FIN Scan", "NULL Scan", "UDP Scan"])
    output.write("\n\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, port_list))    
    for i in port_list:        
        output.write("\n\nStarting TCP Connect Scan for {}:{}...".format(ip, i))
        tcp_connect_scan_res = tcp_connect_scan(ip,int(i),int(timeout))
        output.write("\nTCP Connect Scan Completed for {}:{}".format(ip, i))
        output.write("\n\nStarting TCP Stealth Scan for {}:{}...".format(ip, i))
        tcp_stealth_scan_res = tcp_stealth_scan(ip,int(i),int(timeout))
        output.write("\nTCP Stealth Scan Completed for {}:{}".format(ip, i))
        output.write("\n\nStaring TCP ACK Scan for {}:{}...".format(ip, i))
        tcp_ack_flag_scan_res = tcp_ack_scan(ip,int(i),int(timeout))
        output.write("\nTCP ACK Scan Completed for {}:{}".format(ip, i))
        output.write("\n\nStarting TCP Window Scan for {}:{}...".format(ip, i))
        tcp_window_scan_res = tcp_window_scan(ip,int(i),int(timeout))
        output.write("\nTCP Window Scan Completed for {}:{}".format(ip, i))
        output.write("\n\nStarting XMAS Scan for {}:{}...".format(ip, i))
        xmas_scan_res = xmas_scan(ip,int(i),int(timeout))
        output.write("\nXMAS Scan Completed for {}:{}".format(ip, i))
        output.write("\n\nStarting FIN Scan for {}:{}...".format(ip, i))
        fin_scan_res = fin_scan(ip,int(i),int(timeout))
        output.write("\nFIN Scan Completed for {}:{}".format(ip, i))
        output.write("\n\nStarting NULL Scan for {}:{}...".format(ip, i))
        null_scan_res = null_scan(ip,int(i),int(timeout))
        output.write("\nNULL Scan Completed for {}:{}".format(ip, i))      
        output.write("\n\nStarting UDP Scan for {}:{}...".format(ip, i))
        udp_scan_res = udp_scan(ip,int(i),int(timeout))
        output.write("\nUDP Scan Completed for {}:{}".format(ip, i))
        all_methods_port_scanner_output_table.add_row([i, tcp_connect_scan_res, tcp_stealth_scan_res, tcp_ack_flag_scan_res, tcp_window_scan_res, xmas_scan_res, fin_scan_res, null_scan_res, udp_scan_res])
    output.write("\n\n[*] Scan Completed for the Target: {}\n\nPort Scanner (All Methods) Result:\n".format(ip))
    output.write(str(all_methods_port_scanner_output_table))
    all_methods_port_scanner_stop_time=gettime()
    output.write("\n\nPort Scanner (All Methods) ended at {}".format(all_methods_port_scanner_stop_time))
    output.write("\nTotal Scan Duration in Seconds = {}".format(abs(all_methods_port_scanner_stop_time-all_methods_port_scanner_start_time).total_seconds()))    
    output.close()

#End of Port Scanner

#Start of main Function

if __name__=="__main__":

    file=open(os.path.dirname(__file__)+"/../input.json", "r")
    json_data=json.load(file)
    feature=json_data["Method"]
    scan_ip=json_data["IP_Address"]
    drop_down=json_data["Drop_Down"]
    port=json_data["Port"]
    timeout=int(json_data["Time_Out"])
    verbose=int(json_data["Verbose"])
    
    # try:
    #     port=input("\nEnter the Port(s) to Scan: ")
    # except ValueError:
    #     print("\nNo Ports Entered...")
    #     sys.exit()
    # try:
    #     timeout=int(input("\nEnter the Timeout Duration (Default: 2): "))
    # except ValueError:
    #     timeout=2
    # try:
    #     verbose=int(input("\nEnter the Level of Verbosity [From 0 (almost mute) to 3 (verbose)] (Default: 0): "))
    # except ValueError:
    #     verbose=0
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
    
    # all_methods_port_scanner(ip, port_list, timeout)
    if feature=="Port Scanner":
        if drop_down=="TCP Connect Scan":
            tcp_connect_scan_port_scanner(scan_ip, port_list, timeout)
        elif drop_down=="TCP Stealth Scan":
            tcp_stealth_scan_port_scanner(scan_ip, port_list, timeout)
        elif drop_down=="TCP ACK Scan":
            tcp_ack_scan_port_scanner(scan_ip, port_list, timeout)
        elif drop_down=="TCP Window Scan":
            tcp_window_scan_port_scanner(scan_ip, port_list, timeout)
        elif drop_down=="XMAS Scan":
            xmas_scan_port_scanner(scan_ip, port_list, timeout)
        elif drop_down=="FIN Scan":
            fin_scan_port_scanner(scan_ip, port_list, timeout)
        elif drop_down=="NULL Scan":
            null_scan_port_scanner(scan_ip, port_list, timeout)
        elif drop_down=="UDP Scan":
            udp_scan_port_scanner(scan_ip, port_list, timeout)
        elif drop_down=="All":
            all_methods_port_scanner(scan_ip, port_list, timeout)
    
    sys.exit()

#End of main Function