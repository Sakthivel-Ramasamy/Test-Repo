import ipaddress
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
    tcp_connect_scan_port_scanner_start_time=datetime.now()
    print("\nTCP Connect Scan Port Scanner started at {}".format(tcp_connect_scan_port_scanner_start_time))
    tcp_connect_scan_port_scanner_output_table = prettytable.PrettyTable(["Port", "TCP Connect Scan"])    
    print ("\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, port_list))    
    for i in port_list:
        print("\nStarting TCP Connect Scan for {}:{}...".format(ip, i))
        tcp_connect_scan_res = tcp_connect_scan(ip,int(i),int(timeout))
        print("TCP Connect Scan Completed for {}:{}".format(ip, i))
        tcp_connect_scan_port_scanner_output_table.add_row([i, tcp_connect_scan_res])
    print("\n[*] Scan Completed for the Target: {}\n\nTCP Connect Scan Result:".format(ip))
    print(tcp_connect_scan_port_scanner_output_table)
    tcp_connect_scan_port_scanner_stop_time=datetime.now()
    print("\nTCP Connect Scan Port Scanner ended at {}".format(tcp_connect_scan_port_scanner_stop_time))
    print("Total Scan Duration in Seconds = {}".format(abs(tcp_connect_scan_port_scanner_stop_time-tcp_connect_scan_port_scanner_start_time).total_seconds()))

def tcp_stealth_scan_port_scanner(ip, port_list, timeout):
    tcp_stealth_scan_port_scanner_start_time=datetime.now()
    print("\nTCP Stealth Scan port Scanner started at {}".format(tcp_stealth_scan_port_scanner_start_time))
    tcp_stealth_scan_port_scanner_output_table = prettytable.PrettyTable(["Port", "TCP Stealth Scan"])
    print ("\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, port_list))
    for i in port_list:
        print("\nStarting TCP Stealth Scan for {}:{}...".format(ip, i))
        tcp_stealth_scan_res = tcp_stealth_scan(ip,int(i),int(timeout))
        print("TCP Stealth Scan Completed for {}:{}".format(ip, i))
        tcp_stealth_scan_port_scanner_output_table.add_row([i, tcp_stealth_scan_res])
    print("\n[*] Scan Completed for the Target: {}\n\nTCP Stealth Scan Result:".format(ip))
    print(tcp_stealth_scan_port_scanner_output_table)
    tcp_stealth_scan_port_scanner_stop_time=datetime.now()
    print("\nTCP Stealth Scan Port Scanner ended at {}".format(tcp_stealth_scan_port_scanner_stop_time))
    print("Total Scan Duration in Seconds = {}".format(abs(tcp_stealth_scan_port_scanner_stop_time-tcp_stealth_scan_port_scanner_start_time).total_seconds()))

def tcp_ack_scan_port_scanner(ip, port_list, timeout):
    tcp_ack_scan_port_scanner_start_time=datetime.now()
    print("\nTCP ACK Scan Port Scanner started at {}".format(tcp_ack_scan_port_scanner_start_time))
    tcp_ack_scan_port_scanner_output_table = prettytable.PrettyTable(["Port", "TCP ACK Scan"])
    print ("\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, port_list))    
    for i in port_list:        
        print("\nStaring TCP ACK Scan for {}:{}...".format(ip, i))
        tcp_ack_flag_scan_res = tcp_ack_scan(ip,int(i),int(timeout))
        print("TCP ACK Scan Completed for {}:{}".format(ip, i))
        tcp_ack_scan_port_scanner_output_table.add_row([i, tcp_ack_flag_scan_res])
    print("\n[*] Scan Completed for the Target: {}\n\nTCP ACK Scan Result:".format(ip))
    print(tcp_ack_scan_port_scanner_output_table)
    tcp_ack_scan_port_scanner_stop_time=datetime.now()
    print("\nTCP ACK Scan Port Scanner ended at {}".format(tcp_ack_scan_port_scanner_stop_time))
    print("Total Scan Duration in Seconds = {}".format(abs(tcp_ack_scan_port_scanner_stop_time-tcp_ack_scan_port_scanner_start_time).total_seconds()))

def tcp_window_scan_port_scanner(ip, port_list, timeout):
    tcp_window_scan_port_scanner_start_time=datetime.now()
    print("\nTCP Window Scan Port Scanner started at {}".format(tcp_window_scan_port_scanner_start_time))
    tcp_window_scan_port_scanner_output_table = prettytable.PrettyTable(["Port", "TCP Window Scan"])
    print ("\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, port_list))    
    for i in port_list:
        print("\nStarting TCP Window Scan for {}:{}...".format(ip, i))
        tcp_window_scan_res = tcp_window_scan(ip,int(i),int(timeout))
        print("TCP Window Scan Completed for {}:{}".format(ip, i))
        tcp_window_scan_port_scanner_output_table.add_row([i, tcp_window_scan_res])
    print("\n[*] Scan Completed for the Target: {}\n\nTCP Window Scan Result:".format(ip))
    print(tcp_window_scan_port_scanner_output_table)
    tcp_window_scan_port_scanner_stop_time=datetime.now()
    print("\nTCP Window Scan Port Scanner ended at {}".format(tcp_window_scan_port_scanner_stop_time))
    print("Total Scan Duration in Seconds = {}".format(abs(tcp_window_scan_port_scanner_stop_time-tcp_window_scan_port_scanner_start_time).total_seconds()))

def xmas_scan_port_scanner(ip, port_list, timeout):
    xmas_scan_port_scanner_start_time=datetime.now()
    print("\nXMAS Scan Port Scanner started at {}".format(xmas_scan_port_scanner_start_time))
    xmas_scan_port_scanner_output_table = prettytable.PrettyTable(["Port", "XMAS Scan"])
    print ("\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, port_list))    
    for i in port_list:
        print("\nStarting XMAS Scan for {}:{}...".format(ip, i))
        xmas_scan_res = xmas_scan(ip,int(i),int(timeout))
        print("XMAS Scan Completed for {}:{}".format(ip, i))
        xmas_scan_port_scanner_output_table.add_row([i, xmas_scan_res])
    print("\n[*] Scan Completed for the Target: {}\n\nXMAS Scan Result:".format(ip))
    print(xmas_scan_port_scanner_output_table)
    xmas_scan_port_scanner_stop_time=datetime.now()
    print("\nXMAS Scan Port Scanner ended at {}".format(xmas_scan_port_scanner_stop_time))
    print("Total Scan Duration in Seconds = {}".format(abs(xmas_scan_port_scanner_stop_time-xmas_scan_port_scanner_start_time).total_seconds()))

def fin_scan_port_scanner(ip, port_list, timeout):
    fin_scan_port_scanner_start_time=datetime.now()
    print("\nFIN Scan Port Scanner started at {}".format(fin_scan_port_scanner_start_time))
    fin_scan_port_scanner_output_table = prettytable.PrettyTable(["Port", "FIN Scan"])
    print ("\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, port_list))    
    for i in port_list: 
        print("\nStarting FIN Scan for {}:{}...".format(ip, i))
        fin_scan_res = fin_scan(ip,int(i),int(timeout))
        print("FIN Scan Completed for {}:{}".format(ip, i))
        fin_scan_port_scanner_output_table.add_row([i, fin_scan_res])
    print("\n[*] Scan Completed for the Target: {}\n\nFIN Scan Result:".format(ip))
    print(fin_scan_port_scanner_output_table)
    fin_scan_port_scanner_stop_time=datetime.now()
    print("\nFIN Scan Port Scanner ended at {}".format(fin_scan_port_scanner_stop_time))
    print("Total Scan Duration in Seconds = {}".format(abs(fin_scan_port_scanner_stop_time-fin_scan_port_scanner_start_time).total_seconds()))

def null_scan_port_scanner(ip, port_list, timeout):
    null_scan_port_scanner_start_time=datetime.now()
    print("\nNULL Scan Port Scanner started at {}".format(null_scan_port_scanner_start_time))
    null_scan_port_scanner_output_table = prettytable.PrettyTable(["Port", "NULL Scan"])
    print ("\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, port_list))    
    for i in port_list:
        print("\nStarting NULL Scan for {}:{}...".format(ip, i))
        null_scan_res = null_scan(ip,int(i),int(timeout))
        print("NULL Scan Completed for {}:{}".format(ip, i))      
        null_scan_port_scanner_output_table.add_row([i, null_scan_res])
    print("\n[*] Scan Completed for the Target: {}\n\nNULL Scan Result:".format(ip))
    print(null_scan_port_scanner_output_table)
    null_scan_port_scanner_stop_time=datetime.now()
    print("\nNULL Scan Port Scanner ended at {}".format(null_scan_port_scanner_stop_time))
    print("Total Scan Duration in Seconds = {}".format(abs(null_scan_port_scanner_stop_time-null_scan_port_scanner_start_time).total_seconds()))

def udp_scan_port_scanner(ip, port_list, timeout):
    udp_scan_port_scanner_start_time=datetime.now()
    print("\nUDP Scan Port Scanner started at {}".format(udp_scan_port_scanner_start_time))
    udp_scan_port_scanner_output_table = prettytable.PrettyTable(["Port", "UDP Scan"])
    print ("\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, port_list))    
    for i in port_list:
        print("\nStarting UDP Scan for {}:{}...".format(ip, i))
        udp_scan_res = udp_scan(ip,int(i),int(timeout))
        print("UDP Scan Completed for {}:{}".format(ip, i))
        udp_scan_port_scanner_output_table.add_row([i, udp_scan_res])
    print("\n[*] Scan Completed for the Target: {}\n\nUDP Scan Result:".format(ip))
    print(udp_scan_port_scanner_output_table)
    udp_scan_port_scanner_stop_time=datetime.now()
    print("\nUDP Scan Port Scanner ended at {}".format(udp_scan_port_scanner_stop_time))
    print("Total Scan Duration in Seconds = {}".format(abs(udp_scan_port_scanner_stop_time-udp_scan_port_scanner_start_time).total_seconds()))

def all_methods_port_scanner(ip, port_list, timeout):
    all_methods_port_scanner_start_time=datetime.now()
    print("\nPort Scanner (All Methods) started at {}".format(all_methods_port_scanner_start_time))
    all_methods_port_scanner_output_table = prettytable.PrettyTable(["Port", "TCP Connect Scan", "TCP Stealth Scan", "TCP ACK Scan", "TCP Window Scan", "XMAS Scan", "FIN Scan", "NULL Scan", "UDP Scan"])
    print ("\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, port_list))    
    for i in port_list:        
        print("\nStarting TCP Connect Scan for {}:{}...".format(ip, i))
        tcp_connect_scan_res = tcp_connect_scan(ip,int(i),int(timeout))
        print("TCP Connect Scan Completed for {}:{}".format(ip, i))
        print("\nStarting TCP Stealth Scan for {}:{}...".format(ip, i))
        tcp_stealth_scan_res = tcp_stealth_scan(ip,int(i),int(timeout))
        print("TCP Stealth Scan Completed for {}:{}".format(ip, i))
        print("\nStaring TCP ACK Scan for {}:{}...".format(ip, i))
        tcp_ack_flag_scan_res = tcp_ack_scan(ip,int(i),int(timeout))
        print("TCP ACK Scan Completed for {}:{}".format(ip, i))
        print("\nStarting TCP Window Scan for {}:{}...".format(ip, i))
        tcp_window_scan_res = tcp_window_scan(ip,int(i),int(timeout))
        print("TCP Window Scan Completed for {}:{}".format(ip, i))
        print("\nStarting XMAS Scan for {}:{}...".format(ip, i))
        xmas_scan_res = xmas_scan(ip,int(i),int(timeout))
        print("XMAS Scan Completed for {}:{}".format(ip, i))
        print("\nStarting FIN Scan for {}:{}...".format(ip, i))
        fin_scan_res = fin_scan(ip,int(i),int(timeout))
        print("FIN Scan Completed for {}:{}".format(ip, i))
        print("\nStarting NULL Scan for {}:{}...".format(ip, i))
        null_scan_res = null_scan(ip,int(i),int(timeout))
        print("NULL Scan Completed for {}:{}".format(ip, i))      
        print("\nStarting UDP Scan for {}:{}...".format(ip, i))
        udp_scan_res = udp_scan(ip,int(i),int(timeout))
        print("UDP Scan Completed for {}:{}".format(ip, i))
        all_methods_port_scanner_output_table.add_row([i, tcp_connect_scan_res, tcp_stealth_scan_res, tcp_ack_flag_scan_res, tcp_window_scan_res, xmas_scan_res, fin_scan_res, null_scan_res, udp_scan_res])
    print("\n[*] Scan Completed for the Target: {}\n\nPort Scanner (All Methods) Result:".format(ip))
    print(all_methods_port_scanner_output_table)
    all_methods_port_scanner_stop_time=datetime.now()
    print("\nPort Scanner (All Methods) ended at {}".format(all_methods_port_scanner_stop_time))
    print("Total Scan Duration in Seconds = {}".format(abs(all_methods_port_scanner_stop_time-all_methods_port_scanner_start_time).total_seconds()))    

#End of Port Scanner

#Start of Exit Process

def exit_process():
    sys.exit()

#End of Exit Process

#Start of main Function

if __name__=="__main__":
    os_type=sys.platform
    if os_type=='win32':
        os.system('color')    
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
    print("\nEnter 1 for TCP Connect Scan\n      2 for TCP Stealth Scan\n      3 for TCP ACK Scan\n      4 for TCP Window Scan", end="")
    print("\n      5 for XMAS Scan\n      6 for FIN Scan\n      7 for NULL Scan\n      8 for UDP Scan\n      9 for All of the Above Scans (Default Option)\n")
    print(colored("$ hopperjet(", "green", attrs=['bold']), end="")
    print(colored("hopperjetmenu->portscanner->selectmethod", "blue", attrs=['bold']), end="")
    print(colored(") >", "green", attrs=['bold']), end=" ")
    try:
        portscannerchoice=int(input())
    except ValueError:
        portscannerchoice=9
    if(portscannerchoice==1):
        tcp_connect_scan_port_scanner(ip, port_list, timeout)
    elif(portscannerchoice==2):
        tcp_stealth_scan_port_scanner(ip, port_list, timeout)
    elif(portscannerchoice==3):
        tcp_ack_scan_port_scanner(ip, port_list, timeout)
    elif(portscannerchoice==4):
        tcp_window_scan_port_scanner(ip, port_list, timeout)
    elif(portscannerchoice==5):
        xmas_scan_port_scanner(ip, port_list, timeout)
    elif(portscannerchoice==6):
        fin_scan_port_scanner(ip, port_list, timeout)
    elif(portscannerchoice==7):
        null_scan_port_scanner(ip, port_list, timeout)
    elif(portscannerchoice==8):
        udp_scan_port_scanner(ip, port_list, timeout)
    elif(portscannerchoice==9):
        all_methods_port_scanner(ip, port_list, timeout)

#End of main Function
