import argparse
import datetime
import ipaddress
import nmap
import os
import prettytable
from scapy.all import *
import sys
from termcolor import colored

#Start of Host Discovery Scanner

def host_discovery_scanner_using_nmap():
    ip=input("\nEnter the IP in CIDR Notation (Default: 192.168.1.0/24): ")
    if len(ip)==0:
        network='192.168.1.0/24'
    else:
        network=ip
    print("\nScanning Please Wait...")
    print("(Note: This may take some time)")
    counthost=0
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

def host_discovery_scanner_using_scapy():
    ip=input("\nEnter the IP in CIDR Notation (Default: 192.168.1.0/24): ")
    if len(ip)==0:
        network='192.168.1.0/24'
    else:
        network=ip
    print("\nScanning Please Wait...")
    print("(Note: This may take negligible time)")
    a=Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24")
    result=srp(a,timeout=3,verbose=False)[0]
    counthost=0
    print()
    host_discovery_using_scapy_output_table = prettytable.PrettyTable(["Number", "IP Address", "MAC Address", "Vendor"])
    for element in result:
        #print("IP Address: {} MAC Address: {}".format(element[1].psrc, element[1].hwsrc))
        counthost+=1
        macaddress=element[1].hwsrc
        macaddress=macaddress.replace(":", "").replace("-", "").replace(".","").upper()
        macaddress_file_contents=open("nmap-mac-prefixes", "r").read()
        for macaddr in macaddress_file_contents.split("\n"):
            if macaddr[0:6] == macaddress[0:6]:
                vendor=macaddr[7:].strip()
                break
        host_discovery_using_scapy_output_table.add_row([counthost, element[1].psrc, element[1].hwsrc, vendor])
    print("\nHost Discovery Using Scapy Result:")
    print(host_discovery_using_scapy_output_table)
    print("\nTotal {} hosts are alive in the given network {}".format(counthost, network))

#End of Host Discovery Scanner

#Start of Promiscuous Mode Detection Scanner

def promiscuous_response_identifier(ip):
    a=Ether(dst="FF:FF:FF:FF:FF:FE")/ARP(pdst=ip)
    result = srp(a,timeout=3,verbose=False)[0]
    return result[0][1].hwsrc
    
def promiscuous_device_scanner_using_ip_address(ip):
    counthost=1
    global countpromiscuoushost
    global countnotpromiscuoushost
    promiscuous_mode_detection_using_ip_address_output_table = prettytable.PrettyTable(["Number", "IP Address", "MAC Address", "Status"])
    macaddress="NA"
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

def promiscuous_devices_scanner_using_nmap(network):
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

def promiscuous_devices_scanner_using_scapy(network):
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

#End of Promiscuous Mode Detection Scanner

#Start of ARP Spoofing Detection Scanner

#arpcount=0

#function if no spoofing is taking place 
def arp_spoof_safe():
    print(colored("\nYou are safe", "white", "on_green", attrs=['bold']))
    exit_process()

def arp_spoof_not_safe(a):
    print(colored(("\nYou are under attack REAL-MAC: "+str(a[0])+" FACE MAC:"+str(a[1])), "white", "on_red", attrs=['bold']))
    exit_process()

#function getting mac addrees by broadcasting the ARP msg packets 
def arp_sppof_mac_identifier(ip):
    p = Ether(dst="FF:FF:FF:FF:FF:FF")/ARP(pdst=ip) 
    result = srp(p, timeout=3, verbose=False)[0] 
    return result[0][1].hwsrc

#process for every packet received by sniff function 
def arp_spoof_identifier(packet): 
    #print("process")
    # if the packet is an ARP packet 
    global arpcount
    if packet.haslayer(ARP) and packet[ARP].op == 2: 
        a=[]	 
        try: 
            # get the real MAC address of the sender 
            real_mac = arp_sppof_mac_identifier(packet[ARP].psrc) 
            #print(real_mac) 
            # get the MAC address from the packet sent to us 
            response_mac = packet[ARP].hwsrc 
            #print(response_mac) 
            # if they're different, definetely there is an attack 
            if real_mac != response_mac: 
                #print(f"[!] You are under attack, REAL-MAC: {real_mac.upper()}, FAKE-MAC: {response_mac.upper()}") 
                a.append(real_mac) 
                a.append(response_mac)  
                return arp_spoof_not_safe(a) 
            else: 
                arpcount=arpcount+1 
            if arpcount == 40:
                arpcount=0
                return arp_spoof_safe() 
        except IndexError:            	 
            # unable to find the real mac 
            # may be a fake IP or firewall is blocking packets 
            pass

def arp_spoof_detector(interface):
    sniff(prn=arp_spoof_identifier, iface=interface, store=False)

#End of ARP Spoofing Detection Scanner

#Start of IP Spoofing Detection Scanner

#ttl_values = {}
# Threshold for maximum difference in TTL values
#threshold=int(input("\nEnter the Threshold Value: "))

# Checks if the TTL is within the maximum threshold
def ip_spoof_ttl_checker(src, ttl):
    global ttl_values
    global threshold
    if not src in ttl_values:
		    icmp_pkt = sr1(IP(dst=src)/ICMP(), retry=0, verbose=0, timeout=1)
		    ttl_values[src] = icmp_pkt.ttl
    if abs(int(ttl_values[src]) - int(ttl)) > threshold:
        print(f"[!] Detected possible spoofed packet from [{src}]")
        print(f"[!] Received TTL: {ttl}, Actual TTL: {ttl_values[src]}")

# Parses packets received and passes source IP 
def ip_spoof_identifier(pkt):
	try:
		if pkt.haslayer(IP):
			src = pkt.getlayer(IP).src
			ttl = pkt.getlayer(IP).ttl
			ip_spoof_ttl_checker(src, ttl)
	except:
		pass

# Sniffs traffic on the specified interface. 
# Grabs the src IP and TTL from the network traffic then compares the TTL with an ICMP echo reply. 
# If the difference in TTL is greater than THRESHOLD a warning will be printed.
def ip_spoof_detector(interface):
	print(f"\n[*] Sniffing traffic on interface [{interface}]")
	sniff(prn=ip_spoof_identifier, iface=interface, store=False)

#End of IP Spoofing Detection Scanner

#Start of DNS Spoofing Detection Scanner

def dns_spoof_ip_identifier(packet):
    ipAdds = []
    ancount = packet[DNS].ancount
    for index in range(ancount):
        ipAdds.append(packet[DNSRR][index].rdata)
    return ipAdds

def dns_spoof_identifier(packet):
    if DNS in packet and packet[DNS].qr == 1 and packet[DNS].ancount >= 1:
        global dnsMap
        if packet[DNS].id not in dnsMap:
            dnsMap[packet[DNS].id]=packet
            #print('Packet added to Map')
        else:
            #get mac address from packet
            # Will have to check if this is correct
            macAddr2 = packet[Ether].src
            firstPacket = dnsMap[packet[DNS].id]
            ipAdds = dns_spoof_ip_identifier(packet)
            ipAdds2= dns_spoof_ip_identifier(firstPacket)
            #check if the MAC address is same. if not raise an alarm
            if macAddr2 != firstPacket[Ether].src:
                print()                
                print(str(datetime.now())+' DNS poisoning attempt')
                print('TXID '+str(packet[DNS].id)+' Request '+packet[DNS].qd.qname.decode('utf-8')[:-1])
                #Doubtful about this stmt
                print('Answer 1 ',str(ipAdds2))
                print('Answer 2 ',str(ipAdds))
                print()
            #else:
                #print('False positives')
                #print('TXID '+str(packet[DNS].id)+' Request '+packet[DNS].qd.qname.decode('utf-8')[:-1])
                #Doubtful about this stmt
                #print('Answer 1 ',str(ipAdds2))
                #print('Answer 2 ',str(ipAdds))

def dns_spoof_detector(interface):
    argParser = argparse.ArgumentParser(add_help=False)
    argParser.add_argument('fExp', nargs='*', default=None)
    args = argParser.parse_args()
    filterExp = ''
    if args.fExp is None:
        filterExp = 'port 53'
    sniff(prn=dns_spoof_identifier, iface=interface, filter=filterExp)

#End of DNS Spoofing Detection Scanner

#Start of DHCP Starvation Detection Scanner

def dhcp_starvation_time_checker(time, newtime):
    global dhcp_starvation_timeout
    hour1 = time.split(":")[0]
    hour2 = newtime.split(":")[0]
    min1 = time.split(":")[1]
    min2 = newtime.split(":")[1]

    # If the time is the same I don't need to check the milliseconds
    # If the hour is the same but not the minutes and there are in range of 10 mins send the frame
    if (time == newtime) or ((hour1 == hour2) and (int(min2) - int(min1) in range(dhcp_starvation_timeout))):
        print(colored(("\nDHCP Count = "+ str(dhcpcount) + "\nWARNING: Possible DHCP Starvation Attack Detected"), "white", "on_red", attrs=['bold']))
        return 0    
    else:
        return 1

def dhcp_starvation_identifier(packet):
    global dhcpcount, dhcpdict, dhcp_starvation_timeout, dhcp_starvation_threshold, starttime
    newtime = (str(datetime.now()).split(" ")[1])
    newmac = packet.src
    if DHCP in packet and packet[DHCP].options[0][1] == 1:  # DHCP DISCOVER PACKET
        dhcpcount += 1
        for time, mac in dhcpdict.items():
            if mac != newmac and dhcpcount > dhcp_starvation_threshold:
                val = dhcp_starvation_time_checker(time, newtime)
                if val == 0:
                    dhcpcount=0
                    starttime=datetime.now()
                    exit_process()
    dhcpdict[newtime] = newmac
    stoptime=datetime.now()
    if(abs(stoptime-starttime).total_seconds()>=dhcp_starvation_timeout):
        dhcpcount=0
        starttime=stoptime

def dhcp_starvation_detector(interface):
    sniff( prn=dhcp_starvation_identifier, iface=interface, filter='udp and (port 67 or port 68)', store=0)

#End of DHCP Starvation Detection Scanner

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
    tcp_connect_scan_port_scanner_output_table = prettytable.PrettyTable(["Port", "TCP Connect Scan"])
    #outputtable.align["Port No."] = "l"
    
    print ("\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, port_list))
    
    for i in port_list:
        print("\nStarting TCP Connect Scan for {}:{}...".format(ip, i))
        tcp_connect_scan_res = tcp_connect_scan(ip,int(i),int(timeout))
        print("TCP Connect Scan Completed for {}:{}".format(ip, i))
        tcp_connect_scan_port_scanner_output_table.add_row([i, tcp_connect_scan_res])
    print("\n[*] Scan Completed for the Target: {}\n\nTCP Connect Scan Result:".format(ip))
    print(tcp_connect_scan_port_scanner_output_table)

def tcp_stealth_scan_port_scanner(ip, port_list, timeout):
    tcp_stealth_scan_port_scanner_output_table = prettytable.PrettyTable(["Port", "TCP Stealth Scan"])
    #outputtable.align["Port No."] = "l"
    
    print ("\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, port_list))
    
    for i in port_list:
        print("\nStarting TCP Stealth Scan for {}:{}...".format(ip, i))
        tcp_stealth_scan_res = tcp_stealth_scan(ip,int(i),int(timeout))
        print("TCP Stealth Scan Completed for {}:{}".format(ip, i))
        tcp_stealth_scan_port_scanner_output_table.add_row([i, tcp_stealth_scan_res])
    print("\n[*] Scan Completed for the Target: {}\n\nTCP Stealth Scan Result:".format(ip))
    print(tcp_stealth_scan_port_scanner_output_table)

def tcp_ack_scan_port_scanner(ip, port_list, timeout):
    tcp_ack_scan_port_scanner_output_table = prettytable.PrettyTable(["Port", "TCP ACK Scan"])
    #outputtable.align["Port No."] = "l"
    
    print ("\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, port_list))
    
    for i in port_list:        
        print("\nStaring TCP ACK Scan for {}:{}...".format(ip, i))
        tcp_ack_flag_scan_res = tcp_ack_scan(ip,int(i),int(timeout))
        print("TCP ACK Scan Completed for {}:{}".format(ip, i))
        tcp_ack_scan_port_scanner_output_table.add_row([i, tcp_ack_flag_scan_res])
    print("\n[*] Scan Completed for the Target: {}\n\nTCP ACK Scan Result:".format(ip))
    print(tcp_ack_scan_port_scanner_output_table)

def tcp_window_scan_port_scanner(ip, port_list, timeout):
    tcp_window_scan_port_scanner_output_table = prettytable.PrettyTable(["Port", "TCP Window Scan"])
    #outputtable.align["Port No."] = "l"
    
    print ("\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, port_list))
    
    for i in port_list:
        print("\nStarting TCP Window Scan for {}:{}...".format(ip, i))
        tcp_window_scan_res = tcp_window_scan(ip,int(i),int(timeout))
        print("TCP Window Scan Completed for {}:{}".format(ip, i))
        tcp_window_scan_port_scanner_output_table.add_row([i, tcp_window_scan_res])
    print("\n[*] Scan Completed for the Target: {}\n\nTCP Window Scan Result:".format(ip))
    print(tcp_window_scan_port_scanner_output_table)

def xmas_scan_port_scanner(ip, port_list, timeout):
    xmas_scan_port_scanner_output_table = prettytable.PrettyTable(["Port", "XMAS Scan"])
    #outputtable.align["Port No."] = "l"
    
    print ("\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, port_list))
    
    for i in port_list:
        print("\nStarting XMAS Scan for {}:{}...".format(ip, i))
        xmas_scan_res = xmas_scan(ip,int(i),int(timeout))
        print("XMAS Scan Completed for {}:{}".format(ip, i))
        xmas_scan_port_scanner_output_table.add_row([i, xmas_scan_res])
    print("\n[*] Scan Completed for the Target: {}\n\nXMAS Scan Result:".format(ip))
    print(xmas_scan_port_scanner_output_table)

def fin_scan_port_scanner(ip, port_list, timeout):
    fin_scan_port_scanner_output_table = prettytable.PrettyTable(["Port", "FIN Scan"])
    #outputtable.align["Port No."] = "l"
    
    print ("\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, port_list))
    
    for i in port_list: 
        print("\nStarting FIN Scan for {}:{}...".format(ip, i))
        fin_scan_res = fin_scan(ip,int(i),int(timeout))
        print("FIN Scan Completed for {}:{}".format(ip, i))
        fin_scan_port_scanner_output_table.add_row([i, fin_scan_res])
    print("\n[*] Scan Completed for the Target: {}\n\nFIN Scan Result:".format(ip))
    print(fin_scan_port_scanner_output_table)

def null_scan_port_scanner(ip, port_list, timeout):
    null_scan_port_scanner_output_table = prettytable.PrettyTable(["Port", "NULL Scan"])
    #outputtable.align["Port No."] = "l"
    
    print ("\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, port_list))
    
    for i in port_list:
        print("\nStarting NULL Scan for {}:{}...".format(ip, i))
        null_scan_res = null_scan(ip,int(i),int(timeout))
        print("NULL Scan Completed for {}:{}".format(ip, i))      
        null_scan_port_scanner_output_table.add_row([i, null_scan_res])
    print("\n[*] Scan Completed for the Target: {}\n\nNULL Scan Result:".format(ip))
    print(null_scan_port_scanner_output_table)

def udp_scan_port_scanner(ip, port_list, timeout):
    udp_scan_port_scanner_output_table = prettytable.PrettyTable(["Port", "UDP Scan"])
    #outputtable.align["Port No."] = "l"
    
    print ("\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, port_list))
    
    for i in port_list:
        print("\nStarting UDP Scan for {}:{}...".format(ip, i))
        udp_scan_res = udp_scan(ip,int(i),int(timeout))
        print("UDP Scan Completed for {}:{}".format(ip, i))
        udp_scan_port_scanner_output_table.add_row([i, udp_scan_res])
    print("\n[*] Scan Completed for the Target: {}\n\nUDP Scan Result:".format(ip))
    print(udp_scan_port_scanner_output_table)

def all_methods_port_scanner(ip, port_list, timeout):
    all_methods_port_scanner_output_table = prettytable.PrettyTable(["Port", "TCP Connect Scan", "TCP Stealth Scan", "TCP ACK Scan", "TCP Window Scan", "XMAS Scan", "FIN Scan", "NULL Scan", "UDP Scan"])
    #outputtable.align["Port No."] = "l"
    
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
    print("\n[*] Scan Completed for the Target: {}\n\nResult:".format(ip))
    print(all_methods_port_scanner_output_table)    

#End of Port Scanner

#Start of OS Detection Scanner

def os_detector(ip):
    try:
        nm=nmap.PortScanner()
        os_scan_values=nm.scan(ip, arguments='-O')['scan'][ip]['osmatch']
        counthost=1
        os_detection_output_table = prettytable.PrettyTable(["Number", "IP Address", "OS Vendor", "OS Family", "OS Generation", "OS Details", "OS Common Platform Enumeration (CPE) Details"])
        os_vendor=os_scan_values[0]['osclass'][0]['vendor']
        os_family=os_scan_values[0]['osclass'][0]['osfamily']
        os_generation=""
        for i in range(len(os_scan_values[0]['osclass'])-1):
            os_generation+=str(os_scan_values[0]['osclass'][i]['osgen']) + " | "
        os_generation+=str(os_scan_values[0]['osclass'][len(os_scan_values[0]['osclass'])-1]['osgen'])
        os_details=os_scan_values[0]['name']
        os_cpe=""
        for i in range(len(os_scan_values[0]['osclass'])-1):
            os_cpe+=str(os_scan_values[0]['osclass'][i]['cpe']) + " | "
        os_cpe+=str(os_scan_values[0]['osclass'][len(os_scan_values[0]['osclass'])-1]['cpe'])
        os_detection_output_table.add_row([counthost, ip, os_vendor, os_family, os_generation, os_details, os_cpe])
        print("\nOS Detection Results:")
        print(os_detection_output_table)
    except IndexError:
        print("\nSome Error Occurred...\Either the Target IP Address is filtering the connections or Not able to handle the response...\nPlease try again later...")
        exit_process()
    except KeyError:
        print("\nSome Error Occurred...\nEither the Target IP Address is not active or Not able to reach the Target IP Address.\nPlease try again later...")
        exit_process()

#End of OS Detection Scanner

#Start of Exit Process

def exit_process():
    sys.exit()

#End of Exit Process

#Start of main Function
    
if __name__=="__main__":
    os.system('color')

    #Start of Banner
    
    print(colored("""
       ██╗  ██╗ ██████╗ ██████╗ ██████╗ ███████╗██████╗      ██╗███████╗████████╗
       ██║  ██║██╔═══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗     ██║██╔════╝╚══██╔══╝
       ███████║██║   ██║██████╔╝██████╔╝█████╗  ██████╔╝     ██║█████╗     ██║   
       ██╔══██║██║   ██║██╔═══╝ ██╔═══╝ ██╔══╝  ██╔══██╗██   ██║██╔══╝     ██║   
       ██║  ██║╚██████╔╝██║     ██║     ███████╗██║  ██║╚█████╔╝███████╗   ██║   
       ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝ ╚════╝ ╚══════╝   ╚═╝
    """, "red", attrs=['bold']))
    print()
    print("****************************************************************************************")
    print("*                                                                                      *")
    print("*            Copyright of Sakthivel Ramasamy, Karthikeyan P, Yayady S                  *")
    print("*                                                                                      *")
    print("*                        https://github.com/Sakthivel-Ramasamy                         *")
    print("*                                  © 2021                                              *")
    print("****************************************************************************************")

    #End of Banner

    print("\nEnter 1\n for Host Discovery\n      2 for Promiscuous Mode Detection\n      3 for ARP Spoofing Detection\n", end="")
    print("      4 for IP Spoof Detection\n      5 for DNS Spoofing Detection\n      6 for DHCP Starvation Detection\n", end="")
    print("      7 for Port Scanner\n      8 for OS Detection\n")
    print(colored("$ hopperjet(", "green", attrs=['bold']), end="")
    print(colored("menu", "blue", attrs=['bold']), end="")
    print(colored(") >", "green", attrs=['bold']), end=" ")
    featureselection=int(input())
    if(featureselection==1):
        print("\nEnter 1 to scan using Nmap (Speed of Scan: Moderate)\n      2 to scan using Scapy (Speed of Scan: Fast)\n")
        print(colored("$ hopperjet(", "green", attrs=['bold']), end="")
        print(colored("menu->hostdiscovery", "blue", attrs=['bold']), end="")
        print(colored(") >", "green", attrs=['bold']), end=" ")
        choice=int(input())
        if(choice==1):
            host_discovery_scanner_using_nmap()
        elif(choice==2):
            host_discovery_scanner_using_scapy()
    elif(featureselection==2):
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
    elif(featureselection==3):
        interface=input("\nEnter the Interface of the Host (Default: eth0): ")
        if len(interface)==0:
            interface='eth0'
        arpcount=0
        arp_spoof_detector(interface)
    elif(featureselection==4):
        interface=input("\nEnter the Interface of the Host (Default: eth0): ")
        if len(interface)==0:
            interface='eth0'
        ttl_values={}
        try:
            threshold=int(input("\nEnter the Threshold Value (Default: 5): "))
        except ValueError:
            threshold=5
        print("\nWarning: This may slow down your system and it may not respond as expected...")
        ip_spoof_detector(interface)
    elif(featureselection==5):
        interface=input("\nEnter the Interface of the Host (Default: eth0): ")
        if len(interface)==0:
            interface=conf.iface
        dnsMap={}
        dns_spoof_detector(interface)
    elif(featureselection==6):
        interface=input("\nEnter the Interface of the Host (Default: eth0): ")
        if len(interface)==0:
            interface=conf.iface
        dhcpcount=0
        dhcpdict={}
        dhcp_starvation_timeout=int(input("\nEnter the Timeout Duration in seconds: "))
        dhcp_starvation_threshold=int(input("\nEnter the DHCP DISCOVER Message Threshlod Value: "))
        starttime=datetime.now()
        dhcp_starvation_detector(interface)
    elif(featureselection==7):
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
        print("\n
	1 for TCP Connect Scan\n      2 for TCP Stealth Scan\n      3 for TCP ACK Scan\n      4 for TCP Window Scan", end="")
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
    elif(featureselection==8):
        try:
            ipaddr=input("\nEnter the Target IP Address (Default: 127.0.0.1): ")
            if len(ipaddr)==0:
                ip='127.0.0.1'
            else:
                ip=ipaddr
            ipaddress.ip_address(ip)
            os_detector(ip)
        except ValueError:
            print("\nInvalid IP Address Entered...")
            exit_process()
    exit_process()

#End of main Function
