import argparse
import datetime
from getmac import get_mac_address
import nmap
import os
import prettytable
from scapy.all import *
import sys
from termcolor import colored

#Start of Host Discovery Scanner

def hostdiscoveryscannerusingnmap():
    ip=input("\nEnter the IP in CIDR Notation (Default: 192.168.1.0/24): ")
    if len(ip)==0:
        network='192.168.1.0/24'
    else:
        network=ip
    print("\nScanning Please Wait...")
    print("(Note: This may take some time)")
    nm=nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn')
    host_list=[(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    counthost=0
    print()
    for host, status in host_list:
        mac=get_mac_address(ip=host)
        print("IP Address: {} MAC Address: {}".format(host, mac))
        counthost+=1
    print("\nTotal {} hosts are alive in the given network {}".format(counthost, network))

def hostdiscoveryscannerusingscapy():
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
    for element in result:
        print("IP Address: {} MAC Address: {}".format(element[1].psrc, element[1].hwsrc))
        counthost+=1
    print("\nTotal {} hosts are alive in the given network {}".format(counthost, network))

#End of Host Discovery Scanner

#Start of Promiscuous Mode Detection Scanner

def pro_mac(ip):
    a=Ether(dst="FF:FF:FF:FF:FF:FE")/ARP(pdst=ip)
    result = srp(a,timeout=3,verbose=False)[0]
    return result[0][1].hwsrc

countpromiscuoushost=0
countnotpromiscuoushost=0
    
def pro_start(ip):
    global countpromiscuoushost
    global countnotpromiscuoushost
    try:
        result=pro_mac(ip)
        countpromiscuoushost+=1
        print(colored("The ip {}".format(ip) + " is in promiscuous mode", "white", "on_red", attrs=['bold']))
    except:
        countnotpromiscuoushost+=1
        print(colored("The ip {}".format(ip) + " is not in promiscuous mode", "white", "on_green", attrs=['bold']))        

def promiscuousdevicescannerusingnmap():
    ip=input("\nEnter the IP in CIDR Notation (Default: 192.168.1.0/24): ")
    if len(ip)==0:
        network='192.168.1.0/24'
    else:
        network=ip
    print("\nScanning Please Wait...")
    print("(Note: This may take some time)")
    nm=nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn')
    host_list=[(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    counthost=0
    global countpromiscuoushost
    global countnotpromiscuoushost
    countpromiscuoushost=0
    countnotpromiscuoushost=0
    for host, status in host_list:
        mac=get_mac_address(ip=host)
        print("\nIP Address: {} MAC Address: {}".format(host, mac))
        counthost+=1
        pro_start(host)
    print("\nTotal {} hosts are alive in the given network {}".format(counthost, network))
    print("Number of Hosts in Promisucous Mode = {}\nNumber of Hosts not in Promisucous Mode = {}".format(countpromiscuoushost, countnotpromiscuoushost))

def promiscuousdevicescannerusingscapy():
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
    global countpromiscuoushost
    global countnotpromiscuoushost
    countpromiscuoushost=0
    countnotpromiscuoushost=0
    for element in result:
        print("\nIP Address: {} MAC Address: {}".format(element[1].psrc, element[1].hwsrc))
        counthost+=1
        pro_start(element[1].psrc)
    print("\nTotal {} hosts are alive in the given network {}".format(counthost, network))
    print("Number of Hosts in Promisucous Mode = {}\nNumber of Hosts not in Promisucous Mode = {}".format(countpromiscuoushost, countnotpromiscuoushost))

#End of Promiscuous Mode Detection Scanner

#Start of ARP Spoofing Detection Scanner

#arpcount=0

def danger(a):
    print(colored(("\nYou are under attack REAL-MAC: "+str(a[0])+" FACE MAC:"+str(a[1])), "white", "on_red", attrs=['bold']))
    exitprocess()
    
#function if no spoofing is taking place 
def safe():
    print(colored("\nYou are safe", "white", "on_green", attrs=['bold']))
    exitprocess()

#function getting mac addrees by broadcasting the ARP msg packets 
def get_macarp(ip):
    p = Ether(dst="FF:FF:FF:FF:FF:FF")/ARP(pdst=ip) 
    result = srp(p, timeout=3, verbose=False)[0] 
    return result[0][1].hwsrc

#process for every packet received by sniff function 
def arpspoofdetectprocess(packet): 
    #print("process")
    # if the packet is an ARP packet 
    global arpcount
    if packet.haslayer(ARP) and packet[ARP].op == 2: 
        a=[]	 
        try: 
            # get the real MAC address of the sender 
            real_mac = get_macarp(packet[ARP].psrc) 
            #print(real_mac) 
            # get the MAC address from the packet sent to us 
            response_mac = packet[ARP].hwsrc 
            #print(response_mac) 
            # if they're different, definetely there is an attack 
            if real_mac != response_mac: 
                #print(f"[!] You are under attack, REAL-MAC: {real_mac.upper()}, FAKE-MAC: {response_mac.upper()}") 
                a.append(real_mac) 
                a.append(response_mac)  
                return danger(a) 
            else: 
                arpcount=arpcount+1 
            if arpcount == 40:
                arpcount=0
                return safe() 
        except IndexError:            	 
            # unable to find the real mac 
            # may be a fake IP or firewall is blocking packets 
            pass

def arpspoofcheck(interface):
    sniff(store=False,prn=arpspoofdetectprocess,iface=interface)

#End of ARP Spoofing Detection Scanner

#Start of IP Spoofing Detection Scanner

#ttl_values = {}
# Threshold for maximum difference in TTL values
#threshold=int(input("\nEnter the Threshold Value: "))

# Parses packets received and passes source IP 
def get_ttl(pkt):
	try:
		if pkt.haslayer(IP):
			src = pkt.getlayer(IP).src
			ttl = pkt.getlayer(IP).ttl
			check_ttl(src, ttl)
	except:
		pass

# Checks if the TTL is within the maximum threshold
def check_ttl(src, ttl):
    global ttl_values
    global threshold
    if not src in ttl_values:
		    icmp_pkt = sr1(IP(dst=src)/ICMP(), retry=0, verbose=0, timeout=1)
		    ttl_values[src] = icmp_pkt.ttl
    if abs(int(ttl_values[src]) - int(ttl)) > threshold:
        print(f"[!] Detected possible spoofed packet from [{src}]")
        print(f"[!] Received TTL: {ttl}, Actual TTL: {ttl_values[src]}")

# Sniffs traffic on the specified interface. 
# Grabs the src IP and TTL from the network traffic then compares the TTL with an ICMP echo reply. 
# If the difference in TTL is greater than THRESHOLD a warning will be printed.
def ipspoofcheck(interface):
	print(f"\n[*] Sniffing traffic on interface [{interface}]")
	sniff(prn=get_ttl, iface=interface, store=False)

#End of IP Spoofing Detection Scanner

#Start of DNS Spoofing Detection Scanner

def dnsDetect(packet):
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
            ipAdds = getIPsFromDNS(packet)
            ipAdds2= getIPsFromDNS(firstPacket)
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

def getIPsFromDNS(packet):
    ipAdds = []
    ancount = packet[DNS].ancount
    for index in range(ancount):
        ipAdds.append(packet[DNSRR][index].rdata)
    return ipAdds

def dnsspoofcheck(interface):
    argParser = argparse.ArgumentParser(add_help=False)
    argParser.add_argument('fExp', nargs='*', default=None)
    args = argParser.parse_args()
    filterExp = ''
    if args.fExp is None:
        filterExp = 'port 53'
    sniff(iface=interface, filter=filterExp, prn=dnsDetect)

#End of DNS Spoofing Detection Scanner

#Start of DHCP Starvation Detection Scanner

def handle_dhcp(packet):
    global dhcpcount, dhcpdict
    newtime = (str(datetime.now()).split(" ")[1])
    newmac = packet.src
    if DHCP in packet and packet[DHCP].options[0][1] == 1:  # DHCP DISCOVER PACKET
        dhcpcount += 1
        for time, mac in dhcpdict.items():
            if mac != newmac and dhcpcount > 1012:
                val = hand_washer(time, newtime, newmac)
                if val == 0:
                    exitprocess()
    dhcpdict[newtime] = newmac

def hand_washer(time, newtime, newmac):
    hour1 = time.split(":")[0]
    hour2 = newtime.split(":")[0]
    min1 = time.split(":")[1]
    min2 = newtime.split(":")[1]

    # If the time is the same I don't need to check the milliseconds
    # If the hour is the same but not the minutes and there are in range of 10 mins send the frame
    if (time == newtime) or ((hour1 == hour2) and (int(min2) - int(min1) in range(10))):
        send_frame(time, newtime, newmac)
        return 0    
    else:
        return 1

def send_frame(time, newtime, newmac):
    print(colored(("\nDHCP Count = "+ str(dhcpcount) + "\nWARNING: Possible DHCP Starvation Attack Detected"), "white", "on_red", attrs=['bold']))

def dhcpstarvationdetect(interface):
    sniff(iface=interface, filter='udp and (port 67 or port 68)', prn=handle_dhcp, store=0)

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
def tcp_connect_scan_port_scanner(ip, ports, timeout):
    outputtable = prettytable.PrettyTable(["Port", "TCP Connect Scan"])
    #outputtable.align["Port No."] = "l"
    
    print ("\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, ports))
    
    for i in ports:
        print("\nStarting TCP Connect Scan for {}:{}...".format(ip, i))
        tcp_connect_scan_res = tcp_connect_scan(ip,int(i),int(timeout))
        print("TCP Connect Scan Completed for {}:{}".format(ip, i))
        outputtable.add_row([i, tcp_connect_scan_res])
    print("\n[*] Scan Completed for the Target: {}\n\nTCP Connect Scan Result:".format(ip))
    print(outputtable)

def tcp_stealth_scan_port_scanner(ip, ports, timeout):
    outputtable = prettytable.PrettyTable(["Port", "TCP Stealth Scan"])
    #outputtable.align["Port No."] = "l"
    
    print ("\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, ports))
    
    for i in ports:
        print("\nStarting TCP Stealth Scan for {}:{}...".format(ip, i))
        tcp_stealth_scan_res = tcp_stealth_scan(ip,int(i),int(timeout))
        print("TCP Stealth Scan Completed for {}:{}".format(ip, i))
        outputtable.add_row([i, tcp_stealth_scan_res])
    print("\n[*] Scan Completed for the Target: {}\n\nTCP Stealth Scan Result:".format(ip))
    print(outputtable)

def tcp_ack_scan_port_scanner(ip, ports, timeout):
    outputtable = prettytable.PrettyTable(["Port", "TCP ACK Scan"])
    #outputtable.align["Port No."] = "l"
    
    print ("\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, ports))
    
    for i in ports:        
        print("\nStaring TCP ACK Scan for {}:{}...".format(ip, i))
        tcp_ack_flag_scan_res = tcp_ack_scan(ip,int(i),int(timeout))
        print("TCP ACK Scan Completed for {}:{}".format(ip, i))
        outputtable.add_row([i, tcp_ack_flag_scan_res])
    print("\n[*] Scan Completed for the Target: {}\n\nTCP ACK Scan Result:".format(ip))
    print(outputtable)

def tcp_window_scan_port_scanner(ip, ports, timeout):
    outputtable = prettytable.PrettyTable(["Port", "TCP Window Scan"])
    #outputtable.align["Port No."] = "l"
    
    print ("\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, ports))
    
    for i in ports:
        print("\nStarting TCP Window Scan for {}:{}...".format(ip, i))
        tcp_window_scan_res = tcp_window_scan(ip,int(i),int(timeout))
        print("TCP Window Scan Completed for {}:{}".format(ip, i))
        outputtable.add_row([i, tcp_window_scan_res])
    print("\n[*] Scan Completed for the Target: {}\n\nTCP Window Scan Result:".format(ip))
    print(outputtable)

def xmas_scan_port_scanner(ip, ports, timeout):
    outputtable = prettytable.PrettyTable(["Port", "XMAS Scan"])
    #outputtable.align["Port No."] = "l"
    
    print ("\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, ports))
    
    for i in ports:
        print("\nStarting XMAS Scan for {}:{}...".format(ip, i))
        xmas_scan_res = xmas_scan(ip,int(i),int(timeout))
        print("XMAS Scan Completed for {}:{}".format(ip, i))
        outputtable.add_row([i, xmas_scan_res])
    print("\n[*] Scan Completed for the Target: {}\n\nXMAS Scan Result:".format(ip))
    print(outputtable)

def fin_scan_port_scanner(ip, ports, timeout):
    outputtable = prettytable.PrettyTable(["Port", "FIN Scan"])
    #outputtable.align["Port No."] = "l"
    
    print ("\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, ports))
    
    for i in ports: 
        print("\nStarting FIN Scan for {}:{}...".format(ip, i))
        fin_scan_res = fin_scan(ip,int(i),int(timeout))
        print("FIN Scan Completed for {}:{}".format(ip, i))
        outputtable.add_row([i, fin_scan_res])
    print("\n[*] Scan Completed for the Target: {}\n\nFIN Scan Result:".format(ip))
    print(outputtable)

def null_scan_port_scanner(ip, ports, timeout):
    outputtable = prettytable.PrettyTable(["Port", "NULL Scan"])
    #outputtable.align["Port No."] = "l"
    
    print ("\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, ports))
    
    for i in ports:
        print("\nStarting NULL Scan for {}:{}...".format(ip, i))
        null_scan_res = null_scan(ip,int(i),int(timeout))
        print("NULL Scan Completed for {}:{}".format(ip, i))      
        outputtable.add_row([i, null_scan_res])
    print("\n[*] Scan Completed for the Target: {}\n\nNULL Scan Result:".format(ip))
    print(outputtable)

def udp_scan_port_scanner(ip, ports, timeout):
    outputtable = prettytable.PrettyTable(["Port", "UDP Scan"])
    #outputtable.align["Port No."] = "l"
    
    print ("\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, ports))
    
    for i in ports:
        print("\nStarting UDP Scan for {}:{}...".format(ip, i))
        udp_scan_res = udp_scan(ip,int(i),int(timeout))
        print("UDP Scan Completed for {}:{}".format(ip, i))
        outputtable.add_row([i, udp_scan_res])
    print("\n[*] Scan Completed for the Target: {}\n\nUDP Scan Result:".format(ip))
    print(outputtable)

def all_methods_port_scanner(ip, ports, timeout):
    outputtable = prettytable.PrettyTable(["Port", "TCP Connect Scan", "TCP Stealth Scan", "TCP ACK Scan", "TCP Window Scan", "XMAS Scan", "FIN Scan", "NULL Scan", "UDP Scan"])
    #outputtable.align["Port No."] = "l"
    
    print ("\n[+] Starting the Port Scanner for the Target: {} for the Port(s): {}...".format(ip, ports))
    
    for i in ports:        
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
        outputtable.add_row([i, tcp_connect_scan_res, tcp_stealth_scan_res, tcp_ack_flag_scan_res, tcp_window_scan_res, xmas_scan_res, fin_scan_res, null_scan_res, udp_scan_res])
    print("\n[*] Scan Completed for the Target: {}\n\nResult:".format(ip))
    print(outputtable)    

#End of Port Scanner

#Start of Exit Process

def exitprocess():
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
    print("*            Copyright of Sakthivel Ramasamy, Karthikeyan P, Yayady S 2021             *")
    print("*                                                                                      *")
    print("*                        https://github.com/Sakthivel-Ramasamy                         *")
    print("*                                                                                      *")
    print("****************************************************************************************")

    #End of Banner

    print("\nEnter 1 for Host Discovery\n      2 for Promiscuous Mode Detection\n      3 for ARP Spoofing Detection\n", end="")
    print("      4 for IP Spoof Detection\n      5 for DNS Spoofing Detection\n      6 for DHCP Starvation Detection\n", end="")
    print("      7 for OS Detection\n      8 for Port Scanner\n")
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
            hostdiscoveryscannerusingnmap()
        elif(choice==2):
            hostdiscoveryscannerusingscapy()
    elif(featureselection==2):
        print("\nEnter 1 for Individual IPScan\n      2 for Subnet Scan\n")
        print(colored("$ hopperjet(", "green", attrs=['bold']), end="")
        print(colored("menu->promiscuousmodedetection", "blue", attrs=['bold']), end="")
        print(colored(") >", "green", attrs=['bold']), end=" ")
        suboption=int(input())
        if(suboption==1):
            ip=input("\nEnter the Target IP Address (Default: 127.0.0.1): ")
            if len(ip)==0:
                ipaddress='127.0.0.1'
            else:
                ipaddress=ip
            pro_start(ipaddress)
        elif(suboption==2):
            print("\nEnter 1 to scan using Nmap (Speed of Scan: Moderate)\n      2 to scan using Scapy (Speed of Scan: Fast)\n")
            print(colored("$ hopperjet(", "green", attrs=['bold']), end="")
            print(colored("hopperjetmenu->promiscuousmodedetection->selectmethod", "blue", attrs=['bold']), end="")
            print(colored(") >", "green", attrs=['bold']), end=" ")
            choice=int(input())
            if(choice==1):
                promiscuousdevicescannerusingnmap()
            elif(choice==2):
                promiscuousdevicescannerusingscapy()
    elif(featureselection==3):
        interface=input("\nEnter the Interface of the Host (Default: eth0): ")
        if len(interface)==0:
            interface='eth0'
        arpcount=0
        arpspoofcheck(interface)
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
        ipspoofcheck(interface)
    elif(featureselection==5):
        interface=input("\nEnter the Interface of the Host (Default: eth0): ")
        if len(interface)==0:
            interface=conf.iface
        dnsMap={}
        dnsspoofcheck(interface)
    elif(featureselection==6):
        interface=input("\nEnter the Interface of the Host (Default: eth0): ")
        if len(interface)==0:
            interface=conf.iface
        dhcpcount=0
        dhcpdict={}
        dhcpstarvationdetect(interface)
    elif(featureselection==7):
        print("\nUpcoming...")
    elif(featureselection==8):
        ip=input("\nEnter the Target IP Address: ")
        port=input("\nEnter the Port(s) to Scan: ")        
        try:
            timeout=int(input("\nEnter the Timeout Duration (Default: 2): "))
        except ValueError:
            timeout=2
        try:
            verbose=int(input("\nEnter the Level of Verbosity [From 0 (almost mute) to 3 (verbose)] (Default: 0): "))
        except ValueError:
            verbose=0
        conf.verb=verbose
        ports=[]
        if "," in port:
            port=port.split(",")
            port.sort()
            ports+=port
        elif "-" in port:
            port=port.split("-")
            port.sort()
            portlow=int(port[0])
            porthigh=int(port[1])
            portrange=range(portlow, porthigh)
            ports+=portrange
        else:
            ports.append(port)
        ports = list(set(ports))
        new_ports=[]
        for item in ports:
                new_ports.append(int(item))
        ports = new_ports
        ports.sort()
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
            tcp_connect_scan_port_scanner(ip, ports, timeout)
        elif(portscannerchoice==2):
            tcp_stealth_scan_port_scanner(ip, ports, timeout)
        elif(portscannerchoice==3):
            tcp_ack_scan_port_scanner(ip, ports, timeout)
        elif(portscannerchoice==4):
            tcp_window_scan_port_scanner(ip, ports, timeout)
        elif(portscannerchoice==5):
            xmas_scan_port_scanner(ip, ports, timeout)
        elif(portscannerchoice==6):
            fin_scan_port_scanner(ip, ports, timeout)
        elif(portscannerchoice==7):
            null_scan_port_scanner(ip, ports, timeout)
        elif(portscannerchoice==8):
            udp_scan_port_scanner(ip, ports, timeout)
        elif(portscannerchoice==9):
            all_methods_port_scanner(ip, ports, timeout)
    exitprocess()

#End of main Function
