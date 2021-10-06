from getmac import get_mac_address
import nmap
import os
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

def exitprocess():
    sys.exit()

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
        ___ ___ ________ _________________________________________      ____.______________________
        /   |   \\_____  \\______   \______   \_   _____/\______   \    |    |\_   _____/\__    ___/
        /    ~    \/   |   \|     ___/|     ___/|    __)_  |       _/    |    | |    __)_   |    |   
        \    Y    /    |    \    |    |    |    |        \ |    |   \/\__|    | |        \  |    |   
        \___|_  /\_______  /____|    |____|   /_______  / |____|_  /\________|/_______  /  |____|   
            \/         \/                           \/         \/                   \/   
    """, "red", attrs=['bold']))
    print()
    print("*****************************************************************")
    print("*                                                               *")
    print("*             Copyright of Sakthivel Ramasamy, 2021             *")
    print("*                                                               *")
    print("*             https://github.com/Sakthivel-Ramasamy             *")
    print("*                                                               *")
    print("*****************************************************************")

    #End of Banner

    print("\nEnter 1 for Host Discovery\n      2 for Promiscuous Mode Detection\n      3 for ARP Spoofing Detection\n      4 for IP Spoof Detection\n")
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
        if (choice==1):
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
            if (choice==1):
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
    exitprocess()

#End of main Function
