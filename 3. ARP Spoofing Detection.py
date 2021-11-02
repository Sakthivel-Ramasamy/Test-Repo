from scapy.all import *
import sys
from termcolor import colored

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

#Start of Exit Process

def exit_process():
    sys.exit()

#End of Exit Process

#Start of main Function

if __name__=="__main__":
    os_type=sys.platform
    if os_type=='win32':
        os.system('color')
    interface=input("\nEnter the Interface of the Host (Default: eth0): ")
    if len(interface)==0:
        interface='eth0'
    arpcount=0
    arp_spoof_detector(interface) 

#End of main Function