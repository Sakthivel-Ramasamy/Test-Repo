import datetime
import json
import os
from scapy.all import *
import sys

#Start of ARP Spoofing Detection Scanner

def arp_spoof_safe():
    arp_spoofing_detection_scanner_stop_time=datetime.now()
    output.write("ARP Spoofing Detection Scan started at {}".format(arp_spoofing_detection_scanner_start_time))
    output.write("\n\nTimestamp: {}\nMessage: You are safe".format(datetime.now()))
    output.write("\n\nARP Spoofing Detection Scanner ended at {}".format(arp_spoofing_detection_scanner_stop_time))
    output.write("\nTotal Scan Duration in Seconds = {}".format(abs(arp_spoofing_detection_scanner_stop_time-arp_spoofing_detection_scanner_start_time).total_seconds()))
    output.close()
    exit_process()

def arp_spoof_not_safe(a):
    arp_spoofing_detection_scanner_stop_time=datetime.now()
    output.write("ARP Spoofing Detection Scan started at {}".format(arp_spoofing_detection_scanner_start_time))
    output.write("\n\nTimestamp: {}\nMessage: You are under attack\nVictim's MAC Address: {}\nAttacker's MAC Address: {}".format(datetime.now(), a[0], a[1]))
    output.write("\n\nARP Spoofing Detection Scanner ended at {}".format(arp_spoofing_detection_scanner_stop_time))
    output.write("\nTotal Scan Duration in Seconds = {}".format(abs(arp_spoofing_detection_scanner_stop_time-arp_spoofing_detection_scanner_start_time).total_seconds()))
    output.close()
    attack_output=open("attack.hop", "w")
    attack_output.close()
    exit_process()

#function getting mac addrees by broadcasting the ARP msg packets 
def arp_spoof_mac_identifier(ip):
    p = Ether(dst="FF:FF:FF:FF:FF:FF")/ARP(pdst=ip) 
    result = srp(p, timeout=3, verbose=False)[0] 
    return result[0][1].hwsrc

#process for every packet received by sniff function 
def arp_spoof_identifier(packet):
    global arpcount, arp_spoofing_detection_scanner_start_time
    if packet.haslayer(ARP) and packet[ARP].op == 2: 
        a=[]	 
        try: 
            # get the real MAC address of the sender 
            real_mac = arp_spoof_mac_identifier(packet[ARP].psrc) 
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

    #Start of Color Code

    os_type=sys.platform
    if os_type=='win32':
        os.system('color')
    
    #End of Color Code

    interface=input("\nEnter the Interface of the Host (Default: eth0): ")
    if len(interface)==0:
        interface=conf.iface
    arpcount=0
    output=open(os.path.dirname(__file__)+"/../output.hop", "a")
    output.truncate(0)
    arp_spoofing_detection_scanner_start_time=datetime.now()
    arp_spoof_detector(interface) 

#End of main Function
