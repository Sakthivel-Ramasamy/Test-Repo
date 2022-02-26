import datetime
import json
import os
from scapy.all import *

#Start of IP Spoofing Detection Scanner

def gettime():
    try:
        current_time=datetime.datetime.now()
    except Exception:
        current_time=datetime.now()
    return current_time

# Checks if the TTL is within the maximum threshold
def ip_spoof_ttl_checker(src, ttl):
    global ttl_values
    global ip_spoofing_detection_threshold
    if not src in ttl_values:
        icmp_pkt = sr1(IP(dst=src)/ICMP(), retry=0, verbose=0, timeout=1)
        ttl_values[src] = icmp_pkt.ttl
    if abs(int(ttl_values[src]) - int(ttl)) > ip_spoofing_detection_threshold:
        output=open(os.path.dirname(__file__)+"/../output.hop", "a")
        output.write("Timestamp: {}\nMessage: Detected Possible Spoofed Packet from the IP Address {}\n\n".format(gettime(), src))
        output.close()
        attack_output=open(os.path.dirname(__file__)+"/../error.hop", "w")
        attack_output.close()

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
    try:
        sniff(prn=ip_spoof_identifier, iface=interface, store=False)
    except Exception:
        interface=conf.iface
        sniff(prn=ip_spoof_identifier, iface=interface, store=False)

#End of IP Spoofing Detection Scanner

#Start of main Function

if __name__=="__main__":

    #Start of Color Code

    os_type=sys.platform
    if os_type=='win32':
        os.system('color')
    
    #End of Color Code

    interface=input("\nEnter the Interface of the Host (Default: eth0): ")
    if len(interface)==0:
        interface='eth0'
    ttl_values={}
    try:
        threshold=int(input("\nEnter the Threshold Value (Default: 5): "))
    except ValueError:
        threshold=5
    output=open(os.path.dirname(__file__)+"/../output.hop", "a")
    output.truncate(0)
    output.close()
    ip_spoof_detector(interface)

#End of main Function
