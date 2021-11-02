from scapy.all import *

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

#Start of main Function

if __name__=="__main__":
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

#End of main Function