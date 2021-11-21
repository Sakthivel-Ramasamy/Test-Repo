import argparse
import datetime
from scapy.all import *

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
        else:
            #get mac address from packet
            # Will have to check if this is correct
            macAddr2 = packet[Ether].src
            firstPacket = dnsMap[packet[DNS].id]
            ipAdds = dns_spoof_ip_identifier(packet)
            ipAdds2= dns_spoof_ip_identifier(firstPacket)
            #check if the MAC address is same. if not raise an alarm
            if macAddr2 != firstPacket[Ether].src:
                print("\nTimestamp: {}\nMessage: Possible DNS Poisoning Attempt Detected".format(datetime.now()))
                print("TXID "+str(packet[DNS].id)+" Request "+packet[DNS].qd.qname.decode('utf-8')[:-1])
                print("Attacker's IP Address: {}".format(str(ipAdds2)))
                print("Victim's IP Address: {}".format(str(ipAdds)))

def dns_spoof_detector(interface):
    argParser = argparse.ArgumentParser(add_help=False)
    argParser.add_argument('fExp', nargs='*', default=None)
    args = argParser.parse_args()
    filterExp = ''
    if args.fExp is None:
        filterExp = 'port 53'
    sniff(prn=dns_spoof_identifier, iface=interface, filter=filterExp)

#End of DNS Spoofing Detection Scanner

#Start of main Function

if __name__=="__main__":    
    interface=input("\nEnter the Interface of the Host (Default: eth0): ")
    if len(interface)==0:
        interface=conf.iface
    dnsMap={}
    dns_spoof_detector(interface)

#End of main Function
