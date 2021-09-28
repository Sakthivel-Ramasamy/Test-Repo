from scapy.all import *
import os
import sys
a=Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24")
result=srp(a,timeout=3,verbose=False)[0]
ipaddr=[]
for element in result:
    print(element[1].psrc + " " + element[1].hwsrc)
    ipaddr.append(element[1].psrc)
print()
print(ipaddr)

#print()
#print(result.summary())
#print("Number of hosts = {}/254".format(len(result)))
#print(result)

#print("\nIP Address     MAC Address")
#print(result.summary(lambda s,r: r.sprintf("%ARP.psrc% %Ether.src%")))
#print("\nTotal {} hosts are alive in the given subnet {}".format(len(result), network))