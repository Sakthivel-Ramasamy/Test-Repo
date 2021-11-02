import datetime
from scapy.all import *
import sys
from termcolor import colored

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
        interface=conf.iface
    dhcpcount=0
    dhcpdict={}
    dhcp_starvation_timeout=int(input("\nEnter the Timeout Duration in seconds: "))
    dhcp_starvation_threshold=int(input("\nEnter the DHCP DISCOVER Message Threshlod Value: "))
    starttime=datetime.now()
    dhcp_starvation_detector(interface)

#End of main Function
