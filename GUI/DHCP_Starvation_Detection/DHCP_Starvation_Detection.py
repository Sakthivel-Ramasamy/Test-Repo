import datetime
import json
import os
from scapy.all import *
import sys

#Start of DHCP Starvation Detection Scanner

def gettime():
    try:
        current_time=datetime.datetime.now()
    except Exception:
        current_time=datetime.now()
    return current_time

def dhcp_starvation_time_checker(time, newtime):
    global dhcp_starvation_timeout
    hour1 = time.split(":")[0]
    hour2 = newtime.split(":")[0]
    min1 = time.split(":")[1]
    min2 = newtime.split(":")[1]

    # If the time is the same I don't need to check the milliseconds
    # If the hour is the same but not the minutes and there are in range of 10 mins send the frame
    if (time == newtime) or ((hour1 == hour2) and (int(min2) - int(min1) in range(dhcp_starvation_detection_timeout))):
        output=open(os.path.dirname(__file__)+"/../output.hop", "a")
        output.write("\n\nDHCP Count = {}\nTimestamp: {}\nMessage: Possible DHCP Starvation Attack Detected".format(dhcpcount, gettime()))
        output.close()
        attack_output=open(os.path.dirname(__file__)+"/../error.hop", "w")
        attack_output.close()
        return 1
    else:
        return 0

def dhcp_starvation_identifier(packet):
    global dhcpcount, dhcpdict, dhcp_starvation_detection_timeout, dhcp_starvation_detection_threshold, dhcp_starvation_detection_scanner_global_start_time, dhcp_starvation_detection_scanner_start_time
    newtime = (str(gettime()).split(" ")[1])
    newmac = packet.src
    if DHCP in packet and packet[DHCP].options[0][1] == 1:  # DHCP DISCOVER PACKET
        dhcpcount += 1
        for time, mac in dhcpdict.items():
            if mac != newmac and dhcpcount > dhcp_starvation_detection_threshold:
                val = dhcp_starvation_time_checker(time, newtime)
                if val == 1:
                    dhcpcount=0
                    #dhcp_starvation_detection_scanner_start_time=gettime()
                    dhcp_starvation_detection_scanner_global_stop_time=gettime()
                    output=open(os.path.dirname(__file__)+"/../output.hop", "a")
                    output.write("\n\nDHCP Starvation Detection Scanner ended at {}".format(dhcp_starvation_detection_scanner_global_stop_time))
                    output.write("\nTotal Scan Duration in Seconds = {}".format(abs(dhcp_starvation_detection_scanner_global_stop_time-dhcp_starvation_detection_scanner_global_start_time).total_seconds()))
                    output.close()
                    exit_process()
    dhcpdict[newtime] = newmac
    dhcp_starvation_detection_scanner_stop_time=gettime()
    if(abs(dhcp_starvation_detection_scanner_stop_time-dhcp_starvation_detection_scanner_start_time).total_seconds()>=dhcp_starvation_detection_timeout):
        dhcpcount=0
        dhcp_starvation_detection_scanner_start_time=gettime()

def dhcp_starvation_detector(interface):
    try:
        sniff( prn=dhcp_starvation_identifier, iface=interface, filter='udp and (port 67 or port 68)', store=0)
    except Exception:
        interface=conf.iface
        sniff( prn=dhcp_starvation_identifier, iface=interface, filter='udp and (port 67 or port 68)', store=0)

#End of DHCP Starvation Detection Scanner

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
    dhcpcount=0
    dhcpdict={}
    dhcp_starvation_detection_timeout=int(input("\nEnter the Timeout Duration in seconds: "))
    dhcp_starvation_detection_threshold=int(input("\nEnter the DHCP DISCOVER Message Threshlod Value: "))
    output=open(os.path.dirname(__file__)+"/../output.hop", "a")
    output.truncate(0)
    dhcp_starvation_detection_scanner_global_start_time=gettime()
    dhcp_starvation_detection_scanner_start_time=dhcp_starvation_detection_scanner_global_start_time
    output.write("DHCP Starvation Detection Scanner started at {}".format(dhcp_starvation_detection_scanner_global_start_time))
    output.close()
    dhcp_starvation_detector(interface)

#End of main Function
