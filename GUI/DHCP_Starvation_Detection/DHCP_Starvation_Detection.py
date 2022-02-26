import datetime
import json
import nmap
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
    global dhcp_starvation_detection_timeout
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

    file=open(os.path.dirname(__file__)+"/../input.json", "r")
    json_data=json.load(file)
    feature=json_data["Method"]
    scan_interface=json_data["Interface"]
    dhcp_starvation_detection_timeout=json_data["Timeout"]
    dhcp_starvation_detection_threshold=json_data["Threshold"]
    dhcpcount=0
    dhcpdict={}
    if feature=="DHCP Starvation":
        output=open(os.path.dirname(__file__)+"/../output.hop", "a")
        output.truncate(0)
        dhcp_starvation_detection_scanner_global_start_time=gettime()
        dhcp_starvation_detection_scanner_start_time=dhcp_starvation_detection_scanner_global_start_time
        output.write("DHCP Starvation Detection Scanner started at {}".format(dhcp_starvation_detection_scanner_global_start_time))
        output.close()
        dhcp_starvation_detector(scan_interface)
    sys.exit() 

#End of main Function