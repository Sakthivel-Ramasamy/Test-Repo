import ipaddress
import nmap
import prettytable
from scapy.all import *
import sys

#Start of OS Detection Scanner

def os_detector(ip):
    os_detection_scanner_start_time=datetime.now()
    print("\nOS Detection Scanner started at {}".format(os_detection_scanner_start_time))
    try:
        nm=nmap.PortScanner()
        os_scan_values=nm.scan(ip, arguments='-O')['scan'][ip]['osmatch']
        counthost=1
        os_detection_output_table = prettytable.PrettyTable(["Number", "IP Address", "OS Vendor", "OS Family", "OS Generation", "OS Details", "OS Common Platform Enumeration (CPE) Details"])
        os_vendor=os_scan_values[0]['osclass'][0]['vendor']
        os_family=os_scan_values[0]['osclass'][0]['osfamily']
        os_generation=""
        for i in range(len(os_scan_values[0]['osclass'])-1):
            os_generation+=str(os_scan_values[0]['osclass'][i]['osgen']) + " | "
        os_generation+=str(os_scan_values[0]['osclass'][len(os_scan_values[0]['osclass'])-1]['osgen'])
        os_details=os_scan_values[0]['name']
        os_cpe=""
        for i in range(len(os_scan_values[0]['osclass'])-1):
            os_cpe+=str(os_scan_values[0]['osclass'][i]['cpe']) + " | "
        os_cpe+=str(os_scan_values[0]['osclass'][len(os_scan_values[0]['osclass'])-1]['cpe'])
        os_detection_output_table.add_row([counthost, ip, os_vendor, os_family, os_generation, os_details, os_cpe])
        print("\nOS Detection Results:")
        print(os_detection_output_table)
    except IndexError:
        print("\nSome Error Occurred...\Either the Target IP Address is filtering the connections or Not able to handle the response...\nPlease try again later...")
    except KeyError:
        print("\nSome Error Occurred...\nEither the Target IP Address is not active or Not able to reach the Target IP Address.\nPlease try again later...")
    os_detection_scanner_stop_time=datetime.now()
    print("\nOS Detection Scanner ended at {}".format(os_detection_scanner_stop_time))
    print("Total Scan Duration in Seconds = {}".format(abs(os_detection_scanner_stop_time-os_detection_scanner_start_time).total_seconds()))
    exit_process()

#End of OS Detection Scanner

#Start of Exit Process

def exit_process():
    sys.exit()

#End of Exit Process

#Start of main Function

if __name__=="__main__":    
    try:
        ipaddr=input("\nEnter the Target IP Address (Default: 127.0.0.1): ")
        if len(ipaddr)==0:
            ip='127.0.0.1'
        else:
            ip=ipaddr
        ipaddress.ip_address(ip)
        os_detector(ip)
    except ValueError:
        print("\nInvalid IP Address Entered...")
        exit_process()

#End of main Function
