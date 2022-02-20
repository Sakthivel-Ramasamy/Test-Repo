import pkg_resources
import subprocess
import sys

try:
    # print("\nChecking for the required dependencies. If not found, the required dependencies will be installed.\nThis may take some time...\n")
    installed_packages={pkg.key for pkg in pkg_resources.working_set}
    required_packages={'argparse', 'datetime', 'ipaddress', 'python-nmap', 'prettytable', 'scapy', 'termcolor'}
    missing_packages=required_packages-installed_packages
    if missing_packages:
        python = sys.executable
        subprocess.check_call([python, '-m', 'pip', 'install', *missing_packages], stdout=subprocess.DEVNULL)
    success_file=open("success.hop", "w")
    success_file.write("HOPPERJET dependencies installed successfully!")
    success_file.close()
except:
    pass
