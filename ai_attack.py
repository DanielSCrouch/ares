#!/usr/bin/env python3

import time
import queue
from threading import Thread
from dotenv import load_dotenv
#
from kali_setup import Nessus, MsfRpc
from scan_db import ScanDB
from pymeta import *

################################################################################
# Envionment imports (API Keys etc)
################################################################################

load_dotenv()
NESSUS_USERNAME = os.getenv('NESSUS_USERNAME')
NESSUS_PASSWORD = os.getenv('NESSUS_PASSWORD')
NESSUS_HOST = os.getenv('NESSUS_HOST')
NESSUS_PORT = os.getenv('NESSUS_PORT')
SCAN_NAME = os.getenv('SCAN_NAME')
SCAN_UUID = os.getenv('SCAN_UUID')
SCAN_DESCRIPTION = os.getenv('SCAN_DESCRIPTION')
TARGETS = os.getenv('TARGETS')

################################################################################
# Stat Kali Services
################################################################################

intro = '\n\n'
intro += '     **************************************************\n'
intro += '     ********* AUTOMATED PENETRATION TESTING **********\n'
print(intro)
time.sleep(5)

print("[*] Loading Plugins...")

try:
    time.sleep(3)
    Nessus().start_service()
    print("[*] Nessus started")
except Exception:
    print("[-] Error starting Nessus")

try:
    MsfRpc().start_service()
    time.sleep(3) # wait for MsfRpc service to load
    print("[*] Metasploit RPC started\n")
    time.sleep(3)
except Exception:
    print("[-] Error starting Metasploit RPC")

################################################################################
# Login to Metasploit Console
################################################################################

msf_client = MsfClient()
msf_client.login()
msfcmd_queue = queue.SimpleQueue() # control read/write of commands to msf console
msf_console = MsfConsole(msf_client, cmd_queue=msfcmd_queue)
Thread(target=msf_console.start_polling).start()

################################################################################
# Start Nessus in consol
################################################################################

time.sleep(2)
cmd = "load nessus"
msfcmd_queue.put(cmd)
time.sleep(4)
cmd = "nessus_connect " +       \
       NESSUS_USERNAME  + ':' + \
       NESSUS_PASSWORD  + '@' + \
       NESSUS_HOST      + ':' + \
       NESSUS_PORT      + ' ok'
msfcmd_queue.put(cmd)
time.sleep(10)
cmd = "nessus_scan_new " +       \
       SCAN_UUID         + ' ' + \
       SCAN_NAME         + ' ' + \
       SCAN_DESCRIPTION  + ' ' + \
       TARGETS
msfcmd_queue.put(cmd)
time.sleep(17)

################################################################################
# Load Nessus Scan Data Base
################################################################################

print("[*] Loading Scan Database\n")
time.sleep(4)
scan_db = ScanDB()
print("[*] Database Avaliable\n")
time.sleep(3)
hosts = [host for host in scan_db.targets.keys()]
print("[*] Found (" + str(len(hosts)) + ") hosts\n")
for host in hosts:
    print("     [*] " + str(host) + "\n")
time.sleep(7)
print("[@] scan_db.targets[" + str(hosts[0]) + "]\n")
time.sleep(5)
print(scan_db.targets[hosts[0]])
time.sleep(5)
