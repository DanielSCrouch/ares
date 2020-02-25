#!/usr/bin/env python3

from kali_setup import Nessus, MsfRpc
from pymeta import *
from threading import Thread
from dotenv import load_dotenv
import time
import queue

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

try:
    Nessus().start_service()
    print("[*] Nessus started")
except Exception:
    print("[-] Error starting Nessus")

try:
    MsfRpc().start_service()
    time.sleep(1) # wait for MsfRpc service to load
    print("[*] Metasploit RPC started")
except Exception:
    print("[-] Error starting Metasploit RPC")

################################################################################
# Login to Metasploit Console
################################################################################

msf_client = MsfClient()
msfcmd_queue = queue.SimpleQueue() # control read/write of commands to msf console
msf_console = MsfConsole(msf_client, cmd_queue=msfcmd_queue)
Thread(target=msf_console.start_polling).start()

################################################################################
# Start Nessus in consol
################################################################################

cmd = "load nessus"
msfcmd_queue.put(cmd)
time.sleep(0.5)
cmd = "nessus_connect " +       \
       NESSUS_USERNAME  + ':' + \
       NESSUS_PASSWORD  + '@' + \
       NESSUS_HOST      + ':' + \
       NESSUS_PORT      + ' ok'
msfcmd_queue.put(cmd)
time.sleep(0.5)
cmd = "nessus_scan_new " +       \
       SCAN_UUID         + ' ' + \
       SCAN_NAME         + ' ' + \
       SCAN_DESCRIPTION  + ' ' + \
       TARGETS
# msfcmd_queue.put(cmd)
time.sleep(0.5)







#
