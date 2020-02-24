#!/usr/bin/env python3

from kali_setup import Nessus, MsfRpc
from pymeta import *
from threading import Thread
import time

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
# Create and login to Metasploit Console
################################################################################



msf_client = MsfClient()
msf_console = MsfConsole(msf_client)
