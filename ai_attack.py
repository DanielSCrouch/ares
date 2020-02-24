#!/usr/bin/env python3

from kali_setup import Nessus, MsfRpc
from pymeta import *

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
    print("[*] Metasploit RPC started")
except Exception:
    print("[-] Error starting Metasploit RPC")

################################################################################
# Create and login to Metasploit Console
################################################################################
