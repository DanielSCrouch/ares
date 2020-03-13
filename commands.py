# Extension of console.py module
# Provides additional functions/commands to console

import os
import re
import glob
import time
import ipaddress
import subprocess
from pathlib import Path
# global variables
import config

################################################################################
# Generic Console Command Class - containing methods
################################################################################

class Commands(object):
    """
    Defines a collection of MsfConsole commands.
    """

    def show_scan_names(self):
        """
        Print list of completed scan names.
        """
        s = 'Name \n----'
        path = "nessus_scans_tmp/" + '*.csv'
        csv_path = glob.glob(path)
        file_names = [os.path.basename(s) for s in csv_path]
        for file_name in file_names:
            s += '\n' + file_name.replace(".csv", "")[:-7]
        print(s)

    def show_targets(self):
        """
        Print list of targets.
        """
        s = 'Name \n----'
        for target_name in config.TARGETS.keys():
            s += '\n' + target_name
        print(s)

    def show_target(self, target_name):
        """
        Display a targets information.
        """
        target = config.TARGETS[target_name]
        print(target)

    def show_vulns(self, target_name):
        """
        Display a targets vulnerabilities.
        """
        s = "\n   CVE ID            Risk         Msf       Ares"
        s += '\n   ----------------------------------------------------'
        target = config.TARGETS[target_name]
        vulns = target.vulns.values()
        for vuln in vulns:
            cve_id = vuln.cve_id
            risk = vuln.risk
            msf = str(len(vuln.msf_modules.keys()))
            ares = "no"
            s += "\n   {: <3}     {: <8}     {: <5}     {: <5}".format(\
                        cve_id, risk, msf, ares)
        print(s)

    def validip(self, ip_addr):
        """
        Return True if IP address is valid.
        """
        try:
            ipaddress.ip_address(ip_addr)
            return True
        except:
            return False

    def scan(self, target_name, scan_type):
        if scan_type == 'host':
            config.MSFCOMMANDS.scan('host_scan', target_name)
        if scan_type == 'os':
            config.MSFCOMMANDS.scan('os_scan', target_name)
        if scan_type == 'full':
            config.MSFCOMMANDS.scan('full_scan', target_name)
        scan_path = Path.cwd().glob('nessus_scans_tmp/' + target_name + '/' + scan_type + '*.csv')
        for file in scan_path:
            file_path = file
        target = config.TARGETS[target_name]
        self.scan_import(target_name, scan_type)

    def scan_import(self, target_name, scan_type):
        scan_path = Path.cwd().glob('nessus_scans_tmp/' + target_name + '/' + scan_type + '*.csv')
        for file in scan_path:
            file_path = file
        target = config.TARGETS[target_name]
        target.import_scan(file_path)
        self.update_vulns(target_name)

    def update_vulns(self, target_name):
        target = config.TARGETS[target_name]
        for vuln in target.vulns.values():
            vuln_id = vuln.cve_id
            msfexploits = config.MSFCOMMANDS.search_exploit(vuln_id)
            vuln.msf_modules = msfexploits

    def exit(self):
        if config.MSFCONSOLE:
            print("[*] stopping msfconsole")
            config.MSFCONSOLE.stop_polling()
        if config.MSFCLIENT:
            print("[*] closing msfclient connection")
            config.MSFCLIENT.close_connection()
        if config.METASPLOIT:
            print("[*] closing metasploit sub-process")
            config.METASPLOIT.stop_service()
        if config.NESSUS:
            print("[*] closing Nessus subprocess")
            config.NESSUS.stop_service()
        if config.DATABASE:
            print("[*] closing PostgreSQL subprocess")
            config.DATABASE.stop_service()
        print("Application closed.")
