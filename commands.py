# Extension of console.py module providing functions/commands support to
# the Ares console
#
# Author: Daniel Crouch
# Date created: March 2020

import os
import re
import glob
import time
import ipaddress
import subprocess
from pathlib import Path
from threading import Thread
from modelling.target import Target
# global variables
import config

################################################################################
# Generic Console Command Class - containing methods
################################################################################

class Commands(object):
    """
    Defines a collection of MsfConsole commands.
    """
    def __init__(self):
        self.setup_complete = False

    def setup(self):
        """
        Sets up Ares environment including plugins and module connections
        """
        if not self.setup_complete:
            print("\r[*] loading PostgreSQL plugin")
            config.DATABASE.start_service()
            print("\r[+] PostgreSQL database now avaliable")
            print("\r[*] loading Metasploit plugin")
            config.METASPLOIT.start_service()
            print("\r[+] Metasploit now avaliable")
            print("\r[*] loading Nessus plugin")
            config.NESSUS.start_service()
            print("\r[+] Nessus now avaliable")
            print("\r[*] logging into Metasploit via RPC")
            config.MSFCLIENT.login()
            print("\r[+] Metasploit client login successfull")
            print("\r[*] connecting msf console to Metasploit client")
            config.MSFCONSOLE.connect(config.MSFCLIENT)
            print("\r[+] msf console now avaliable, see 'help msf'")
            print("\r[*] connecting msf commmand tool to msf console")
            config.MSFCOMMANDS.connect_nessus()
            print("\r[+] Nessus now avaliable to msf")
            print("\r[*] connecting Metasploit to database")
            config.MSFCOMMANDS.connect_database()
            print("\r[+] Metasploit connected to database")
            print("\r[+] setting up msf workspace")
            config.MSFCOMMANDS.set_workspace()
            print("\r[*] setup complete")
            self.setup_complete = True
            print()

    def plan(self, target_name, depth=6, verbose=False):
        """
        Generate problem file and run planner.
        """
        outpath = Path.cwd() / 'planning' / 'pddl_files' / 'plan.txt'
        steps = []
        # require targets
        if len(config.TARGETS) == 0:
            print("no targets, see 'help target'")
            return
        # recall planner to find maximum depth
        for d in range(1, depth+1):
            # print("\r[*] running planner at depth", d)
            steps = []
            config.PDDLTRANSLATE.generate_problem(target_name, depth=d)
            config.PLANNER.run()
            plan = outpath.read_text()
            if 'plan' not in plan:
                break
            else:
                # record plan
                plan = outpath.read_text()
                lines = (line for line in plan.splitlines())
                for line in lines:
                    if line.startswith('step'):
                        steps.append(line)
                        break
                for line in lines:
                    if len(line.strip()) == 0:
                        break
                    else:
                        steps.append(line)
        if verbose:
            print("\r[*] planner resolved")
            print('\n    ' + 'Attack Vector' + '\n    ' + '=' * 60)
            if len(steps) == 0:
                print('\r[!] planning error, see plan.txt')
            else:
                for step in steps:
                    print('   ', step)
                print()

    def target(self, name, ip, verbose=False):
        """
        Track a target
        """
        config.TARGETS[name] = Target(name, ip)
        # display output
        if verbose:
            print('\n    ' + 'targets' + '\n    ' + '=' * 60)
            for target in config.TARGETS.values():
                print('   ', target.name, target.ip)
            print()

    def show_targets(self):
        """
        Print list of targets.
        """
        print('\n    ' + 'targets' + '\n    ' + '=' * 60)
        for target in config.TARGETS.values():
            print('   ', target.name, target.ip)
        print()

    def show_target(self, target_name):
        """
        Display a targets information.
        """
        target = config.TARGETS[target_name]
        print(target)

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

    def shell(self, cmd):
        """
        Print response of shell command
        """
        output = os.popen(cmd).read()
        print('\n    ' + 'shell response' + '\n    ' + '=' * 60)
        for line in output.splitlines():
            print('   ', line)

    def validip(self, ip_addr):
        """
        Return True if IP address is valid.
        """
        try:
            ipaddress.ip_address(ip_addr)
            return True
        except:
            return False

    def scan_import(self, scan_type, target_name):
        """
        Import a Nessus CSV scan report to a target
        """
        scan_name = scan_type + '_scan'
        scan_path = Path.cwd().glob('nessus_scans_tmp/' + target_name + '/' + scan_name + '*.csv')
        for file in scan_path:
            file_path = file
        target = config.TARGETS[target_name]
        if scan_type == 'port':
            config.SCANIMPORT.import_port_scan(target_name, file_path)
        if scan_type == 'full':
            config.SCANIMPORT.import_full_scan(target_name, file_path)
        # self.update_vulns(target_name)
        print("\r[+]", target_name, "updated with", scan_type, "scan \n")

    def update_vulns(self, target_name):
        """
        Check vulnerabilities for matching Metasploit exploit
        """
        target = config.TARGETS[target_name]
        for vuln in target.vulns.values():
            vuln_id = vuln.cve_id
            msfexploits = config.MSFCOMMANDS.search_exploit(vuln_id)
            vuln.msf_modules = msfexploits

    def exit(self):
        """
        Close application, plugins and connections
        """
        if config.MSFCONSOLE:
            print("\r[*] stopping msfconsole")
            config.MSFCONSOLE.stop_polling()
        if config.MSFCLIENT:
            print("\r[*] closing msfclient connection")
            config.MSFCLIENT.close_connection()
        if config.METASPLOIT:
            print("\r[*] closing metasploit sub-process")
            config.METASPLOIT.stop_service()
        if config.NESSUS:
            print("\r[*] closing Nessus subprocess")
            # config.NESSUS.stop_service()
        if config.DATABASE:
            print("\r[*] closing PostgreSQL subprocess")
            # config.DATABASE.stop_service()
        print("\n[*] Application closed.")
