# Extension of console.py module
# Provides additional functions/commands to console

import os
import re
import glob
import time
import ipaddress
import subprocess
from pathlib import Path
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

    def plan(self, depth=1, verbose=False):
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
            print("[*] running planner at depth", d)
            steps = []
            config.PDDLTRANSLATE.generate_problem(depth=d)
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
            print("[*] planner resolved")
            print('\n    ' + 'plan' + '\n    ' + '=' * 60)
            if len(steps) == 0:
                print('something broke, see plan.txt')
            else:
                for step in steps:
                    print('   ', step)


    def target(self, name, ip, verbose=False):
        config.TARGETS[name] = Target(name, ip)
        # display output
        if verbose:
            print('\n    ' + 'targets' + '\n    ' + '=' * 60)
            for target in config.TARGETS.values():
                print('   ', target.name, target.ip)

    def show_targets(self):
        """
        Print list of targets.
        """
        print('\n    ' + 'targets' + '\n    ' + '=' * 60)
        for target in config.TARGETS.values():
            print('   ', target.name, target.ip)

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
        scan_name = scan_type + '_scan'
        scan_path = Path.cwd().glob('nessus_scans_tmp/' + target_name + '/' + scan_name + '*.csv')
        for file in scan_path:
            file_path = file
        target = config.TARGETS[target_name]
        target.import_scan(file_path)
        # self.update_vulns(target_name)
        print("[+]", target_name, "updated with", scan_type, "scan")

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
            # config.NESSUS.stop_service()
        if config.DATABASE:
            print("[*] closing PostgreSQL subprocess")
            # config.DATABASE.stop_service()
        print("Application closed.")
