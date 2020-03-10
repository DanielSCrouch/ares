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
        Print list of targets.
        """
        target = config.TARGETS[target_name]
        print(target)

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
        target.import_scan(file_path)
