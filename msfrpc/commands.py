
# Extension of msf console module
# Provides collection of automated msfconsole methods

import os
import re
import time
import subprocess
from dotenv import load_dotenv
# global variables
import config

################################################################################
# Local import
################################################################################



################################################################################
# Envionment variable imports (API Keys etc)
################################################################################

load_dotenv()
NESSUS_USERNAME = os.getenv('NESSUS_USERNAME')
NESSUS_PASSWORD = os.getenv('NESSUS_PASSWORD')
NESSUS_HOST = os.getenv('NESSUS_HOST')
NESSUS_PORT = os.getenv('NESSUS_PORT')
POSTGRES_USER = os.getenv('POSTGRES_USER')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD')
POSTGRES_SERVER = os.getenv('POSTGRES_SERVER')
POSTGRES_PORT = os.getenv('POSTGRES_PORT')
POSTGRES_DB_NAME = os.getenv('POSTGRES_DB_NAME')
MSF_WORKSPACE_DEFAULT = os.getenv('MSF_WORKSPACE_DEFAULT')
NESSUS_DEF_DIR = os.getenv('NESSUS_DEF_DIR')
NESSUS_LOC_DIR = os.getenv('NESSUS_LOC_DIR')
HOST_SCAN_ID = os.getenv('HOST_SCAN_ID')
OS_SCAN_ID = os.getenv('OS_SCAN_ID')
FULL_SCAN_ID = os.getenv('FULL_SCAN_ID')

################################################################################
# Msf Console Command Class - containing msf methods
################################################################################

class MsfCommands(object):
    """
    Defines a collection of MsfConsole commands.
    """

    def __init__(self):
        self.msfconsole = None

    def connect(self, msfconsole):
        """
        Connect commands class to console to enable command execution
        """
        self.msfconsole = msfconsole

    def connect_nessus(self):
        """
        Creates bridge from Metasploit to Nessus.
        """
        cmd = 'load nessus'
        msf_reply = self.msfconsole.callback(cmd)
        cmd = "nessus_connect " +       \
               NESSUS_USERNAME  + ':' + \
               NESSUS_PASSWORD  + '@' + \
               NESSUS_HOST      + ':' + \
               NESSUS_PORT      + ' ok'
        msf_reply = self.msfconsole.callback(cmd)

    def connect_database(self):
        """
        Creates bridge from Metasploit to PostgreSQL database.
        """
        cmd =  "db_connect "
        cmd += POSTGRES_USER + ":" + POSTGRES_PASSWORD + "@"
        cmd += POSTGRES_SERVER + ":" + POSTGRES_PORT + "/"
        cmd += POSTGRES_DB_NAME
        msf_reply = self.msfconsole.callback(cmd, verbose=False)
        if POSTGRES_DB_NAME not in msf_reply:
            raise Exception("[!] unable to connect to database \n")

    def set_workspace(self, workspace_name):
        """
        Change workspace within Metasploit, create new if not already avaliable.
        """
        cmd = "workspace -a " + workspace_name
        msf_reply = self.msfconsole.callback(cmd, verbose=True)

    def show_scan_policies(self):
        """
        Print list of Nessus scan policies.
        """
        cmd = "nessus_policy_list"
        msf_reply = self.msfconsole.callback(cmd, verbose=True)

    def scan(self, scan_name, target_name):
        """
        Scan an IP address with a given scan policy.
        """
        ip_addr = config.TARGETS[target_name].ip
        # create scan
        if 'host_scan' in scan_name:
            uuid = HOST_SCAN_ID
        elif 'os_scan' in scan_name:
            uuid = OS_SCAN_ID
        elif 'full_scan' in scan_name:
            uuid = FULL_SCAN_ID
        cmd = "nessus_scan_new "
        cmd += uuid + " "
        cmd += scan_name + "_policy "
        cmd += 'none' + " "
        cmd += ip_addr
        msf_reply = self.msfconsole.callback(cmd, verbose=False)
        if 'scan added' not in msf_reply:
            raise Exception("error creating scan")
        # retrieve scan id
        regex = "nessus_scan_launch (\d+)"
        m = re.search(regex, msf_reply, re.IGNORECASE)
        try:
            scanid = m.group(1)
            i = int(scanid) # check value is integer
        except Exception as e:
            print(msf_reply)
            raise Exception("error creating scan 2")
        # launch scan
        cmd = "nessus_scan_launch " + scanid
        msf_reply = self.msfconsole.callback(cmd, verbose=True)
        if "successfully launched" not in msf_reply:
            raise Exception("error launching scan")
        # wait for scan to complete
        scanning = True
        while scanning:
            time.sleep(5)
            print('[*] scan running...')
            cmd = "nessus_scan_list"
            msf_reply = self.msfconsole.callback(cmd, verbose=False)
            for line in msf_reply.splitlines():
                if scanid in line and 'completed' in line:
                    print("[*] scan completed")
                    scanning = False
        # import scan into postgresql
        cmd = "nessus_db_import " + scanid
        msf_reply = self.msfconsole.callback(cmd, verbose=True)
        if 'Done' not in msf_reply:
            raise Exception("error importing scan")
        # export scan to csv
        cmd = "nessus_scan_export " + scanid + " CSV"
        msf_reply = self.msfconsole.callback(cmd, verbose=False)
        if 'export is ready' not in msf_reply:
            raise Exception("error exporting scan to csv")
        # move scan to local nessus temp folder
        shell_cmd = "install -D -C -m 775 -o ares -g ares "
        shell_cmd += NESSUS_DEF_DIR + "/" + scan_name + "*.csv "
        shell_cmd += " -t " + NESSUS_LOC_DIR + "/" + target_name
        process = subprocess.Popen(shell_cmd,                 \
                                   universal_newlines = True, \
                                   stdout = subprocess.PIPE,  \
                                   stderr = subprocess.PIPE,  \
                                   shell=True,                \
                                   bufsize=0)
        out, err = process.communicate()
        if err:
            raise Exception(err)
