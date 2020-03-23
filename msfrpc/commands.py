
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

    def connect_nessus(self):
        """
        Creates bridge from Metasploit to Nessus.
        """
        cmd = 'load nessus'
        msf_reply = config.MSFCONSOLE.callback(cmd)
        cmd = "nessus_connect " +       \
               NESSUS_USERNAME  + ':' + \
               NESSUS_PASSWORD  + '@' + \
               NESSUS_HOST      + ':' + \
               NESSUS_PORT      + ' ok'
        msf_reply = config.MSFCONSOLE.callback(cmd)

    def connect_database(self):
        """
        Creates bridge from Metasploit to PostgreSQL database.
        """
        cmd =  "db_connect "
        cmd += POSTGRES_USER + ":" + POSTGRES_PASSWORD + "@"
        cmd += POSTGRES_SERVER + ":" + POSTGRES_PORT + "/"
        cmd += POSTGRES_DB_NAME
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=False)
        if POSTGRES_DB_NAME not in msf_reply:
            raise Exception("[!] unable to connect to database \n")

    def set_workspace(self, workspace_name=MSF_WORKSPACE_DEFAULT):
        """
        Change workspace within Metasploit, create new if not already avaliable.
        """
        cmd = "workspace -a " + workspace_name
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)

    def show_scan_policies(self):
        """
        Print list of Nessus scan policies.
        """
        cmd = "nessus_policy_list"
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)

    def search_exploit(self, id):
        """
        Return module (and rank) of msf exploits targeted to vulnerability.
        """
        cmd = "search " + id
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=False)
        # Parse response
        exploits = {}
        lines = (line for line in msf_reply.splitlines())
        for line in lines:
            if "No results from search" in line:
                return {}
            if "Rank" in line:
                rank_index = line.split().index('Rank')
            if "---" in line:
                break
        for line in lines:
            items = line.split()
            if len(items) > 1:
                exploits[items[1]] = items[rank_index]
        return exploits
