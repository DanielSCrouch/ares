
# Extension of msf console module
# Provides collection of automated msfconsole methods

import os
from dotenv import load_dotenv

################################################################################
# Local import
################################################################################

from msf_nessus_parser import policy_list_parser

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




#################################

    def scan_policies(self):
        """
        Returns list of Nessus scan policies.
        """
        try:
            print("[*] collecting scan policies from nessus")
            cmd = "nessus_policy_list"
            msf_reply = self.msfconsole.callback(cmd, verbose=False)
            scan_policies = policy_list_parser(msf_reply)
            return scan_policies
        except Exception as e:
            print('[!] Error10: ', e)
