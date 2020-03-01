
# Extension of console.py module
# Provides collection of msfconsole functions

################################################################################
# Local import
################################################################################

from msf_nessus_parser import policy_list_parser

################################################################################
# Msf Console Command Class - containing msf methods
################################################################################

class MsfCommands(object):

    def __init__(self, msfconsole):
        """
        Defines a collection of MsfConsole commands.
        """
        self.msfconsole = msfconsole

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

    def workspace(self, workspace_name):
        """
        Setups up workspace on Metasploit.
        """
        try:
            cmd = "workspace -a " + workspace_name
            msf_reply = self.msfconsole.callback(cmd, verbose=True)
        except Exception as e:
            print('[!] Error11: ', e)
