
import os
import re
import time
from cmd import Cmd
from dotenv import load_dotenv

################################################################################
# Local import
################################################################################

from plugins import PostgreSQL, Nessus, Metasploit
from msfrpc import MsfClient, MsfConsole
from database import Database
from registrar import Registrar
from msf_nessus_parser import policy_list_parser

################################################################################
# Envionment variable imports (API Keys etc)
################################################################################

load_dotenv()
MSF_WORKSPACE_DEFAULT = os.getenv('MSF_WORKSPACE_DEFAULT')
NESSUS_USERNAME = os.getenv('NESSUS_USERNAME')
NESSUS_PASSWORD = os.getenv('NESSUS_PASSWORD')
NESSUS_HOST = os.getenv('NESSUS_HOST')
NESSUS_PORT = os.getenv('NESSUS_PORT')
POSTGRES_USER = os.getenv('POSTGRES_USER')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD')
POSTGRES_SERVER = os.getenv('POSTGRES_SERVER')
POSTGRES_PORT = os.getenv('POSTGRES_PORT')
POSTGRES_DB_NAME = os.getenv('POSTGRES_DB_NAME')
SCAN_NAME = os.getenv('SCAN_NAME')
SCAN_UUID = os.getenv('SCAN_UUID')
SCAN_DESCRIPTION = os.getenv('SCAN_DESCRIPTION')
TARGETS = os.getenv('TARGETS')

################################################################################
# Main ARES Console
################################################################################

class Console(Cmd):
    prompt = ">>> "
    intro = "\n\n            |     '||''|.   '||''''|   .|'''.|  \n           |||     ||   ||   ||  .     ||..  '  \n          |  ||    ||''|'    ||''|      ''|||.  \n         .''''|.   ||   |.   ||       .     '|| \n        .|.  .||. .||.  '|' .||.....| |'....|'  \n        \n        Automated  Recon  &  Exploit  Software\n\n"
    #
    registrar = Registrar()
    services = {'database'  : None, \
                'planner'   : None, \
                'metasploit': None, \
                'msfclient' : None, \
                'msfconsole': None, \
                'nessus'    : None}
    scan_policies = {} # {name: UUID}
    targets = '10.91.251.173'

    def do_s(self, cmd):
        self.do_connect('services')

    def do_connect(self, cmd):
        """
        Connect services avaliable to console.
        Services: database, planner, metasploit, msfclient, msfconsole, nessus
        """
        cmds = cmd.split()
        if len(cmds) != 1:
            print("*** invalid number of arguments")
            return
        if cmds[0] != 'services':
            print("*** invalid connect option, see 'help connect'")
            return

        # Database

        if self.services['database'] is None:
            try:
                print("[*] loading PostgreSQL plugin")
                self.services['database'] = PostgreSQL()
            except Exception as e:
                print('[!] Error3: ', e)
            try:
                self.services['database'].start_service()
                print("[+] PostgreSQL plugin loaded")
            except Exception as e:
                print('[!] Error4: ', e)

        # Metasploit Plugin

        if self.services['metasploit'] is None:
            try:
                print("[*] loading Metasploit plugin")
                self.services['metasploit'] = Metasploit()
            except Exception as e:
                print('[!] Error3: ', e)
            try:
                self.services['metasploit'].start_service()
                print("[+] Metasploit plugin loaded")
            except Exception as e:
                print('[!] Error4: ', e)

        # Metasploit Rpc Client

        if self.services['msfclient'] is None:
            try:
                print("[*] creating msf rpc client")
                self.services['msfclient'] = MsfClient()
                print("[*] athenticating Metasploit RPC user login")
                self.services['msfclient'].login()
                print("[+] Metasploit RPC athenticating successful")
            except Exception as e:
                print("[!] Error5: ", e)
                print("[!] Recommendation: run app from new console as root'")

        # Metasploit Rpc Console

        if self.services['msfconsole'] is None:
            try:
                print("[*] creating msf rpc console")
                console = MsfConsole(self.services['msfclient'], self.registrar)
                self.services['msfconsole'] = console
                print("[+] Metasploit console avaliable, see 'help msf'")
            except Exception as e:
                print('[!] Error6: ', e)

        # Nessus

        if self.services['nessus'] is None:
            try:
                print("[*] loading Nessus plugin")
                self.services['nessus'] = Nessus()
            except Exception as e:
                print('[!] Error7: ', e)
            try:
                self.services['nessus'].start_service()
                print("[+] Nessus plugin loaded")
            except Exception as e:
                print('[!] Error8: ', e)

            # Nessus - Metasploit Bridge

            try:
                print("[*] creating Nessus to Metasploit bridge")
                msfconsole = self.services['msfconsole']
                cmd = 'load nessus'
                msf_reply = msfconsole.callback(cmd)
            except Exception as e:
                print('[!] Error8: ', e)

            # Nessus - Authentication over bridge

            try:
                print("[*] authenticating Nessus via bridge")
                msfconsole = self.services['msfconsole']
                cmd = "nessus_connect " +       \
                       NESSUS_USERNAME  + ':' + \
                       NESSUS_PASSWORD  + '@' + \
                       NESSUS_HOST      + ':' + \
                       NESSUS_PORT      + ' ok'
                msf_reply = msfconsole.callback(cmd)
            except Exception as e:
                print('[!] Error9: ', e)

            # Nessus - load scan policies

            try:
                print("[*] collecting scan policies from nessus")
                msfconsole = self.services['msfconsole']
                cmd = "nessus_policy_list"
                msf_reply = msfconsole.callback(cmd, verbose=False)
                self.scan_policies = policy_list_parser(msf_reply)
                print("[+] scan policies are avaliable, see 'help scans'")
            except Exception as e:
                print('[!] Error10: ', e)

        # Connect Metasploit to Database

        try:
            print("[*] connecting Metasploit to database: ", POSTGRES_DB_NAME)
            msfconsole = self.services['msfconsole']
            cmd =  "db_connect "
            cmd += POSTGRES_USER + ":" + POSTGRES_PASSWORD + "@"
            cmd += POSTGRES_SERVER + ":" + POSTGRES_PORT + "/"
            cmd += POSTGRES_DB_NAME
            msf_reply = msfconsole.callback(cmd, verbose=False)
            if POSTGRES_DB_NAME not in msf_reply:
                print("[!] unable to connect to database")
            else:
                print("[+] Metasploit connected to database")
        except Exception as e:
            print('[!] Error11: ', e)

        # Workspace setup

        try:
            print("[*] setting up Metasploit workspace")
            self.do_workspace('add ' + MSF_WORKSPACE_DEFAULT)
        except Exception as e:
            print('[!] Error11: ', e)

        # AI Planner

        if self.services['planner'] is None:
            try:
                print("[*] connecting to planner")
                self.services['planner'] = Planner()
                print("[+] planner now avaliable")
            except Exception as e:
                print('[!] Error2: ', e)

        # Setup end

        print("[*] setup complete \n")

    def complete_connect(self, text, line, begidx, endidx):
        services = ['services']
        if text:
            services = ([s for s in services if s.startswith(text)])
        return services

    def do_msf(self, cmd):
        """
        Open msf console service.
        """
        if self.services['msfconsole'] is None:
            print("[!] msfconsole service has not been connected, see 'help connect'")
        else:
            msf = self.services['msfconsole']
            msf.prompt = 'msf' + self.prompt
            msf.cmdloop()

    def do_target(self, cmd):
        """
        Set target IP range.
        """
        cmds = cmd.split()
        if len(cmds) != 1:
            print("*** invalid arguments, see 'help scan'")
            return
        else:
            self.targets = cmd

    ############################################

    def do_scan(self, cmd):
        cmds = cmd.split()
        # Command validation
        if len(cmds) == 1 and cmds[0] not in ['policies']:
            print("*** invalid arguments, see 'help scan'")
            return
        if len(cmds) == 2 and cmds[0] not in ['run']:
            print("*** invalid arguments, see 'help scan'")
            return
        if len(cmds) == 2 and cmds[1] not in self.scan_policies.keys():
            print("*** invalid scan name, see 'scan policies'")
            return
        if len(cmds) == 2 and self.targets is None:
            print("*** no target selected, see 'help target'")
            return
        # Command execution
        if cmds[0] == 'policies':
            print("[*] scan policies avaliable: \n")
            for policy_name in self.scan_policies.keys():
                print("       " + policy_name)
                print("       " + self.scan_policies[policy_name] + '\n')
        if cmds[0] == 'run':
            scanid = None
            scan_policy_name = cmds[1]
            print("[*] running scan...")
            uuid = self.scan_policies[scan_policy_name]
            name = scan_policy_name.replace("Policy", "Scan")
            desc = 'none'
            target =self.targets
            cmd = "nessus_scan_new "
            cmd += uuid + " "
            cmd += name + " "
            cmd += desc + " "
            cmd += target
            msfconsole = self.services['msfconsole']
            msf_reply = msfconsole.callback(cmd, verbose=False)
            if 'scan added' not in msf_reply:
                print("[!] error creating scan")
                return
            try:
                regex = "nessus_scan_launch (\d+)"
                m = re.search(regex, msf_reply, re.IGNORECASE)
                scanid = m.group(1)
                i = int(scanid) # check value is integer
                print("[*] scan created with ID: ", scanid)
            except:
                print("[!] error creating scan")
                return
            cmd = "nessus_scan_launch " + scanid
            msfconsole = self.services['msfconsole']
            msf_reply = msfconsole.callback(cmd, verbose=True)
            if "successfully launched" in msf_reply:
                print("Scan launched, waiting for completion")
            else:
                print("[!] error launching scan")
                return
            # poll nessus for scan completion
            scanning = True
            while scanning:
                time.sleep(5)
                print('...')
                cmd = "nessus_scan_list"
                msfconsole = self.services['msfconsole']
                msf_reply = msfconsole.callback(cmd, verbose=True)
                for line in msf_reply.splitlines():
                    if scanid in line and 'completed' in line:
                        print("[*] scan completed")
                        scanning = False
            # import scan result into database
            cmd = "nessus_db_import " + scanid
            msfconsole = self.services['msfconsole']
            msf_reply = msfconsole.callback(cmd, verbose=True)








    def complete_scan(self, text, line, begidx, endidx):
        options = ['policies', 'run']
        if text:
            scan_opts = ([o for o in options if o.startswith(text)])
        return scan_opts


    ############################################

    def do_workspace(self, cmd):
        """
        Select workspace, or use options add to create new.
        """
        cmds = cmd.split()
        if self.services['metasploit'] == None:
            print("[!] Metasploit service has not been connected, see 'help connect'")
        elif len(cmds) != 0 and len(cmds) != 2:
            print("*** invalid number of arguments, see 'help workspace'")
            return
        if len(cmds) == 0:
            msfconsole = self.services['msfconsole']
            cmd = "workspace"
            msf_reply = msfconsole.callback(cmd, verbose=False)
            print("[*] workspaces: \n")
            for line in msf_reply.splitlines():
                print("    " + line)
        elif len(cmds) == 2 and cmds[0] not in ['add', 'select', 'delete']:
            print("*** invalid arguments, see 'help workspace'")
            return
        else:
            method = cmds[0]
            workspace_name = cmds[1]
            if method == 'add':
                msfconsole = self.services['msfconsole']
                cmd = "workspace -a " + workspace_name
                msf_reply = msfconsole.callback(cmd, verbose=True)

    def do_import(self, cmd):
        """
        Import scans into database.
        """
        cmds = cmd.split()
        if self.services['database'] == None:
            print("[!] database service has not been connected, see 'help connect'")
        elif len(cmds) != 1:
            print("*** invalid number of arguments")
            return
        elif cmds[0] not in self.scans.keys():
            print("*** invalid import option, see 'help import'")
            return
        else:
            path = self.scans[cmds[0]]
            try:
                self.services['database'].populate(path)
            except Exception as e:
                print('[!] Error10: ', e)
                return
            print("[+] scan loaded into database")
            return

    def complete_import(self, text, line, begidx, endidx):
        if not text:
            try:
                scans = list(self.scans.keys())
            except Exception as e:
                print(e)
        else:
            scans = ([s for s in self.scans.keys() if s.startswith(text)])
        return scans

    def do_show_targets(self, cmd):
        """
        Display targets imported to database from scans.
        """
        if self.services['database'] is None:
            print("[!] database service has not been connected, see 'help connect'")
        else:
            targets = self.services['database'].get_targets()
            print("[*] target hosts identified: \n")
            for target in targets:
                print("        ", target)

    def do_show_target(self, cmd):
        """
        Display the targets data.
        """
        cmds = cmd.split()
        if self.services['database'] == None:
            print("[!] database service has not been connected, see 'help connect'")
        elif len(cmds) != 1:
            print("*** invalid number of arguments")
            return
        elif cmds[0] in self.services['database'].get_targets():
            target = self.services['database'].get_target(cmds[0])
            print("[*] target identified: \n")
            print(target)

    def default(self, cmd):
        if cmd == 'q':
            return self.do_exit(cmd)
        else:
            print("*** Unknown Command, see 'help'")

    def do_shell(self, cmd):
        """
        run a shell command
        """
        print("[+] Running a shell command")
        output = os.popen(cmd).read()
        print(output)

    def do_exit(self, cmd):
        """
        exit the application
        """
        print("[+] Closing application.\n")
        return True

    do_EOF = do_exit # assign end-of-line to exit

    ##################################################

    def precmd(self, cmd):
        return Cmd.precmd(self, cmd)

    # def do_input(self, s):
    #     if s=='':
    #         s = input('Your name please: ')
    #     print('Hello', s)


################################################################################
# Main
################################################################################

if __name__ == '__main__':
    console = Console().cmdloop()
