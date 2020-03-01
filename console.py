
import os
import re
import time
from cmd import Cmd
from dotenv import load_dotenv

################################################################################
# Local import
################################################################################

from initial_setup import Setup
from nessus_scan import NessusScan
from msf_commands import MsfCommands

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
SCAN_NAME = os.getenv('SCAN_NAME')
SCAN_UUID = os.getenv('SCAN_UUID')
SCAN_DESCRIPTION = os.getenv('SCAN_DESCRIPTION')
TARGETS = os.getenv('TARGETS')

################################################################################
# Main ARES Console
################################################################################

class Console(Cmd):
    prompt = ">>> "
    intro = INTRO
    #
    services = {'database'  : None, \
                'planner'   : None, \
                'metasploit': None, \
                'msfclient' : None, \
                'msfconsole': None, \
                'nessus'    : None}
    targets = '10.91.251.173'

    def do_s(self, cmd):
        self.do_connect('services')

    def do_connect(self, cmd):
        """
        Connect services avaliable to console.
        Services: database, planner, metasploit, msfclient, msfconsole, nessus
        """
        # command validation
        cmds = cmd.split()
        if len(cmds) != 1:
            print("*** invalid number of arguments")
            return
        if cmds[0] != 'services':
            print("*** invalid connect option, see 'help connect'")
            return
        # command execution
        # Database
        if self.services['database'] is None:
            self.services['database'] = Setup().database()
        # Metasploit
        if self.services['metasploit'] is None:
            self.services['metasploit'] = Setup().metasploit()
        # Nessus
        if self.services['nessus'] is None:
            self.services['nessus'] = Setup().nessus()
        # Planner
        if self.services['planner'] is None:
            planner = Setup().planner()
            self.services['planner'] = planner
        # MsfClient
        if self.services['msfclient'] is None:
            msfclient = Setup().msfclient()
            self.services['msfclient'] = msfclient
        # MsfConsole
        if self.services['msfconsole'] is None:
            msfconsole = Setup().msfconsole(msfclient)
            self.services['msfconsole'] = msfconsole
        # Connections
        Setup().nessus_bridge(msfconsole)
        Setup().database_bridge(msfconsole)
        Setup().workspace(msfconsole)
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
        scan_policies = MsfCommands(self.services['msfconsole']).scan_policies()
        if len(cmds) == 1 and cmds[0] not in ['policies']:
            print("*** invalid arguments, see 'help scan'")
            return
        if len(cmds) == 2 and cmds[0] not in ['run']:
            print("*** invalid arguments, see 'help scan'")
            return
        if len(cmds) == 2 and cmds[1] not in scan_policies.keys():
            print("*** invalid scan name, see 'scan policies'")
            return
        if len(cmds) == 2 and self.targets is None:
            print("*** no target selected, see 'help target'")
            return
        # Command execution
        if cmds[0] == 'policies':
            print("[*] scan policies avaliable: \n")
            for policy_name in scan_policies.keys():
                print("       " + policy_name)
                print("       " + scan_policies[policy_name] + '\n')
        if cmds[0] == 'run':
            scan_policy_name = cmds[1]
            #
            uuid = scan_policies[scan_policy_name]
            scan_name = scan_policy_name.replace("Policy", "Scan")
            targets = self.targets
            msfconsole = self.services['msfconsole']
            scan = NessusScan(uuid, scan_name, targets, msfconsole)
            scan.start_scan()
            # except Exception as e:
            #     print("[!] Error13: ", e)


    def complete_scan(self, text, line, begidx, endidx):
        options = ['policies', 'run']
        if text:
            scan_opts = ([o for o in options if o.startswith(text)])
        return scan_opts


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
