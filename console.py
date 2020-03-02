
import os
import re
import time
from cmd import Cmd
from dotenv import load_dotenv

################################################################################
# Local import
################################################################################

from initial_setup import Setup, INTRO
from nessus_scan import NessusScan
from msf_commands import MsfCommands

################################################################################
# Envionment variable imports (API Keys etc)
################################################################################

load_dotenv()
TARGETS = os.getenv('TARGETS')

################################################################################
# Main ARES Console
################################################################################

class Console(Cmd):
    prompt = ">>> "
    intro = INTRO
    database = None
    model = None
    planner = None
    metasploit = None
    msfclient = None
    msfconsole = None
    nessus = None
    targets = '10.91.251.173'

    def do_s(self, cmd):
        """
        Calls setup.
        """
        self.do_setup('services')

    def do_setup(self, cmd):
        """
        Setup services avaliable to console.
        Services:
        """
        # command validation
        cmds = cmd.split()
        if len(cmds) != 1:
            print("*** invalid number of arguments")
            return
        if cmds[0] != 'services':
            print("*** invalid setup option, see 'help setup'")
            return
        # command execution
        # Database
        if self.database is None:
            self.database = Setup().database()
        # Metasploit
        if self.metasploit is None:
            self.metasploit = Setup().metasploit()
        # Nessus
        if self.nessus is None:
            self.nessus = Setup().nessus()
        # Model
        if self.model is None:
            self.model = Setup().model()
        # Planner
        if self.planner is None:
            planner = Setup().planner()
            self.planner = planner
        # MsfClient
        if self.msfclient is None:
            msfclient = Setup().msfclient()
            self.msfclient = msfclient
        # MsfConsole
        if self.msfconsole is None:
            msfconsole = Setup().msfconsole(msfclient)
            self.msfconsole = msfconsole
        # Connections
        Setup().nessus_bridge(msfconsole)
        Setup().database_bridge(msfconsole)
        Setup().workspace(msfconsole)
        # Setup end
        print("[*] setup complete")

    def complete_setup(self, text, line, begidx, endidx):
        services = ['services']
        if text:
            services = ([s for s in services if s.startswith(text)])
        return services

    def do_msf(self, cmd):
        """
        Open msf console service.
        """
        if self.msfconsole is None:
            print("[!] msfconsole service has not been setup, see 'help setup'")
        else:
            msf = self.msfconsole
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
        scan_policies = MsfCommands(self.msfconsole).scan_policies()
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
            msfconsole = self.msfconsole
            scan = NessusScan(uuid, scan_name, targets, msfconsole)
            scan.start_scan()
            print("[*] Updating model")
            try:
                self.model.update(scan_name)
            except Exception as e:
                print("Error: ", e)


    def complete_scan(self, text, line, begidx, endidx):
        options = ['policies', 'run']
        if text:
            scan_opts = ([o for o in options if o.startswith(text)])
        return scan_opts


    def do_model(self, cmd):
        """
        Import scans and database entries into model.
        """
        cmds = cmd.split()
        if self.model == None:
            print("[!] Model service has not been setup, see 'help setup'")
        elif len(cmds) != 1:
            print("*** invalid number of arguments")
            return
        elif cmds[0] not in self.scans.keys():
            print("*** invalid import option, see 'help import'")
            return
        else:
            path = self.scans[cmds[0]]
            try:
                self.Model.populate(path)
            except Exception as e:
                print('[!] Error10: ', e)
                return
            print("[+] scan loaded into model")
            return

    def complete_model(self, text, line, begidx, endidx):
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
        Display targets imported to model from scans.
        """
        if self.model is None:
            print("[!] Model service has not been setup, see 'help setup'")
        else:
            targets = self.model.get_targets()
            print("[*] target hosts identified: \n")
            for target in targets:
                print("        ", target, '\n')

    def do_show_target(self, cmd):
        """
        Display the targets data.
        """
        cmds = cmd.split()
        if self.model == None:
            print("[!] Model service has not been setup, see 'help setup'")
        elif len(cmds) != 1:
            print("*** invalid number of arguments")
            return
        elif cmds[0] in self.model.get_targets():
            target = self.model.get_target(cmds[0])
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
        try:
            self.msfconsole.stop_polling()
            print("[*] stopping msfconsole")
        except Exception as e:
            print("Error: ", e)
        try:
            self.msfclient.close_connection()
            print("[*] closing msfclient connect")
        except Exception as e:
            print("Error: ", e)
        try:
            self.metasploit.stop_service()
            print("[*] closing metasploit sub-process")
        except Exception as e:
            print("Error: ", e)
        print("[+] Closing application.\n")

        return True

    do_EOF = do_exit # assign end-of-line to exit

    ##################################################

    def precmd(self, cmd):
        return Cmd.precmd(self, cmd)

    def postloop(self):
        print('\n')

    # def do_input(self, s):
    #     if s=='':
    #         s = input('Your name please: ')
    #     print('Hello', s)


################################################################################
# Main
################################################################################

if __name__ == '__main__':
    console = Console().cmdloop()
