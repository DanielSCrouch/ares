
import os
import re
import time
import traceback
from cmd import Cmd
from dotenv import load_dotenv

################################################################################
# Local import
################################################################################

from plugins.postgresql import PostgreSQL
from plugins.metasploit import Metasploit
from plugins.nessus import Nessus

from msfrpc.client import MsfClient
from msfrpc.console import MsfConsole
from msfrpc.commands import MsfCommands

from modelling.model import Model

from planning.planner import Planner

################################################################################
# Global variables
################################################################################

# Plugin processes
DATABASE = PostgreSQL()
METASPLOIT = Metasploit()
NESSUS = Nessus()
# Native objects
MODEL = Model()
PLANNER = Planner()
MSFCLIENT = MsfClient()
MSFCONSOLE = MsfConsole()
MSFCOMMANDS = MsfCommands()
# Variables
TARGET = None

################################################################################
# Main ARES Console
################################################################################

class Console(Cmd):
    prompt = ">>> "
    with open('misc/intro.txt', 'r') as f:
        intro = f.read()

    ############################################
    # Initial Setup
    ############################################

    def do_setup(self, cmd):
        """
        Setup services avaliable to console.
        """
        # command validation
        cmds = cmd.split()
        if len(cmds) != 1:
            print("*** invalid number of arguments")
            return
        # command execution
        try:
            print("[*] loading PostgreSQL plugin")
            DATABASE.start_service()
            print("[*] PostgreSQL database now avaliable")
            print("[*] loading Metasploit plugin")
            METASPLOIT.start_service()
            print("[*] Metasploit now avaliable")
            print("[*] loading Nessus plugin")
            NESSUS.start_service()
            print("[*] Nessus now avaliable")
            print("[*] logging into Metasploit via RPC")
            MSFCLIENT.login()
            print("[*] Metasploit client login successfull")
            print("[*] connecting msf console to Metasploit client")
            MSFCONSOLE.connect(MSFCLIENT)
            print("[*] msf console now avaliable, see 'help msf'")
            print("[*] connecting msf commmand tool to msf console")
            MSFCOMMANDS.connect(MSFCONSOLE)
            print("[*] msf automated commands now avaliable")
            print("[*] connecting Metasploit to Nessus")
            MSFCOMMANDS.connect_nessus()
            print("[*] Nessus now avaliable to msf")
            print("[*] connecting Metasploit to database")
            MSFCOMMANDS.connect_database()
            print("[+] Metasploit connected to database")
            print("[+] setting up msf workspace")
            MSFCOMMANDS.set_workspace('default')
            print("[*] setup complete")
        except Exception as e:
            handle(e)

    ############################################
    # Metasploit console
    ############################################

    def do_msf(self, cmd):
        """
        Open msf console.
        """
        try:
            MSFCONSOLE.prompt = 'msf' + self.prompt
            MSFCONSOLE.cmdloop()
        except Exception as e:
            handle(e)

    ############################################
    # set target(s)
    ############################################

    def do_target(self, cmd):
        """
        Set target IP range.
        """
        cmds = cmd.split()
        if len(cmds) != 1:
            print("*** invalid arguments, see 'help scan'")
            return
        ip_range = cmds[0]
        self.target = ip_range

    ############################################
    # set show
    ############################################

    def do_show(self, cmd):
        """
        Display hosts.
        Use 'all' for a list of all known hosts.
        USe 'target' to see current target ip range
        """
        cmds = cmd.split()
        if len(cmds) != 1:
            print("*** invalid arguments, see 'help scan'")
            return
        try:
            host_name = cmds[0]
            if 'all' in host_name:
                host_names = self.model.get_host_names()
                print("[*] hosts identified: \n")
                for host_name in host_names:
                    print("        ", host_name)
            elif 'target' in host_name:
                print(self.target)
            else:
                host = self.model.get_host(host_name)
                print(host)
        except Exception as e:
            print(e)

    ############################################
    # Scanning
    ############################################

    def do_scan(self, cmd):
        cmds = cmd.split()
        # Command validation
        if len(cmds) == 1 and cmds[0] not in ['policies', 'names']:
            print("*** invalid arguments, see 'help scan'")
            return
        if len(cmds) == 2 and cmds[0] not in ['run']:
            print("*** invalid arguments, see 'help scan'")
            return
        if len(cmds) == 2 and self.targets is None:
            print("*** no target selected, see 'help target'")
            return
        # Command execution
        if cmds[0] == 'policies':
            scan_policies = MsfCommands(self.msfconsole).scan_policies()
            print("[*] scan policies avaliable: \n")
            for policy_name in scan_policies.keys():
                print("       " + policy_name)
                print("       " + scan_policies[policy_name])
        if cmds[0] == 'names':
            scan_names = Commands().get_scan_names()
            if scan_names:
                print("[*] scans avaliable: \n")
                for scan_name in scan_names:
                    print("       " + scan_name)
            else:
                print("[!] no scans found")
        if cmds[0] == 'run':
            scan_policy_name = cmds[1]
            #
            scan_policies = MsfCommands(self.msfconsole).scan_policies()
            try:
                uuid = scan_policies[scan_policy_name]
            except:
                print("[!] no matching policy name")
                return
            scan_name = scan_policy_name.replace("Policy", "Scan")
            targets = self.targets
            msfconsole = self.msfconsole
            scan = NessusScan(uuid, scan_name, targets, msfconsole)
            scan.start_scan()
            print("[*] Updating model")
            try:
                self.model.import_scan(scan_name)
            except Exception as e:
                print("Error: ", e)


    def complete_scan(self, text, line, begidx, endidx):
        options = ['policies', 'run']
        if text:
            scan_opts = ([o for o in options if o.startswith(text)])
        return scan_opts

    ############################################
    # Modelling
    ############################################

    def do_model(self, cmd):
        cmds = cmd.split()
        # Command validation
        if len(cmds) != 2:
            print("*** invalid number of arguments, see 'help scan'")
            return
        method = cmds[0]
        attr = cmds[1]
        # Command execution
        if 'import' in method:
            try:
                self.model.import_scan(attr)
                print("[*] import to model complete")
            except Exception as e:
                print("Error: ", e)

    def complete_model(self, text, line, begidx, endidx):
        if not text:
            try:
                scans = list(self.scans.keys())
            except Exception as e:
                print(e)
        else:
            scans = ([s for s in self.scans.keys() if s.startswith(text)])
        return scans

    ############################################
    # generic console commands
    ############################################

    def do_shell(self, cmd):
        """
        run a shell command
        """
        print("[+] Running a shell command")
        output = os.popen(cmd).read()
        print(output)

    def default(self, cmd):
        if cmd == 'q':
            return self.do_exit(cmd)
        if cmd == 's':
            self.do_setup(cmd)
        else:
            print("*** Unknown Command, see 'help'")

    def precmd(self, cmd):
        return Cmd.precmd(self, cmd)

    def postcmd(self, stop, line):
        print('\n')
        if stop:
            return True

    ############################################
    # exit process
    ############################################

    def do_exit(self, cmd):
        """
        exit the application
        """
        try:
            print("[*] stopping msfconsole")
            MSFCONSOLE.stop_polling()
            print("[*] closing msfclient connect")
            MSFCLIENT.close_connection()
            print("[*] closing metasploit sub-process")
            METASPLOIT.stop_service()
        except Exception as e:
            print("Error: ", e)
        print("[+] Closing application.")
        return True

    do_EOF = do_exit # assign end-of-line to exit

    ##################################################

    # def do_input(self, s):
    #     if s=='':
    #         s = input('Your name please: ')
    #     print('Hello', s)

################################################################################
# Handle exceptions within console (print traceback)
################################################################################

def handle(exception):
    print(exception)
    track = traceback.format_exc()
    print(track)

################################################################################
# Main
################################################################################

if __name__ == '__main__':
    console = Console().cmdloop()
