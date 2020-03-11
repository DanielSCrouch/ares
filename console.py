
import os
import re
import time
import traceback
from cmd import Cmd

# local imports
import config
from modelling.target import Target

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
            config.DATABASE.start_service()
            print("[*] PostgreSQL database now avaliable")
            print("[*] loading Metasploit plugin")
            config.METASPLOIT.start_service()
            print("[*] Metasploit now avaliable")
            print("[*] loading Nessus plugin")
            config.NESSUS.start_service()
            print("[*] Nessus now avaliable")
            print("[*] logging into Metasploit via RPC")
            config.MSFCLIENT.login()
            print("[*] Metasploit client login successfull")
            print("[*] connecting msf console to Metasploit client")
            config.MSFCONSOLE.connect(config.MSFCLIENT)
            print("[*] msf console now avaliable, see 'help msf'")
            print("[*] connecting msf commmand tool to msf console")
            config.MSFCOMMANDS.connect(config.MSFCONSOLE)
            print("[*] msf automated commands now avaliable")
            print("[*] connecting Metasploit to Nessus")
            config.MSFCOMMANDS.connect_nessus()
            print("[*] Nessus now avaliable to msf")
            print("[*] connecting Metasploit to database")
            config.MSFCOMMANDS.connect_database()
            print("[+] Metasploit connected to database")
            print("[+] setting up msf workspace")
            config.MSFCOMMANDS.set_workspace('default')
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
        # command validation
        cmds = cmd.split()
        if len(cmds) != 0:
            print("*** invalid argument")
            return
        # command execution
        try:
            config.MSFCONSOLE.prompt = 'msf' + self.prompt
            config.MSFCONSOLE.cmdloop()
        except Exception as e:
            handle(e)

    ############################################
    # add target
    ############################################

    def do_target(self, cmd):
        """
        Set create a target as the specificed IP address.
        """
        # command validation
        cmds = cmd.split()
        if len(cmds) != 2:
            print("*** invalid number of arguments, see 'target'")
            return
        if not config.COMMANDS.validip(cmds[1]):
            print("*** invalid IP address")
            return
        target_name = cmds[0]
        target_ip = cmds[1]
        # command execution
        config.TARGETS[target_name] = Target(target_ip)

    ############################################
    # Scan a target
    ############################################

    def do_scan(self, cmd):
        """
        Scan a targeted host.
        Options:
        - host, os, full
        - target name
        """
        # command validation
        cmds = cmd.split()
        if len(cmds) != 2:
            print("*** invalid number of arguments, see 'help scan'")
            return
        scan_type = cmds[0].strip()
        target_name = cmds[1].strip()
        if scan_type not in ['host', 'os', 'full']:
            print("*** invalid scan name, see 'help scan'")
        if target_name not in config.TARGETS.keys():
            print("*** target not known")
        # command execution
        try:
            config.COMMANDS.scan(target_name, scan_type)
        except Exception as e:
            handle(e)


    def complete_scan(self, text, line, begidx, endidx):
        options = ['host', 'os', 'full']
        if text:
            scan_opts = ([o for o in options if o.startswith(text)])
        return scan_opts

    ############################################
    # show target info
    ############################################

    def do_show(self, cmd):
        """
        Display environment data.
        - Options:
        """
        # Command validation
        cmds = cmd.split()
        if len(cmds) == 1 and cmds[0] not in ['policies', 'scans', 'targets']:
            print("*** invalid arguments, see 'help show'")
            return
        # Command execution
        try:
            if cmds[0] == 'policies':
                config.MSFCOMMANDS.show_scan_policies()
            if cmds[0] == 'scans':
                config.COMMANDS.show_scan_names()
            if cmds[0] == 'targets':
                config.COMMANDS.show_targets()
            if cmds[0] == 'target':
                config.COMMANDS.show_target(cmds[1])
        except Exception as e:
            handle(e)

    ############################################
    # shell console
    ############################################

    def do_shell(self, cmd):
        """
        run a shell command
        """
        print("[+] Running a shell command")
        output = os.popen(cmd).read()
        print(output)

    ############################################
    # generic console commands
    ############################################

    def default(self, cmd):
        if cmd == 'q':
            return self.do_exit(cmd)
        if cmd == 's':
            self.do_setup(cmd)
        else:
            try:
                exec(cmd)
            except Exception as e:
                handle(e)
        # print("*** Unknown Command, see 'help'")

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
            config.COMMANDS.exit()
        except Exception as e:
            handle(e)
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
