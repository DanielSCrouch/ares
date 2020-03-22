
import os
import re
import time
import traceback
from cmd import Cmd

# local imports
import config


################################################################################
# Main ARES Console
################################################################################

class Console(Cmd):
    prompt = ">>> "
    with open('misc/intro.txt', 'r') as f:
        intro = f.read()

    def __init__(self):
        super(Console, self).__init__()
        # config.COMMANDS.target('bruce', '192.168.1.190')
        # config.COMMANDS.target('nigel', '192.168.1.191')
        # config.COMMANDS.scan_import('full', 'bruce')

    ############################################
    # start
    ############################################

    def do_setup(self, cmd):
        """
        Setup services avaliable to console.
        """
        # console hook
        config.CONSOLE = self
        # command validation
        cmds = cmd.split()
        if len(cmds) != 1:
            print("*** invalid number of arguments")
            return
        # command execution
        try:
            print("[*] loading PostgreSQL plugin")
            config.DATABASE.start_service()
            print("[+] PostgreSQL database now avaliable")
            print("[*] loading Metasploit plugin")
            config.METASPLOIT.start_service()
            print("[+] Metasploit now avaliable")
            print("[*] loading Nessus plugin")
            config.NESSUS.start_service()
            print("[+] Nessus now avaliable")
            print("[*] logging into Metasploit via RPC")
            config.MSFCLIENT.login()
            print("[+] Metasploit client login successfull")
            print("[*] connecting msf console to Metasploit client")
            config.MSFCONSOLE.connect(config.MSFCLIENT)
            print("[+] msf console now avaliable, see 'help msf'")
            print("[*] connecting msf commmand tool to msf console")
            config.MSFCOMMANDS.connect_nessus()
            print("[+] Nessus now avaliable to msf")
            print("[*] connecting Metasploit to database")
            config.MSFCOMMANDS.connect_database()
            print("[+] Metasploit connected to database")
            print("[+] setting up msf workspace")
            config.MSFCOMMANDS.set_workspace('default')
            print("[*] setup complete")
        except Exception as e:
            handle(e)

    ############################################
    # scan
    ############################################

    def do_scan(self, cmd):
        """
        Scan hosts.
        Options: host, port, full
        """
        # command validation
        cmds = cmd.split()
        if len(cmds) != 2:
            print("*** invalid number of arguments, see 'help scan'")
            return
        scan_type = cmds[0].strip()
        target_name = cmds[1].strip()
        try:
            if scan_type == 'host':
                config.RECON.host_scan(target_name, verbose=True)
            if scan_type == 'port':
                config.RECON.port_scan(scan_type, target_name, verbose=False)
            if scan_type == 'full':
                config.RECON.full_scan(scan_type, target_name, verbose=False)

        except Exception as e:
            handle(e)

    def complete_scan(self, text, line, begidx, endidx):
        options = ['host', 'port', 'full']
        if text:
            scan_opts = ([o for o in options if o.startswith(text)])
        return scan_opts

    ############################################
    # target
    ############################################

    def do_target(self, cmd):
        """
        Target host as the ip address.
        """
        # command validation
        cmds = cmd.split()
        if len(cmds) != 2:
            print("*** invalid number of arguments, see 'target'")
            return
        if not config.COMMANDS.validip(cmds[1]):
            print("*** invalid IP address")
            return
        name = cmds[0]
        ip = cmds[1]
        # command execution
        try:
            config.COMMANDS.target(name, ip, verbose=True)
        except Exception as e:
            handle(e)

    ############################################
    # show
    ############################################

    def do_show(self, cmd):
        """
        Show target attributes
        - Options:
        """
        # Command validation
        cmds = cmd.split()

        # Command execution
        try:
            if cmds[0] == 'targets':
                config.COMMANDS.show_targets()
            if cmds[0] == 'target':
                config.COMMANDS.show_target(cmds[1])
            if cmds[0] == 'vulns':
                config.COMMANDS.show_vulns(cmds[1])
        except Exception as e:
            handle(e)

    ############################################
    # import
    ############################################

    def do_import(self, cmd):
        """
        Import a scan to a targeted host.
        Options: full, target name
        """
        # command validation
        cmds = cmd.split()
        if len(cmds) != 2:
            print("*** invalid number of arguments, see 'help scan'")
            return
        scan_type = cmds[0].strip()
        target_name = cmds[1].strip()
        if scan_type not in ['port', 'full']:
            print("*** invalid scan name, see 'help scan'")
            return
        if target_name not in config.TARGETS.keys():
            print("*** target not known")
            return
        # command execution
        try:
            config.COMMANDS.scan_import(scan_type, target_name)
        except Exception as e:
            handle(e)

    def complete_import(self, text, line, begidx, endidx):
        options = ['full']
        if text:
            scan_opts = ([o for o in options if o.startswith(text)])
        return scan_opts

    ############################################
    # metasploit
    ############################################

    def do_msf(self, cmd):
        """
        Open msf console.
        """
        # command validation
        cmds = cmd.split()
        if len(cmds) != 0 and len(cmds) != 1:
            print("*** invalid argument")
            return
        # command execution
        if len(cmds) == 1:
            cmd = cmds[0]
        try:
            if cmd and cmd == 'busy':
                print(config.MSFCONSOLE.check_busy())
            else:
                config.MSFCONSOLE.open_console()
        except Exception as e:
            handle(e)

    ############################################
    # shell
    ############################################

    def do_shell(self, cmd):
        """
        run a shell command.
        """
        try:
            config.COMMANDS.shell(cmd)
        except Exception as e:
            handle(e)

    ############################################
    # plan
    ############################################

    def do_plan(self, cmd):
        """
        execute planner.
        """
        try:
            config.COMMANDS.plan(verbose=True)
        except Exception as e:
            handle(e)

    ############################################
    # exploit
    ############################################

    def do_exploit(self, cmd):
        """
        run exploit
        """
        # command validation
        cmds = cmd.split()
        # if len(cmds) != 2:
        #     print("*** invalid number of arguments")
        #     return
        exploit = cmds[0]
        target_name = cmds[1]
        if len(cmds) == 3:
            target_name2 = cmds[2]
        # command execution
        try:
            if exploit == 'cve-2008-4250':
                config.INITIALACCESS.exploit_cve_2008_4250(target_name)
            if exploit == 'msql-brute-force':
                config.INITIALACCESS.exploit_msql_brute_force(target_name)
            if exploit == 'tokens':
                config.PRIVILEDGEESC.exploit_tokens(target_name)
            if exploit == 'cve-2011-2005':
                config.PRIVILEDGEESC.exploit_cve_2011_2005(target_name)
            if exploit == 'hashdump':
                config.PRIVILEDGEESC.exploit_hashdump(target_name)
            if exploit == 'psexec':
                config.TRAVERSAL.exploit_psexec(target_name, target_name2)
            else:
                pass
        except Exception as e:
            handle(e)

    def complete_exploit(self, text, line, begidx, endidx):
        options = ['cve-2008-4250', 'msql-brute-force', 'tokens', 'cve-2011-2005']
        if text:
            scan_opts = ([o for o in options if o.startswith(text)])
        return scan_opts

    ############################################
    # generic console commands
    ############################################

    def default(self, cmd):
        if cmd == 'q':
            return self.do_cexit(cmd)
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

    def do_cexit(self, cmd):
        """
        exit the application
        """
        try:
            config.COMMANDS.exit()
        except Exception as e:
            handle(e)
        return True

    do_EOF = do_cexit # assign end-of-line to exit

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
