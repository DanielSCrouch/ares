
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
        Cmd.__init__(self)
        # console hook
        config.CONSOLE = self

    ############################################
    # start
    ############################################

    def do_setup(self, cmd):
        """
        Setup services avaliable to console.
        """
        # command validation
        cmds = cmd.split()
        if len(cmds) != 0:
            print("*** invalid number of arguments")
            return
        # command execution
        try:
            config.COMMANDS.setup()
        except Exception as e:
            handle(e)

    ############################################
    # scan
    ############################################

    def do_scan(self, cmd):
        """
        Scan a network or targetted host
        Options:
        - scan hosts "ip range"
        - scan port "target name"
        - scan full "target name"
        """
        # command validation
        cmds = cmd.split()
        if len(cmds) != 2:
            print("*** invalid number of arguments, see 'help scan'")
            return
        scan_type = cmds[0].strip()
        target_name = cmds[1].strip()
        try:
            if scan_type == 'hosts':
                config.RECON.host_scan(target_name, verbose=True)
            if scan_type == 'ports':
                config.RECON.port_scan('port', target_name, verbose=False)
            if scan_type == 'full':
                config.RECON.full_scan('full', target_name, verbose=False)

        except Exception as e:
            handle(e)

    def complete_scan(self, text, line, begidx, endidx):
        options = ['hosts', 'ports', 'full']
        if text:
            scan_opts = ([o for o in options if o.startswith(text)])
        return scan_opts

    ############################################
    # target
    ############################################

    def do_target(self, cmd):
        """
        Target a host on the network
        Options:
        - target "target name" "ip address"
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
        Options:
        - show targets
        - show target "target name"
        - show vulns "target name"
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
        Import a scan to a targeted host
        Options:
        - import port "target name"
        - import full "target name"
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
        Open msf console
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
        Run a shell command
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
        Run AI Planner
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
        Execute an exploit against a target
        Options:
        - exploit cve-2008-4250 "target name"
        - exploit msql-brute-force "target name"
        - exploit tokens "target name"
        - exploit cve-2011-2005 "target name"
        - exploit hashdump "target name"
        - exploit psexec "target name"
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
        options = ['cve-2008-4250', 'msql-brute-force', 'tokens', \
                        'cve-2011-2005', 'hashdump', 'psexec']
        if text:
            scan_opts = ([o for o in options if o.startswith(text)])
        return scan_opts

    ############################################
    # generic console commands
    ############################################

    def default(self, cmd):
        """
        Default console commands. Runs as python executable if unmatched
        """
        if cmd == 'q':
            return self.do_cexit(cmd)
        if cmd == 's':
            self.do_setup('')
        else:
            try:
                exec(cmd)
            except Exception as e:
                handle(e)
        # print("*** Unknown Command, see 'help'")

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

    ############################################
    # testing
    ############################################

    def do_test(self, cmd):
        """
        Unit tests
        Options:
        - test 1    : setup
        - test 2    : live host scan
        - test 3    : host targetting
        - test 4    : port scan
        - test 5    : import scan (port and full)
        - test 6    : planning (initial access)
        """
        try:
            config.TESTS.test(cmd)
        except Exception as e:
            handle(e)

    ##################################################

################################################################################
# Handle exceptions within console (print traceback)
################################################################################

def handle(exception):
    print("[!] Exception Error")
    print(exception)
    track = traceback.format_exc()
    print(track)

################################################################################
# Main
################################################################################

if __name__ == '__main__':
    console = Console().cmdloop()
