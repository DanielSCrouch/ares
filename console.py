
import os
from cmd import Cmd
from dotenv import load_dotenv

################################################################################
# Local import
################################################################################

from plugins import Nessus, Metasploit
from msfrpc import MsfClient, MsfConsole
from database import Database
from registrar import Registrar
# from pymeta import Database

################################################################################
# Envionment variable imports (API Keys etc)
################################################################################

load_dotenv()
NESSUS_USERNAME = os.getenv('NESSUS_USERNAME')
NESSUS_PASSWORD = os.getenv('NESSUS_PASSWORD')
NESSUS_HOST = os.getenv('NESSUS_HOST')
NESSUS_PORT = os.getenv('NESSUS_PORT')
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
    scans = {'Basic_Scan': "nessus_scans_tmp/Basic_Network_Scan_Custom.csv"} # name: path

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
                print("[*] connecting to database")
                self.services['database'] = Database()
            except Exception as e:
                print('[!] Error1: ', e)
            print("[+] target database avaliable")

        # Planner

        if self.services['planner'] is None:
            try:
                print("[*] connecting to planner")
                self.services['planner'] = Planner()
            except Exception as e:
                print('[!] Error2: ', e)
            print("[+] planner now avaliable")

        # Metasploit Plugin

        if self.services['metasploit'] is None:
            try:
                print("[*] loading Metasploit plugin")
                self.services['metasploit'] = Metasploit()
            except Exception as e:
                print('[!] Error3: ', e)
            try:
                self.services['metasploit'].start_service()
            except Exception as e:
                print('[!] Error4: ', e)
            print("[+] Metasploit plugin loaded")

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
            except Exception as e:
                print('[!] Error6: ', e)
            print("[+] Metasploit console avaliable, see 'help msf'")

        # Nessus

        if self.services['nessus'] is None:
            try:
                print("[*] loading Nessus plugin")
                self.services['nessus'] = Nessus()
            except Exception as e:
                print('[!] Error7: ', e)
            try:
                self.services['nessus'].start_service()
            except Exception as e:
                print('[!] Error8: ', e)
            print("[+] Nessus plugin loaded")

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
    Console().cmdloop()
