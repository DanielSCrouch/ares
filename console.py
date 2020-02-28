
import os
from cmd import Cmd
#
from plugins import Nessus, Metasploit
from msfrpc import MsfClient, MsfConsole
from database import Database
from registrar import Registrar
# from pymeta import Database

################################################################################
# Main ARES Console
################################################################################

class Console(Cmd):
    prompt = ">>> "
    intro = "\n\n            |     '||''|.   '||''''|   .|'''.|  \n           |||     ||   ||   ||  .     ||..  '  \n          |  ||    ||''|'    ||''|      ''|||.  \n         .''''|.   ||   |.   ||       .     '|| \n        .|.  .||. .||.  '|' .||.....| |'....|'  \n        \n        Automated  Recon  &  Exploit  Software\n\n"
    #
    registrar = Registrar()
    plugins = {'nessus': None, 'metasploit': None}
    services = {'msfconsole': None, 'database': None, 'planner': None}
    msfclient = None
    scans = {'Basic_Scan': "nessus_scans_tmp/Basic_Network_Scan_Custom.csv"} # name: path

    def do_load(self, cmd):
        """
        Load plugin services into console.
        Options: nessus, metasploit
        """
        cmds = cmd.split()
        if len(cmds) != 1:
            print("*** invalid number of arguments")
            return
        if cmds[0] not in self.plugins.keys():
            print("*** invalid service option, see 'help load'")
            return
        # Nessus
        if cmds[0] == 'nessus':
            print("[*] loading Nessus plugin")
            try:
                self.plugins['nessus'] = Nessus()
            except Exception as e:
                print('[!] Error: ', e)
                return
            try:
                self.plugins['nessus'].start_service()
            except Exception as e:
                print('[!] Error: ', e)
                return
            print("[+] Nessus plugin loaded")
            return
        # Metasploit
        if cmds[0] == 'metasploit':
            print("[*] loading Metasploit plugin")
            try:
                self.plugins['metasploit'] = Metasploit()
            except Exception as e:
                print('[!] Error: ', e)
                return
            try:
                self.plugins['metasploit'].start_service()
            except Exception as e:
                print('[!] Error: ', e)
                return
            print("[+] Metasploit plugin loaded")
            return

    def complete_load(self, text, line, begidx, endidx):
        if not text:
            try:
                plugins = list(self.plugins.keys())
            except Exception as e:
                print(e)
        else:
            plugins = ([p for p in self.plugins.keys() if p.startswith(text)])
        return plugins

    def do_start(self, cmd):
        """
        Start services avaliable to console.
        Services: msfconsole, database, planner
        """
        cmds = cmd.split()
        if len(cmds) != 1:
            print("*** invalid number of arguments")
            return
        if cmds[0] not in self.services.keys():
            print("*** invalid sreate option, see 'help sreate'")
            return
        # Metasploit Console
        if cmds[0] == 'msfconsole':
            if self.plugins['metasploit'] is None:
                print("[!] Metasplsoit has not been loaded, see 'help load'")
                return
            try:
                self.msfclient = MsfClient()
                print("[*] athenticating Metasploit RPC user login")
                self.msfclient.login()
                print("[+] Metasploit RPC athenticating successful")
            except Exception as e:
                print("[!] Error: ", e)
                print("[!] Recommendation: run app from new console as root'")
                return
            try:
                self.services['msfconsole'] = MsfConsole(self.msfclient,
                                                         self.registrar)
            except Exception as e:
                print('[!] Error: ', e)
                return
            print("[+] Metasploit console avaliable, see 'help msf'")
            return
        # Database
        if cmds[0] == 'database':
            try:
                self.services['database'] = Database()
            except Exception as e:
                print('[!] Error: ', e)
                return
            print("[+] target database avaliable")
            return
        # Planner
        if cmds[0] == 'planner':
            try:
                self.services['planner'] = Planner()
            except Exception as e:
                print('[!] Error: ', e)
                return
            print("[+] planner now avaliable")
            return

    def complete_start(self, text, line, begidx, endidx):
        if not text:
            try:
                services = list(self.services.keys())
            except Exception as e:
                print(e)
        else:
            services = ([s for s in self.services.keys() if s.startswith(text)])
        return services

    def do_msf(self, cmd):
        """
        Open msf console service.
        """
        if self.services['msfconsole'] is None:
            print("[!] msfconsole service has not been started, see 'help start'")
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
            print("[!] database service has not been startd, see 'help start'")
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
                print('[!] Error: ', e)
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
            print("[!] database service has not been startd, see 'help start'")
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
            print("[!] database service has not been startd, see 'help start'")
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
