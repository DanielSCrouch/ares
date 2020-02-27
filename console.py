
import os
from cmd import Cmd
#
from plugins import Nessus, Metaploit
from msfrpc import MsfClient, MsfConsole
from database import Database
# from pymeta import Database


class Console(Cmd):
    prompt = ">>> "
    intro = "\n\n            |     '||''|.   '||''''|   .|'''.|  \n           |||     ||   ||   ||  .     ||..  '  \n          |  ||    ||''|'    ||''|      ''|||.  \n         .''''|.   ||   |.   ||       .     '|| \n        .|.  .||. .||.  '|' .||.....| |'....|'  \n        \n        Automated  Recon  &  Exploit  Software\n\n"
    #
    plugins = {'nessus': None, 'metaploit': None}
    services = {'msfconsole': None, 'database': None, 'planner': None}
    msfclient = None
    #
    COLOURS = ['red', 'blue', 'green']

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
        if cmds[0] == 'metaploit':
            print("[*] loading Metasploit plugin")
            try:
                self.plugins['metaploit'] = Metaploit()
            except Exception as e:
                print('[!] Error: ', e)
                return
            try:
                self.plugins['metaploit'].start_service()
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

    def do_create(self, cmd):
        """
        Create services avaliable to console.
        Options: msfconsole, database, planner
        """
        cmds = cmd.split()
        if len(cmds) != 1:
            print("*** invalid number of arguments")
            return
        if cmds[0] not in self.services.keys():
            print("*** invalid create option, see 'help create'")
            return
        # Metasploit Console
        if cmds[0] == 'msfconsole':
            if self.plugins['metaploit'] is None:
                print("[!] Metaplsoit has not been loaded, see 'help load'")
                return
            try:
                self.msfclient = MsfClient()
                print("[*] athenticating Metaploit RPC user login")
                self.msfclient.login()
                print("[+] Metasploit RPC athenticating successful")
            except Exception as e:
                print("[!] Error: ", e)
                print("[!] Recommendation: run app from new console as root'")
                return
            try:
                self.services['msfconsole'] = MsfConsole(self.msfclient)
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

    def complete_create(self, text, line, begidx, endidx):
        if not text:
            try:
                services = list(self.services.keys())
            except Exception as e:
                print(e)
        else:
            services = ([s for s in self.services.keys() if s.startswith(text)])
        return services

    def do_msf(self, cmd):
        msf = self.services['msfconsole']
        msf.prompt = 'msf' + self.prompt
        msf.cmdloop()

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

    def do_input(self, s):
        if s=='':
            s = input('Your name please: ')
        print('Hello', s)


################################################################################
# Main
################################################################################

if __name__ == '__main__':
    Console().cmdloop()
