
import os
from cmd import Cmd



class Console(Cmd):
    prompt = ">>> "
    intro = "\n\n         |     '||''|.   '||''''|   .|'''.|  \n        |||     ||   ||   ||  .     ||..  '  \n       |  ||    ||''|'    ||''|      ''|||.  \n      .''''|.   ||   |.   ||       .     '|| \n     .|.  .||. .||.  '|' .||.....| |'....|'  \n     \n     Automated  Recon  &  Exploit  Software\n\n"
    COLOURS = ['red', 'blue', 'green']
    LAST_COMMAND = ''

    def precmd(self, cmd):
        return Cmd.precmd(self, cmd)

    def do_add(self, s):
        l = s.split()
        if len(l) != 2:
            print("*** invalid number of arguments")
            return
        try:
            l = [int(i) for i in l]
        except:
            print("*** arguments should be numbers")
            return
        print(l[0] +l[1])

    def complete_add(self, text, line, begidx, endidx):
        if not text:
            try:
                colours = self.COLOURS[:]
            except Exception as e:
                print(e)
        else:
            colours =      ([i \
                           for i in self.COLOURS \
                           if i.startswith(text)])
        return colours

    def default(self, s):
        if s == 'q':
            return self.do_exit(s)

    def do_shell(self, cmd):
        """
        run a shell command
        """
        print("[+] Running a shell command")
        output = os.popen(cmd).read()
        print(output)

    def do_msf(self, s):
        msf = MsfConsole()
        msf.prompt = 'msf' + self.prompt
        msf.cmdloop()

    def do_input(self, s):
        if s=='':
            s = input('Your name please: ')
        print('Hello', s)

    def do_exit(self, s):
        """
        exit the application
        """
        print("[+] Closing application.\n")
        return True

    do_EOF = do_exit

class MsfConsole(Cmd):
    intro = "\n\n     **************************************************\n"
    intro +=    "     ********* AUTOMATED PENETRATION TESTING **********\n"
    COLOURS = ['red', 'blue', 'green']
    LAST_COMMAND = ''

    def do_show(self, s):
        print('running msf')

    def do_back(self, s):
        """
        exit the application
        """
        print("[+] Closing application.\n")
        return True


if __name__ == '__main__':
    Console().cmdloop()
