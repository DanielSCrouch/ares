# Module to provide Metasploit plugin support (start/stop service)
#
# Author: Daniel Crouch
# Date created: March 2020

import time
import os
from threading import Thread
from dotenv import load_dotenv
import subprocess
import config

# Has to be run from sudo

################################################################################
# Envionment imports (Set msf server login details)
################################################################################

load_dotenv()
MSF_SERVER = os.getenv('MSF_SERVER')
MSF_PORT = os.getenv('MSF_PORT')
MSF_USER = os.getenv('MSF_USER')
MSF_PASSWORD = os.getenv('MSF_PASSWORD')

################################################################################
# Launch Metasploit and msfrpc
################################################################################

class Metasploit(object):
    """
    Launches a Metasploit application as a subprocess.
    """
    def __init__(self):
        self.process = None
        self.polling = False # check if subprocess has died
        self.running = False

    def start_service(self):
        """
        Starts an os subprocess to run metasploit console,
        then starts MsfRPC service.
        """
        command = ["msfconsole"]
        self.process = subprocess.Popen(command,              \
                                   stdin = subprocess.PIPE,   \
                                   stdout = subprocess.PIPE,  \
                                   stderr = subprocess.PIPE,  \
                                   universal_newlines = True, \
                                   shell=True,                \
                                   bufsize=0)
        config.LOADING = True
        time.sleep(12)
        config.LOADING = False

        cmd = "load msgrpc"
        cmd += " ServerHost=" + MSF_SERVER
        cmd += " ServerPort=" + MSF_PORT
        cmd += " Pass=" + MSF_PASSWORD
        cmd += " User=" + MSF_USER
        cmd += " \n"
        self.process.stdin.write(cmd)
        self.process.stdin.flush()

        time.sleep(4)

        Thread(target=self.poll_server).start()
        return True

    def stop_service(self):
        """
        Stops metasploit console.
        """
        # stop polling service
        self.polling = False
        time.sleep(1)
        # exit msfconsole
        self.process.stdin.write("\n exit \n")
        self.process.stdin.flush()
        self.process.stdin.close()
        self.process.terminate()
        self.process.wait(timeout=0.2)
        # return True if service has stopped
        return True

    def poll_server(self):
        """
        Polls msfconsole process, raises exception error if down.
        """
        self.polling = True
        while(self.polling):
            returncode = self.process.poll()
            if returncode is not None:
                self.polling = False
                raise Exception(returncode)
            time.sleep(0.1)

################################################################################
# Main
################################################################################

if __name__ == '__main__':
    # metasploit = Metasploit()
    # metasploit.start_service()
    pass


















#
