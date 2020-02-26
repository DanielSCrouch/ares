import subprocess
import time
import os
from threading import Thread
from dotenv import load_dotenv

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
# Nessus setup
################################################################################

class Nessus(object):
    """
    Nessus class with start and stop service functions.
    Service runs outside of subprocess, i.e subprocess completes on start.
    """
    def start_service(self):
        """
        Starts an os subprocess to start Nessus server.
        """
        command = ["./nessusd start"]
        process = subprocess.Popen(command,                   \
                                   cwd="/etc/init.d/",        \
                                   stdin = subprocess.PIPE,   \
                                   stdout = subprocess.PIPE,  \
                                   stderr = subprocess.PIPE,  \
                                   universal_newlines = True, \
                                   shell=True,                \
                                   bufsize=0)
        # check for exception errors (startup not successful)
        for line in process.stderr:
            if 'complete' not in line and 'already running' not in line:
                raise Exception(line.strip())
                return False
        return True

    def stop_service(self):
        """
        Stops Nessus server.
        """
        command = ["./nessusd stop"]
        process = subprocess.Popen(command,                   \
                                   cwd="/etc/init.d/",        \
                                   stdin = subprocess.PIPE,   \
                                   stdout = subprocess.PIPE,  \
                                   stderr = subprocess.PIPE,  \
                                   universal_newlines = True, \
                                   shell=True,                \
                                   bufsize=0)
        # for line in process.stdout:
        #     print(line.strip())
        for line in process.stderr:
            raise Exception(line.strip())
            return False
        return True

################################################################################
# Nessus setup
################################################################################

class MsfRpc(object):
    """
    MsfRpc class with start and stop service functions.
    Service runs while subprocess is active.
    """
    def __init__(self):
        self.process = None
        self.polling = False

    def start_service(self):
        """
        Starts an os subprocess to run metasploit console, then
        starts MsfRPC service.
        """
        command = ["msfconsole"]
        self.process = subprocess.Popen(command,              \
                                   stdin = subprocess.PIPE,   \
                                   stdout = subprocess.PIPE,  \
                                   stderr = subprocess.PIPE,  \
                                   universal_newlines = True, \
                                   shell=True,                \
                                   bufsize=2048)
        time.sleep(10)
        cmd = "load msgrpc"
        cmd += " ServerHost=" + MSF_SERVER
        cmd += " ServerPort=" + MSF_PORT
        cmd += " Pass=" + MSF_PASSWORD
        cmd += " User=" + MSF_USER
        cmd += " \n"
        # print("[+] Logining into Msf Rpc as ", MSF_USER)
        self.process.stdin.write(cmd)
        self.process.stdin.flush()
        # self.process.stdin.close()
        # out, err = self.process.communicate()
        # print(out)
        Thread(target=self.poll_server).start()
        # return True if service has started
        # self.process.wait(timeout=0.2)
        return True

    def stop_service(self):
        """
        Stops metaploit console.
        """
        # stop polling service
        self.polling = False
        # exit msfconsole
        self.process.stdin.write("exit \n")
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
