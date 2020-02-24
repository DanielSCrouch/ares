import subprocess
import time
from threading import Thread


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
                                   bufsize=0)
        # check for exception errors
        for line in self.process.stderr:
            raise Exception(line.strip())
        print('here')
        # start msgrpc service
        cmd = "load msgrpc ServerHost=10.91.251.100 ServerPort=55553 Pass=kings123 User=msf"
        self.process.stdin.write()
        # check for exception errors
        for line in self.process.stderr:
            raise Exception(line.strip())
        # raise exception error if service stops
        Thread(self.poll_server).start()
        # return True if service has started
        return True

    def stop_service(self):
        """
        Stops Nessus server.
        """
        # stop polling service
        self.polling = False
        # exit msfconsole
        self.process.stdin.write("exit \n")
        self.process.stdin.close()
        # check for exception errors
        for line in process.stderr:
            raise Exception(line.strip())
            return False
        # return True if service has stopped
        return True

    def poll_server(self):
        """
        Polls msfconsole process, raises exception error if down.
        """
        self.polling = True
        while(self.polling):
            print("polling")
            returncode = self.process.poll()
            if returncode is not None:
                self.polling = False
                raise Error(returncode)
            time.sleep(1)

            for line in self.process.stdout:
                print(line.strip())


# nessus = Nessus()
# print(nessus.start_service())
# print(nessus.stop_service())
# print(nessus.start_service())

msf = MsfRpc()
msf.start_service()
