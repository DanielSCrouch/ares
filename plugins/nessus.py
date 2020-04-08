# Module to provide Nessus plugin support (start/stop service)
#
# Author: Daniel Crouch
# Date created: March 2020

import time
import os
from threading import Thread
from dotenv import load_dotenv
import subprocess

# Has to be run from sudo

################################################################################
# Nessus setup
################################################################################

class Nessus(object):
    """
    Launches a Nessus application as a subprocess.
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
        process.wait(timeout=10)
        for line in process.stderr:
            raise Exception(line.strip())
            return False
        return True

################################################################################
# Main
################################################################################

if __name__ == '__main__':
    # nessus = Nessus()
    # nessus.start_service()
    pass


















#
