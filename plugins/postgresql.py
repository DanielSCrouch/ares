

import time
import os
from threading import Thread
from dotenv import load_dotenv
import subprocess

# Has to be run from sudo

################################################################################
# PostgreSQL service start
################################################################################

class PostgreSQL(object):
    """
    Launches PostgreSQL application as a subprocess.
    """
    def start_service(self):
        """
        Starts an os subprocess to start PostgreSQL server.
        """
        # postgresql from service command
        command = ["service postgresql start"]
        process = subprocess.Popen(command,                   \
                                   stdin = subprocess.PIPE,   \
                                   stdout = subprocess.PIPE,  \
                                   stderr = subprocess.PIPE,  \
                                   universal_newlines = True, \
                                   shell=True,                \
                                   bufsize=0)
        process.wait(timeout=10)
        error_stream = process.stderr
        error = error_stream.read()
        output_stream = process.stdout
        output = output_stream.read()
        if error or output:
            raise Exception("error starting PostgreSQL")
        # check service is active
        command = ["service postgresql status"]
        process = subprocess.Popen(command,                   \
                                   stdin = subprocess.PIPE,   \
                                   stdout = subprocess.PIPE,  \
                                   stderr = subprocess.PIPE,  \
                                   universal_newlines = True, \
                                   shell=True,                \
                                   bufsize=0)
        process.wait(timeout=1)
        for line in process.stdout:
            if '(dead)' in line:
                raise Exception("error starting PostgreSQL")
                return False
            if '(exited)' in line:
                return True
        raise Exception("unexpected response from service call")
        return False

    def stop_service(self):
        """
        Stops PostgreSQL server.
        """
        command = ["service postgresql start"]
        process = subprocess.Popen(command,                   \
                                   stdin = subprocess.PIPE,   \
                                   stdout = subprocess.PIPE,  \
                                   stderr = subprocess.PIPE,  \
                                   universal_newlines = True, \
                                   shell=True,                \
                                   bufsize=0)
        for line in process.stderr:
            raise Exception(line.strip())
            return False
        return True

################################################################################
# Main
################################################################################

if __name__ == '__main__':
    # postgresql = PostgreSQL()
    # postgresql.start_service()
    pass


















#
