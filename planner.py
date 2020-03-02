import os
import re
import time
import glob
import subprocess
from dotenv import load_dotenv

################################################################################
# Envionment imports (Nessus scan report CSV location)
################################################################################

load_dotenv()
JAVAFF_DOMAIN_PATH = os.getenv('JAVAFF_DOMAIN_PATH')
JAVAFF_PROBLEM_PATH = os.getenv('JAVAFF_PROBLEM_PATH')
JAVAFF_PLAN_PATH = os.getenv('JAVAFF_PLAN_PATH')
JAVAFF_DIR = os.getenv('JAVAFF_DIR')

################################################################################
# Planner class, avaliable for executing JavaFF searches
################################################################################

class Planner(object):
    """
    Launches JavaFF planner as a subprocess.
    """
    def start_service(self):
        """
        Starts an os subprocess to start JavaFF.
        """
        shell_cmd = "./run.sh "
        shell_cmd += JAVAFF_DOMAIN_PATH + " "
        shell_cmd += JAVAFF_PROBLEM_PATH + " "
        shell_cmd += JAVAFF_PLAN_PATH
        process = subprocess.Popen(shell_cmd,                 \
                                   cwd=JAVAFF_DIR,            \
                                   universal_newlines = True, \
                                   stdout = subprocess.PIPE,  \
                                   stderr = subprocess.PIPE,  \
                                   shell=True,                \
                                   bufsize=0)
        process.wait()
        out, err = process.communicate()
        if not err:
            print("[+] working")
            print(out)
            return True
        else:
            print("[!] Error: not working ")


################################################################################
# Main
################################################################################

if __name__ == '__main__':
    planner = Planner()
    planner.start_service()
