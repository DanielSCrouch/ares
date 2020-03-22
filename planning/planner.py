import os
import re
import time
import glob
import subprocess
from pathlib import Path
from dotenv import load_dotenv

################################################################################
# Envionment imports (Nessus scan report CSV location)
################################################################################

load_dotenv()
METRIC_FF_DIR = os.getenv('METRIC_FF_DIR')
PDDL_MODEL_DIR = os.getenv('PDDL_MODEL_DIR')
PDDL_DOMAIN_FILE = os.getenv('PDDL_DOMAIN_FILE')
PDDL_PROBLEM_FILE = os.getenv('PDDL_PROBLEM_FILE')

################################################################################
# Planner class, avaliable for executing JavaFF searches
################################################################################

class Planner(object):
    """
    Launches JavaFF planner as a subprocess.
    """

    def run(self):
        """
        Starts an os subprocess to start JavaFF.
        """
        shell_cmd = "./ff "
        shell_cmd += "-p " + PDDL_MODEL_DIR + " "
        shell_cmd += "-o " + PDDL_DOMAIN_FILE + " "
        shell_cmd += "-f " + PDDL_PROBLEM_FILE
        process = subprocess.Popen(shell_cmd,                 \
                                   cwd=METRIC_FF_DIR,         \
                                   universal_newlines = True, \
                                   stdout = subprocess.PIPE,  \
                                   stderr = subprocess.PIPE,  \
                                   shell=True,                \
                                   bufsize=0)
        process.wait(5)
        out, err = process.communicate()
        if not err:
            print("[+] planner run, see output")
            outpath = Path.cwd() / 'planning' / 'pddl_files' / 'plan.txt'
            outpath.write_text(out)
            return True
        else:
            print("[!] Error: ", err)








################################################################################
# Main
################################################################################

if __name__ == '__main__':
    planner = Planner()
    planner.run()
    # planner.generate_problem()
