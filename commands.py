# Extension of console.py module
# Provides additional functions/commands to console


import os
import re
import glob
import time
import subprocess
from dotenv import load_dotenv

################################################################################
# Envionment imports (Set msf server login details)
################################################################################

load_dotenv()
NESSUS_DEF_DIR = os.getenv('NESSUS_DEF_DIR')
NESSUS_LOC_DIR = os.getenv('NESSUS_LOC_DIR')

################################################################################
# Generic Console Command Class - containing methods
################################################################################

class Commands(object):
    """
    Defines a collection of MsfConsole commands.
    """

    def get_scan_names(self):
        """
        Return list of scan names.
        """
        scan_names = []
        path = "nessus_scans_tmp/" + '*.csv'
        try:
            csv_path = glob.glob(path)
            file_names = [os.path.basename(s) for s in csv_path]
            for file_name in file_names:
                scan_names.append(file_name.replace(".csv", "")[:-7])
        except Exception as e:
            print("[!] Error23: ", e)
            return
        return scan_names
