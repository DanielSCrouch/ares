
# Extension of console.py module
# Provides scan function, enabling nessus scans through an msfrpc console


import os
import re
import time
import subprocess
from dotenv import load_dotenv

################################################################################
# Envionment imports (Set msf server login details)
################################################################################

load_dotenv()
NESSUS_DEF_DIR = os.getenv('NESSUS_DEF_DIR')
NESSUS_LOC_DIR = os.getenv('NESSUS_LOC_DIR')

class NessusScan(object):

    def __init__(self, uuid, scan_name, targets, msfconsole):
        """
        Nessus scan class, call start_scan function to initiate
        """
        self.uuid = uuid
        self.scan_name = scan_name
        self.targets = targets
        self.msfconsole = msfconsole
        #
        self.scanid = None

    def start_scan(self):
        """
        Run a nessus scan through the msfconsole.
        """
        print("[*] running scan...")
        if not self.create_scan():
            return False
        if not self.launch_scan():
            return False
        self.check_complete()
        if not self.import_scan():
            return False
        if not self.export_scan():
            return False
        if not self.local_copy():
            return False
        return True

    def create_scan(self):
        """
        Calls Nessus to create a scan from a policy.
        """
        # create scan
        cmd = "nessus_scan_new "
        cmd += self.uuid + " "
        cmd += self.scan_name + " "
        cmd += 'none' + " "
        cmd += self.targets
        msf_reply = self.msfconsole.callback(cmd, verbose=False)
        if 'scan added' not in msf_reply:
            print("[!] error creating scan")
            return
        # retrieve scan id
        regex = "nessus_scan_launch (\d+)"
        m = re.search(regex, msf_reply, re.IGNORECASE)
        self.scanid = m.group(1)
        i = int(self.scanid) # check value is integer
        print("[*] scan created with ID: ", self.scanid)
        return True

    def launch_scan(self):
        """
        Launch a scan in Nessus.
        """
        cmd = "nessus_scan_launch " + self.scanid
        msf_reply = self.msfconsole.callback(cmd, verbose=True)
        if "successfully launched" in msf_reply:
            print("[*] scan launched, waiting for completion")
            return True
        else:
            print("[!] error launching scan")
            return

    def check_complete(self):
        """
        Poll Nessus for scan to complete.
        """
        scanning = True
        while scanning:
            time.sleep(5)
            print('...')
            cmd = "nessus_scan_list"
            msf_reply = self.msfconsole.callback(cmd, verbose=False)
            for line in msf_reply.splitlines():
                if self.scanid in line and 'completed' in line:
                    print("[*] scan completed")
                    scanning = False

    def import_scan(self):
        """
        Import the scan result into the sql database.
        """
        print("[*] importing scan into database")
        cmd = "nessus_db_import " + self.scanid
        msf_reply = self.msfconsole.callback(cmd, verbose=True)
        if 'Done' in msf_reply:
            print("[+] import to database complete")
            return True
        else:
            print("[!] error importing scan")
            return False

    def export_scan(self):
        """
        Exports the scan to a CSV format
        dir: /opt/nessus/var/nessus/users/ares/files
        """
        print("[*] export to csv")
        cmd = "nessus_scan_export " + self.scanid + " CSV"
        msf_reply = self.msfconsole.callback(cmd, verbose=False)
        if 'export is ready' in msf_reply:
            print("[+] export complete: dir: /opt/nessus/var/nessus/users/ares/files")
            return True
        else:
            print("[!] error updating model")
            return False

    def local_copy(self):
        """
        Transfer file from Nessus's /opt/.. folder to local /nessus_scan_tmp,
        Updates owner to 'ares'
        """
        shell_cmd = "install -C -m 775 -o ares -g ares "
        shell_cmd += NESSUS_DEF_DIR + "/" +self.scan_name + "*.csv "
        shell_cmd += NESSUS_LOC_DIR
        process = subprocess.Popen(shell_cmd,                 \
                                   universal_newlines = True, \
                                   stdout = subprocess.PIPE,  \
                                   stderr = subprocess.PIPE,  \
                                   shell=True,                \
                                   bufsize=0)
        out, err = process.communicate()
        if not err:
            print("[+] local copy: dir: /nessus_scans_tmp")
            return True
        else:
            print("[!] Error: transfering scan csv export to local folder ")
