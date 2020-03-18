
import re
import time
import subprocess
from pathlib import Path
# global variables
import config

################################################################################
# Generic Console Command Class - containing methods
################################################################################

class FullScan(object):
    """
    Full scan
    """

    def scan(self, scan_type, target_name, verbose=False):
        """
        Scan an IP address with a given scan policy.
        """
        scan_name = 'full_scan'
        target = config.TARGETS[target_name]
        target.full_scanned = True 
        ip_addr = target.ip
        uuid = config.FULL_SCAN_ID
        cmd = "nessus_scan_new "
        cmd += uuid + " "
        cmd += scan_name + " "
        cmd += 'none' + " "
        cmd += ip_addr
        print("command:", cmd)
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=verbose)
        if 'scan added' not in msf_reply:
            raise Exception("error creating scan")
        # retrieve scan id
        regex = "nessus_scan_launch (\d+)"
        m = re.search(regex, msf_reply, re.IGNORECASE)
        try:
            scanid = m.group(1)
            i = int(scanid) # check value is integer
        except Exception as e:
            print(msf_reply)
            raise Exception("error creating scan 2")
        # launch scan
        cmd = "nessus_scan_launch " + scanid
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=verbose)
        if "successfully launched" not in msf_reply:
            raise Exception("error launching scan")
        # wait for scan to complete
        scanning = True
        while scanning:
            time.sleep(5)
            print('[*] scan running...')
            cmd = "nessus_scan_list"
            msf_reply = config.MSFCONSOLE.callback(cmd, verbose=verbose)
            for line in msf_reply.splitlines():
                if scanid in line and 'completed' in line:
                    print("[*] scan completed")
                    scanning = False
        # import scan into postgresql
        cmd = "nessus_db_import " + scanid
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=verbose)
        if 'Done' not in msf_reply:
            raise Exception("error importing scan")
        # export scan to csv
        cmd = "nessus_scan_export " + scanid + " CSV"
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=verbose)
        if 'export is ready' not in msf_reply:
            raise Exception("error exporting scan to csv")
        # move scan to local nessus temp folder
        shell_cmd = "install -D -C -m 775 -o ares -g ares "
        shell_cmd += config.NESSUS_DEF_DIR + "/" + scan_name + "*.csv "
        shell_cmd += " -t " + config.NESSUS_LOC_DIR + "/" + target_name
        process = subprocess.Popen(shell_cmd,                 \
                                   universal_newlines = True, \
                                   stdout = subprocess.PIPE,  \
                                   stderr = subprocess.PIPE,  \
                                   shell=True,                \
                                   bufsize=0)
        out, err = process.communicate()
        if err:
            raise Exception(err)
        # import scan to target
        scan_path = Path.cwd().glob('nessus_scans_tmp/' + target_name + '/' + scan_type + '*.csv')
        for file in scan_path:
            file_path = file
        target = config.TARGETS[target_name]
        config.COMMANDS.scan_import(scan_type, target_name)



#
