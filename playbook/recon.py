# Module providing Scanning exploits
#
# Author: Daniel Crouch
# Date created: March 2020

import os
import re
import sys
import time
import subprocess
from pathlib import Path
from dotenv import load_dotenv
# global variables
import config

################################################################################
# Priviledge Escalation commands
################################################################################

class Recon(object):
    """
    Defines a collection of scan methods.
    """

    def host_scan(self, ip_range, verbose=False):
        """
        Return list of detected hosts.
        """
        # start scan in shell
        cmd = ["nmap -sP " + ip_range]
        process = subprocess.Popen(cmd,       \
                   stdin = subprocess.PIPE,   \
                   stdout = subprocess.PIPE,  \
                   stderr = subprocess.PIPE,  \
                   universal_newlines = True, \
                   shell=True,                \
                   bufsize=0)
        # wait for completion
        process.wait(timeout=10)
        # raise errors
        error_stream = process.stderr
        error = error_stream.read()
        if error:
            raise Exception(error)
        # process output
        output_stream = process.stdout
        output = output_stream.read()
        live_hosts = []
        for word in output.split():
            word = word.replace('(','').replace(')','')
            search = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            if re.match(search, word):
                live_hosts.append(word)
        # display output
        if verbose:
            print('\n    ' + 'hosts' + '\n    ' + '=' * 60)
            for host in live_hosts:
                print('    ' + host + " - live")
            print()
        return live_hosts

    def port_scan(self, scan_type, target_name, verbose=False):
        """
        Scan an IP address with a given scan policy.
        """
        scan_name = 'port_scan'
        target = config.TARGETS[target_name]
        target.port_scanned = True
        ip_addr = target.ip
        uuid = config.PORT_SCAN_ID
        cmd = "nessus_scan_new "
        cmd += uuid + " "
        cmd += scan_name + " "
        cmd += 'none' + " "
        cmd += ip_addr
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
        print('\r[*] scan running...')
        while scanning:
            config.LOADING = True
            time.sleep(5)
            cmd = "nessus_scan_list"
            msf_reply = config.MSFCONSOLE.callback(cmd, verbose=verbose)
            for line in msf_reply.splitlines():
                if scanid in line and 'completed' in line:
                    print("\r[*] scan completed")
                    scanning = False
                    config.LOADING = False
                    time.sleep(1)
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

    def full_scan(self, scan_type, target_name, verbose=False):
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

    def snap(self, target_name, verbose = True):
        """
        Copy the targets current screen display
        """
        target = config.TARGETS[target_name]
        if not target.session_id:
            raise Exception("shell session with target not active")
            return
        # open session with target
        config.MSFCONSOLE.open_session(target_name)
        # execute
        cmd = "use espia"
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True, wait=2)
        cmd = "screengrab"
        msf_reply = config.MSFCONSOLE.callback(cmd, verbose=True, wait=1)
        # background session
        config.MSFCONSOLE.background_session(target_name)





#
