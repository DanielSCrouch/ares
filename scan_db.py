#!/usr/bin/env python3

import os
import csv
import glob
from dotenv import load_dotenv

################################################################################
# Envionment imports (Nessus scan report CSV location)
################################################################################

load_dotenv()
SCAN_REPORT_DIR = os.getenv('SCAN_REPORT_DIR')
SCAN_NAME = os.getenv('SCAN_NAME')

################################################################################
# Nessus Scan Database Object
################################################################################

class ScanDB(object):
    """
    Nessus scan report database object
    """

    def __init__(self):
        self.reader = None
        self.targets = {}
        # create dict reader from csv
        csvpath = None
        for path in glob.iglob(SCAN_REPORT_DIR + '*.csv'):
            if SCAN_NAME in path:
                csvpath = path
        try:
            with open(csvpath, newline='') as csvfile:
                self.reader = csv.DictReader(csvfile)
        except Exception as e:
            print("[-] Unable to read nessus scan csv -", e)
        # identify hosts
        for row in self.reader:
            for host in row['Host']:
                if host not in self.hosts:
                    self.targets.append(host)

class Target(object):
    """
    A target host identified from Nessus Scanning.
    """

    def __init__(self):
        self.host = ''
        self.os = ''
        self.open_tcp_ports = []
        self.open_udp_ports = []
        self.services = []
        self.vulnerabilities = []

class Service(object):
    """
    A service detected on a host.
    """

    def __init__(self):
        self.plugin = '' # nessus plugin used to identify
        self.plugin_name = ''
        self.service_name = ''
        self.port = None
        self.risk = None
        sel.description = ''

class Vulnerabilty(object):
    """
    A vulnerability detected on a host.
    """

    def __init__(self):
        self.plugin = '' # nessus plugin used to identify
        self.plugin_name = ''
        self.cve_id = None
        self.port = None
        self.risk = None
        sel.description = ''








################################################################################
# Test
################################################################################

scandb = ScanDB()
