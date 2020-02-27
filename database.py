#!/usr/bin/env python3

import os
import csv
import glob
from dotenv import load_dotenv
#
import service_identifier
import os_identifier
import installed_service_identifier

################################################################################
# Envionment imports (Nessus scan report CSV location)
################################################################################

load_dotenv()
SCAN_REPORT_DIR = os.getenv('SCAN_REPORT_DIR')
SCAN_NAME = os.getenv('SCAN_NAME')
CSV_PATH = glob.glob(SCAN_REPORT_DIR + SCAN_NAME + '.csv')[0]

################################################################################
# Nessus Scan Database Object
################################################################################

class Database(object):
    """
    A Database of knwon Targets and their attributes.
    """
    def __init__(self):
        self.targets = {}
        self.services = []
        self.vulns = []
        self.installed_services = []
        # populate database
        self.populate()

    def populate(self):
        """
        Populate data with Targets, Services and Vulnerabilities.
        Controls csv read flow.
        """

        with open(CSV_PATH, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:

                # identify detection attributes
                host = row['Host']
                plugin = str(row['Plugin ID'])
                cve_id = row['CVE']
                cvss = row['CVSS']
                protocol = row['Protocol']
                port = str(row['Port'])
                name = row['Name']
                plugin_out = row['Plugin Output']

                # add new hosts
                if host not in self.targets.keys():
                    self.targets[host] = Target(host)

                # identify and add open tcp ports
                if protocol == 'tcp' and port != '0':
                    if port not in self.targets[host].tcp_ports:
                        self.targets[host].tcp_ports.append(port)

                # identify and add open tcp ports
                if protocol == 'udp' and port != '0':
                    if port not in self.targets[host].udp_ports:
                        self.targets[host].udp_ports.append(port)

                # identify and add services
                service_name = service_identifier.get_service(plugin)
                if service_name is not None:
                    s = Service(plugin, service_name, protocol, port)
                    self.services.append(s)
                    self.targets[host].services.append(s)

                # identify and add vulnerabilities
                if len(cve_id) > 3:
                    v = Vuln(plugin, cve_id, cvss, protocol, port)
                    self.vulns.append(v)
                    self.targets[host].vulns.append(v)

                # identify and add OS
                if plugin == "11936":
                    os_list = os_identifier.get_os(plugin_out)
                    self.targets[host].os = os_list

                # identify and add installed services (credential access)
                if plugin == "20811":
                    print('here')
                    is_list = installed_service_identifier.get_service(plugin_out)
                    self.installed_services = is_list
                    self.targets[host].os = is_list


################################################################################
# Host targets identified
################################################################################

class Target(object):
    """
    A target host identified from Nessus Scanning.
    """
    def __init__(self, host):
        self.host = host
        self.tcp_ports = []
        self.udp_ports = []
        self.services = []
        self.installed_services = []
        self.vulns = []
        self.os = []

    def __str__(self):
        string = '\n   **********************************************'
        # Host
        string += "\n\n   Host     : " + self.host
        # OS
        attribute = self.os
        string += "\n\n   OpSystem : "
        if len(attribute) >1:
            string += str(attribute[0])
            for item in attribute[1:min(5, len(attribute))]:
                string += '\n              ' + str(item)
        # TCP Ports
        string += "\n\n   TCP Ports: "
        for item in self.tcp_ports[0:min(3, len(self.tcp_ports))]:
            string += item + ', '
        string += '    ... total(' + str(len(self.tcp_ports)) + ')'
        # UDP Ports
        string += "\n   UDP Ports: "
        for item in self.udp_ports[0:min(3, len(self.udp_ports))]:
            string += item + ', '
        string += ' ... total(' + str(len(self.udp_ports)) + ')'
        # Services
        attribute = self.services
        string += "\n\n   Services : "
        if len(attribute) >1:
            string += str(attribute[0])
            for item in attribute[1:min(5, len(attribute))]:
                string += '\n              ' + str(item)
            string += '\n              total(' + str(len(attribute)) + ')'
        # Vulnerabilities
        attribute = self.vulns
        string += "\n\n   Vuls     : "
        if len(attribute) >1:
            string += str(attribute[0]) + ''
            for item in attribute[1:min(5, len(attribute))]:
                string += '\n              ' + str(item)
            string += '\n              total(' + str(len(attribute)) + ')'
        # Installed services
        attribute = self.installed_services
        string += "\n\n   IServices: "
        if len(attribute) >1:
            string += str(attribute[0])
            for item in attribute[1:min(5, len(attribute))]:
                string += '\n              ' + str(item)
            string += '\n              total(' + str(len(attribute)) + ')'
        string += '\n\n   **********************************************\n'
        return string


################################################################################
# Services running on hosts detected
################################################################################

class Service(object):
    """
    A service detected on a host.
    """
    def __init__(self, plugin, service_name, protocol, port):
        self.plugin = plugin # nessus plugin used to identify
        self.service_name = service_name
        self.protocol = protocol
        self.port = port

    def __str__(self):
        return str(self.service_name)

################################################################################
# Vulnerabilities running on hosts detected
################################################################################

class Vuln(object):
    """
    A vulnerability detected on a host.
    """
    def __init__(self, plugin, cve_id, cvss, protocol, port):
        self.plugin = plugin # nessus plugin used to identify
        self.cve_id = cve_id
        self.cvss = cvss
        self.protocol = protocol
        self.port = port

    def __str__(self):
        return str(self.cve_id)

################################################################################
# Test
################################################################################

# scandb = ScanDB()
# for target in scandb.targets.values():
#     print(target)
#     break
