
import os
import csv
import glob
from pathlib import Path
from dotenv import load_dotenv
#

from .service import Service
from .vulnerability import Vuln
from . import service_identifier
from . import os_identifier
from . import installed_service_identifier


class Target(object):
    """
    Model of a network target.
    """
    def __init__(self, name, ip):
        self.name = name
        self.ip = ip
        self.scanned = False
        self.tcp_ports = []
        self.udp_ports = []
        self.services = []
        self.installed_services = []
        self.vulns = {} # {cve_id: Vuln}
        self.os = []

    def __str__(self):
        string = '\n    ' + str("=" * 60)
        # Target
        string += "\n\n    IP:        " + self.ip
        # OS
        attribute = self.os
        string += "\n\n    OpSystem:  "
        if len(attribute) >1:
            string += str(attribute[0])
            for item in attribute[1:min(5, len(attribute))]:
                string += '\n               ' + str(item)
        # TCP Ports
        string += "\n\n    TCP Ports: "
        for item in self.tcp_ports[0:min(3, len(self.tcp_ports))]:
            string += item + ', '
        string += ' ... total(' + str(len(self.tcp_ports)) + ')'
        # UDP Ports
        string += "\n    UDP Ports: "
        for item in self.udp_ports[0:min(3, len(self.udp_ports))]:
            string += item + ', '
        string += ' ... total(' + str(len(self.udp_ports)) + ')'
        # Services
        attribute = self.services
        string += "\n\n    Services:  "
        if len(attribute) >1:
            string += str(attribute[0])
            for item in attribute[1:min(5, len(attribute))]:
                string += '\n               ' + str(item)
            string += '\n              total(' + str(len(attribute)) + ')'
        # Vulnerabilities
        attribute = list(self.vulns.keys())
        string += "\n\n    Vulns:     "
        if len(attribute) >1:
            string += str(attribute[0]) + ''
            for item in attribute[1:min(5, len(attribute))]:
                string += '\n               ' + str(item)
            string += '\n               total(' + str(len(attribute)) + ')'
        # Installed services
        attribute = self.installed_services
        string += "\n\n    IServices: "
        if len(attribute) >1:
            string += str(attribute[0])
            for item in attribute[1:min(5, len(attribute))]:
                string += '\n               ' + str(item)
            string += '\n               total(' + str(len(attribute)) + ')'
        string += "\n\n    " + str("=" * 60) + '\n'
        return string

    def import_scan(self, scan_path):
        """
        Update Target from scan csv.
        """
        with open(scan_path, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:

                # identify detection attributes
                ip = row['Host']
                plugin = str(row['Plugin ID'])
                cve_id = row['CVE']
                cvss = row['CVSS']
                protocol = row['Protocol']
                port = str(row['Port'])
                name = row['Name']
                plugin_out = row['Plugin Output']
                risk = row['Risk']

                # add new hosts
                if ip in self.ip:

                    # identify and add open tcp ports
                    if protocol == 'tcp' and port != '0':
                        if port not in self.tcp_ports:
                            self.tcp_ports.append(port)

                    # identify and add open tcp ports
                    if protocol == 'udp' and port != '0':
                        if port not in self.udp_ports:
                            self.udp_ports.append(port)

                    # identify and add services
                    service_name = service_identifier.get_service(plugin)
                    if service_name is not None:
                        s = Service(plugin, service_name, protocol, port)
                        self.services.append(s)

                    # identify and add vulnerabilities
                    if len(cve_id) > 3:
                        if cve_id not in self.vulns.keys():
                            v = Vuln(plugin, cve_id, cvss, protocol, port, risk)
                            self.vulns[cve_id] = v

                    # identify and add OS
                    if plugin == "11936":
                        os_list = os_identifier.get_os(plugin_out)
                        self.os = os_list

                    # identify and add installed services (credential access)
                    if plugin == "20811":
                        is_list = installed_service_identifier.get_service(plugin_out)
                        self.installed_services = is_list
        # set to scanned
        self.scanned = True
