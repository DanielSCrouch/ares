
import os
import csv
import glob
from pathlib import Path
from dotenv import load_dotenv

class Target(object):
    """
    Model of a network target.
    """
    def __init__(self, name, ip):
        self.name = name
        self.ip = ip
        self.session_id = ''
        self.access = ''
        self.os = ''
        self.full_scan = False
        self.port_scan = False
        self.tcp_ports = []
        self.udp_ports = []
        self.services = []
        self.installed_services = []
        self.vulns = {} # {cve_id: Vuln}
        self.admin_user = ''
        self.admin_hash = ''
        self.msql_username = ''
        self.msql_password = ''
        # actions completed
        self.action_history = []

    def __str__(self):
        string = '\n    ' + str("=" * 60)
        # Target
        string += "\n\n    IP:        " + self.ip
        # Session ID
        string += "\n\n    Session:   " + self.session_id
        # Priviledges
        string += "\n\n    Access:    " + self.access
        # OS
        string += "\n\n    OS:        " + self.os
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
