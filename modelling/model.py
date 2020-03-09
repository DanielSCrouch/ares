import os
import csv
import glob
from pathlib import Path
from dotenv import load_dotenv
#
from . import service_identifier
from . import os_identifier
from . import installed_service_identifier

################################################################################
# Envionment imports (Nessus scan report CSV location)
################################################################################

load_dotenv()
SCAN_REPORT_DIR = os.getenv('SCAN_REPORT_DIR')

################################################################################
# Model Object built from Nessus scans and Metasploit's Postgres Database
################################################################################

class Model(object):
    """
    A Model of known Hosts and their attributes.
    """
    def __init__(self):
        self.hosts = {}
        self.services = []
        self.vulns = []
        self.installed_services = []

    def get_host_names(self):
        """
        Return list of hosts names.
        """
        return self.hosts.keys()

    def get_hosts(self):
        """
        Return a list of hosts
        """
        return self.hosts.values()

    def get_host(self, host):
        """
        Return host
        """
        return self.hosts[host]

    def get_host_name(self, host):
        """
        Return the host specificed by the host IP address.
        """
        if host in self.hosts.keys():
            return self.hosts[host]

    def get_vuln_names(self):
        """
        Return list of vulnerability names.
        """
        return self.vulns

    def import_scan(self, scan_name, csv_dir=SCAN_REPORT_DIR):
        """
        Update data with Hosts, Services and Vulnerabilities.
        """
        path = "nessus_scans_tmp/" + scan_name + '*.csv'
        try:
            csv_path = glob.glob(path)
            csv_path = csv_path[0]
        except Exception as e:
            print("[!] Error: ", e)
            return

        with open(csv_path, newline='') as csvfile:
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
                if host not in self.hosts.keys():
                    self.hosts[host] = Host(host)

                # identify and add open tcp ports
                if protocol == 'tcp' and port != '0':
                    if port not in self.hosts[host].tcp_ports:
                        self.hosts[host].tcp_ports.append(port)

                # identify and add open tcp ports
                if protocol == 'udp' and port != '0':
                    if port not in self.hosts[host].udp_ports:
                        self.hosts[host].udp_ports.append(port)

                # identify and add services
                service_name = service_identifier.get_service(plugin)
                if service_name is not None:
                    s = Service(plugin, service_name, protocol, port)
                    self.services.append(s)
                    self.hosts[host].services.append(s)

                # identify and add vulnerabilities
                if len(cve_id) > 3:
                    v = Vuln(plugin, cve_id, cvss, protocol, port)
                    self.vulns.append(v)
                    self.hosts[host].vulns.append(v)

                # identify and add OS
                if plugin == "11936":
                    os_list = os_identifier.get_os(plugin_out)
                    self.hosts[host].os = os_list

                # identify and add installed services (credential access)
                if plugin == "20811":
                    print('here')
                    is_list = installed_service_identifier.get_service(plugin_out)
                    self.installed_services = is_list
                    self.hosts[host].os = is_list

    def generate_problem(self, depth=0):
        """
        Generates a PDDL problem file for use with planner.
        - optional arguments:
        depth: determines how many progress steps required to achieve goal
        """
        # path = glob.glob("/problem_test.txt")
        cwd = Path.cwd()
        problem_file = Path.cwd() / 'pddl_files' / 'problem.pddl'
        problem = PDDLTranslate(self).get_header()
        problem += PDDLTranslate(self).get_objects()
        problem += PDDLTranslate(self).get_init(depth)
        problem += PDDLTranslate(self).get_goals(depth)
        problem += '\n\n)'
        problem_file.write_text(problem)
        print('Done!')


class PDDLTranslate(object):
    """
    Defines a collection of methods for translating models to PDDL problems
    """
    def __init__(self, model):
        self.model = model

    def get_header(self):
        p = "(define (problem attackvector) (:domain attacksurface)"
        return p

    def get_objects(self):
        p = "\n\n(:objects"
        # add hosts
        p += "\n    placeholder - host"
        for host_name in self.model.get_host_names():
            host_name = self.get_legal(host_name)
            p += "\n    " + host_name + " - host"
        # add vulns
        p += "\n    placeholder - vuln"
        for vuln_name in self.model.get_vuln_names():
            vuln_name = self.get_legal(vuln_name)
            p += "\n    " + vuln_name + " - vuln"
        # add os
        p += "\n    placeholder - os"
        # port
        p += "\n    placeholder - port"
        # end
        p += "\n    )"
        return p

    def get_init(self, depth):
        p = "\n\n(:init"
        p += "(is placeholder)"
        for host in self.model.get_hosts():
            host_name = self.get_legal(host.host)
            # add found hosts
            if host.found:
                p += "\n    (found " + host_name + ")"
        p += "\n    )"
        return p

    def get_goals(self, depth):
        p = "\n\n(:goal"
        if len(self.model.get_host_names()) > 1:
            p += " (or"
            for host_name in self.model.get_host_names():
                host_name = self.get_legal(host_name)
                p += "\n    (has_progress" + str(depth) + " " + host_name + ")"
            p += "\n    "
        else:
            for host_name in self.model.get_host_names():
                host_name = self.get_legal(host_name)
                p += "\n    (has_progress" + str(depth) + " " + host_name + ")"
        p += "\n    )"
        return p

    def get_legal(self, name):
        if name[0].isdigit():
            name = 'xx' + name
        name = name.replace('.', '_')
        return name

################################################################################
# Host identified
################################################################################

class Host(object):
    """
    A Host host identified from Nessus Scanning.
    """
    def __init__(self, host):
        self.host = host
        self.found = False
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

# model = Model()
# model.import_scan('Host_Discover_Scan')
# for host in model.get_hosts():
#     print(host)
# model.generate_problem(1)
