import csv
import glob
import time
from pathlib import Path
#
import config
from .service import Service
from .vulnerability import Vuln

class ScanImport(object):
    """
    Class defining a collection of methods for importing a scan from a
    Nessus CSV report
    """

    def import_full_scan(self, target_name, scan_path):
        """
        Function to import Nessus CSV report to Target
        """
        target = config.TARGETS[target_name]
        config.LOADING = True
        time.sleep(2)
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
                if ip in target.ip:

                    # identify and add open tcp ports
                    if protocol == 'tcp' and port != '0':
                        if port not in target.tcp_ports:
                            target.tcp_ports.append(port)

                    # identify and add open tcp ports
                    if protocol == 'udp' and port != '0':
                        if port not in target.udp_ports:
                            target.udp_ports.append(port)

                    # identify and add services
                    service_name = self.get_service(plugin)
                    if service_name is not None:
                        s = Service(plugin, service_name, protocol, port)
                        target.services.append(s)

                    # identify and add vulnerabilities
                    if len(cve_id) > 3:
                        if cve_id not in target.vulns.keys():
                            v = Vuln(plugin, cve_id, cvss, protocol, port, risk)
                            target.vulns[cve_id] = v

                    # identify and add OS
                    if plugin == "11936":
                        os_list = self.get_os(plugin_out)
                        target.os = os_list[0] # assumes first is correct!

                    # identify and add installed services (credential access)
                    if plugin == "20811":
                        is_list = self.get_service(plugin_out)
                        target.installed_services = is_list
        # set to scanned
        config.LOADING = False
        target.full_scan = True

    def import_port_scan(self, target_name, scan_path):
        """
        Function to import Nessus port scan CSV report to Target
        """
        target = config.TARGETS[target_name]
        config.LOADING = True
        time.sleep(2)
        with open(scan_path, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:

                # identify detection attributes
                ip = row['Host']
                protocol = row['Protocol']
                port = str(row['Port'])

                # add new hosts
                if ip in target.ip:

                    # identify and add open tcp ports
                    if protocol == 'tcp' and port != '0':
                        if port not in target.tcp_ports:
                            target.tcp_ports.append(port)

                    # identify and add open tcp ports
                    if protocol == 'udp' and port != '0':
                        if port not in target.udp_ports:
                            target.udp_ports.append(port)

        # set to scanned
        config.LOADING = False
        target.port_scan = True

    def get_os(self, plugin_output):
        """
        Function to extract operating systems from Nessus plugin 11936
        """
        os_list = []
        lines = (line for line in plugin_output.splitlines())
        for line in lines:
            if "one of these operating systems :" in line:
                break
        for line in lines:
            if 'Service Pack 3' in line:
                os_list.append(line)
        return os_list


    def get_services(self, plugin_output):
        """
        Function to extract services from Nessus plugin 20811
        """
        is_list = []
        lines = (line for line in plugin_output.splitlines())
        for line in lines:
            if "following softare are installed on the remote host :" in line:
                break
        for line in lines:
            break
        for line in lines:
            if len(line) == 0:
                break
            else:
                start = line.find('[')
                end = line.find('[')
                if start != -1 and end != -1:
                    rline = line[start:end+1]
                    nline = line.replace(rline, "")
                    is_list.append(nline)
        return is_list


    def get_service(self, plugin):
        """
        Function to match Nessus plugin ID to detected service
        """
        cwd = Path.cwd()
        path = Path.cwd() / "modelling" / "nessus_scan_plugin_to_service.csv"

        with open(path) as f:
            list_of_dicts = [{pid:val for pid,val in row.items()} \
                           for row in csv.DictReader(f, skipinitialspace=True)]
        translation = {}
        for i in range(len(list_of_dicts)):
            translation[list_of_dicts[i]["Plugin"]] = list_of_dicts[i]["Service"]

        plugin = str(plugin)
        if plugin in translation.keys():
            return translation[plugin]
        else:
            return None
