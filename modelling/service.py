# Object describing a detected host service 
#
# Author: Daniel Crouch
# Date created: March 2020

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
