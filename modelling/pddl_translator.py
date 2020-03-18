
import os
import re
import glob
import time
import ipaddress
import subprocess
from pathlib import Path
from modelling.target import Target
# global variables
import config

################################################################################
# Class for translating Targets to a PDDL problem
################################################################################

class PDDLTranslate(object):
    """
    Defines a collection of methods for translating models to PDDL problems.
    """

    def generate_problem(self, depth=2):
        """
        Generates a PDDL problem file for use with planner.
        - optional arguments:
        depth: determines how many progress steps required to achieve goal
        """
        # path = glob.glob("/problem_test.txt")
        cwd = Path.cwd()
        problem_file = Path.cwd() / 'planning' / 'pddl_files' / 'problem.pddl'
        problem = self.get_header()
        problem += self.get_objects()
        problem += self.get_init(depth)
        problem += self.get_goals(depth)
        problem += '\n\n)'
        problem_file.write_text(problem)
        return True

    def get_header(self):
        p = "(define (problem attackvector) (:domain attacksurface)"
        return p

    def get_objects(self):
        p = "\n\n(:objects"
        # add hosts
        p += "\n    placeholder - host"
        for target in config.TARGETS.values():
            name = self.get_legal(target.name)
            p += "\n    " + name + " - host"
        # add vulns
        p += "\n    placeholder - vuln"
        vulns = set()
        for target in config.TARGETS.values():
            for vuln in target.vulns.values():
                vulns.add(vuln)
        for vuln in vulns:
            name = self.get_legal(vuln.cve_id)
            p += "\n    " + name + " - vuln"
        # add os
        p += "\n    placeholder - os"
        # end
        p += "\n    )"
        return p

    def get_init(self, depth):
        p = "\n\n(:init"
        p += " (is_host placeholder)"
        for target in config.TARGETS.values():
            name = self.get_legal(target.name)
            # add targets
            p += "\n       (is_host " + name + ")"
            # add session id
            if target.session_id:
                p += "\n       (has_session " + name + ")"
            # add access level
            access = self.get_legal(target.access)
            p += "\n       (access_" + access + " " + name + ")"
            # add os
            os = self.get_legal(target.os)
            p += "\n       (os_" + os + " " + name + ")"
            # add port scanned
            if target.port_scanned:
                p += "\n       (port_scanned " + name + ")"
            # add full scanned
            if target.full_scanned:
                p += "\n       (full_scanned " + name + ")"
            # add tcp ports
            for tcp_port in target.tcp_ports:
                # tcp_port = self.get_legal(tcp_port)
                p += "\n       (has_tcp_port_" + tcp_port + " " + name + ")"
            # add host vulns
            for vuln in target.vulns.values():
                vuln_name = self.get_legal(vuln.cve_id)
                p += "\n       (has_" + vuln_name + " " + name + ")"
            # add previously completed actions
            for action in target.action_history:
                action_name = self.get_legal(action)
                p += "\n       (hist_" + action_name + " " + name + ")"

        p += "\n       )"
        return p

    def get_goals(self, depth):
        p = "\n\n(:goal"
        if len(config.TARGETS) > 1:
            p += " (or"
            for target in config.TARGETS.values():
                name = self.get_legal(target.name)
                p += "\n    (has_progress" + str(depth) + " " + name + ")"
            p += "\n    )"
        else:
            for target in config.TARGETS.values():
                name = self.get_legal(target.name)
                p += "\n    (has_progress" + str(depth) + " " + name + ")"
        p += "\n    )"
        return p

    def get_legal(self, name):
        if name[0].isdigit():
            name = 'xx' + name
        name = name.replace('.', '_')
        name = name.replace('-', '_')
        name = name.replace(' ', '_')
        return name
