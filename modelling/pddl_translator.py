
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
            # add port scanned
            if target.port_scan:
                p += "\n       (port_scanned " + name + ")"
            # add full scanned
            if target.full_scan:
                p += "\n       (full_scanned " + name + ")"
            # add initial access
            if target.session_id:
                p += "\n       (initial_access " + name + ")"
            # add admin access
            if target.access:
                access = self.get_legal(target.access)
                p += "\n       (" + access + "_access" + " " + name + ")"
            # add os
            if target.os:
                os = self.get_legal(target.os)
                p += "\n       (os_" + os + " " + name + ")"
            # add tcp ports
            for tcp_port in target.tcp_ports:
                # tcp_port = self.get_legal(tcp_port)
                p += "\n       (has_tcp_port_" + tcp_port + " " + name + ")"
            # add host vulns
            for vuln in target.vulns.values():
                vuln_name = self.get_legal(vuln.cve_id)
                p += "\n       (has_" + vuln_name + " " + name + ")"
            # add admin (smb exploit)
            if target.admin_hash:
                p += "\n       (has_admin_hash " + name + ")"
            # add previously completed actions
            for action in target.action_history:
                action_name = self.get_legal(action)
                p += "\n       (hist_" + action_name + " " + name + ")"

        p += "\n       )"
        return p

    def get_goals(self, depth):
        # parse goal
        goal = ''
        if depth == 1:
            goal = 'port_scanned'
        if depth == 2:
            goal = 'full_scanned'
        if depth == 3:
            goal = 'initial_access'
        if depth == 4:
            goal = 'admin_access'
        if depth == 5:
            goal = 'traversed'
        if depth == 6:
            goal = 'command'
        if depth == 7:
            goal = 'objective'
        print('goal is: ', goal)
        # format goal
        p = "\n\n(:goal"
        if len(config.TARGETS) > 1:
            p += " (or"
            for target in config.TARGETS.values():
                name = self.get_legal(target.name)
                p += "\n    (" + goal + " " + name + ")"
            p += "\n    )"
        else:
            for target in config.TARGETS.values():
                name = self.get_legal(target.name)
                p += "\n    (" + goal + " " + name + ")"
        p += "\n    )"
        return p

    def get_legal(self, name):
        if name[0].isdigit():
            name = 'xx' + name
        name = name.replace('.', '_')
        name = name.replace('-', '_')
        name = name.replace(' ', '_')
        return name
