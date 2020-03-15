
# module imports
import os
from dotenv import load_dotenv
# class import
from plugins.postgresql import PostgreSQL
from plugins.metasploit import Metasploit
from plugins.nessus import Nessus
from msfrpc.client import MsfClient
from msfrpc.console import MsfConsole
from msfrpc.commands import MsfCommands
from planning.planner import Planner
from modelling.pddl_translator import PDDLTranslate
from commands import Commands
from playbook.host_scan import HostScan
from playbook.full_scan import FullScan
from playbook.initial_access import InitialAccess
# main console
CONSOLE = None
# Plugin processes
DATABASE = PostgreSQL()
METASPLOIT = Metasploit()
NESSUS = Nessus()
# Native objects
PLANNER = Planner()
MSFCLIENT = MsfClient()
MSFCONSOLE = MsfConsole()
MSFCOMMANDS = MsfCommands()
PDDLTRANSLATE = PDDLTranslate()
COMMANDS = Commands()
HOSTSCAN = HostScan()
FULLSCAN = FullScan()
INITIALACCESS = InitialAccess()
# Global variables
TARGETS = {}
NESSUS_DEF_DIR = os.getenv('NESSUS_DEF_DIR')
NESSUS_LOC_DIR = os.getenv('NESSUS_LOC_DIR')
VAR1 = None
VAR2 = None
VAR3 = None
