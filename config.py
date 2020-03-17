
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
from playbook.port_scan import PortScan
from playbook.full_scan import FullScan
from playbook.initial_access import InitialAccess
from playbook.priviledge_escalation import PriviledgeEsc
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
PORTSCAN = PortScan()
FULLSCAN = FullScan()
INITIALACCESS = InitialAccess()
PRIVILEDGEESC = PriviledgeEsc()
# Global variables
TARGETS = {}
NESSUS_DEF_DIR = os.getenv('NESSUS_DEF_DIR')
NESSUS_LOC_DIR = os.getenv('NESSUS_LOC_DIR')
FULL_SCAN_ID = os.getenv('FULL_SCAN_ID')
PORT_SCAN_ID = os.getenv('PORT_SCAN_ID')
MSF_LHOST = os.getenv('MSF_LHOST')
MSF_LPORT = os.getenv('MSF_LPORT')
VAR1 = None
VAR2 = None
VAR3 = None
