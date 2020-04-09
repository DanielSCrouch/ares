# Configuration, a globally accessable module containing the initialisations
# of all persistent objects and variables
#
# Author: Daniel Crouch
# Date created: March 2020

# module imports
import os
import time
from dotenv import load_dotenv
from threading import Thread
# class import
from commands import Commands
from testing import Tests
from modelling.pddl_translator import PDDLTranslate
from modelling.scan_importer import ScanImport
from msfrpc.client import MsfClient
from msfrpc.console import MsfConsole
from msfrpc.commands import MsfCommands
from planning.planner import Planner
from playbook.recon import Recon
from playbook.initial_access import InitialAccess
from playbook.priviledge_escalation import PriviledgeEsc
from playbook.traversal import Traversal
from playbook.control import Control
from plugins.postgresql import PostgreSQL
from plugins.metasploit import Metasploit
from plugins.nessus import Nessus

# main console
CONSOLE = None
# Plugin processes
DATABASE = PostgreSQL()
METASPLOIT = Metasploit()
NESSUS = Nessus()
# Native objects
COMMANDS = Commands()
TESTS = Tests()
SCANIMPORT = ScanImport()
PLANNER = Planner()
MSFCLIENT = MsfClient()
MSFCONSOLE = MsfConsole()
MSFCOMMANDS = MsfCommands()
PDDLTRANSLATE = PDDLTranslate()
RECON = Recon()
INITIALACCESS = InitialAccess()
PRIVILEDGEESC = PriviledgeEsc()
TRAVERSAL = Traversal()
CONTROL = Control()
# Global variables
TARGETS = {}
MSF_LHOST = os.getenv('MSF_LHOST')
NESSUS_DEF_DIR = os.getenv('NESSUS_DEF_DIR')
NESSUS_LOC_DIR = os.getenv('NESSUS_LOC_DIR')
FULL_SCAN_ID = os.getenv('FULL_SCAN_ID')
PORT_SCAN_ID = os.getenv('PORT_SCAN_ID')
MSF_LHOST = os.getenv('MSF_LHOST')
MSF_LPORT = os.getenv('MSF_LPORT')
VAR1 = None
VAR2 = None
VAR3 = None

################################################################################
# Console loading
################################################################################

LOADING = False

def loading_thread():
    while True:
        time.sleep(0.2)
        if LOADING:
            print('\r[|] ', end='', flush=True)
            time.sleep(0.2)
        if LOADING:
            print('\r[/] ', end='', flush=True)
            time.sleep(0.2)
        if LOADING:
            print('\r[—] ', end='', flush=True)
            time.sleep(0.1)
        if LOADING:
            print('\r[\\] ', end='', flush=True)
            time.sleep(0.2)
        if LOADING:
            print('\r[|] ', end='', flush=True)
            time.sleep(0.2)
        if LOADING:
            print('\r[/] ', end='', flush=True)
            time.sleep(0.2)
        if LOADING:
            print('\r[—] ', end='', flush=True)
            time.sleep(0.1)
        if LOADING:
            print('\r[\\] ', end='', flush=True)

try:
    Thread(target=loading_thread).start()
except:
    pass
