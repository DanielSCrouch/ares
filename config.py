
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
from commands import Commands

# Plugin processes
DATABASE = PostgreSQL()
METASPLOIT = Metasploit()
NESSUS = Nessus()
# Native objects
# MODEL = Model()
PLANNER = Planner()
MSFCLIENT = MsfClient()
MSFCONSOLE = MsfConsole()
MSFCOMMANDS = MsfCommands()
COMMANDS = Commands()
# Target hosts {name, object}

# Global variables
TARGETS = {}
NESSUS_DEF_DIR = os.getenv('NESSUS_DEF_DIR')
NESSUS_LOC_DIR = os.getenv('NESSUS_LOC_DIR')
