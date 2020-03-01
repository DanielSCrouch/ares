
# Extension of console.py module
# Provides collection of setup functions

import os
from dotenv import load_dotenv

################################################################################
# Local import
################################################################################

from plugins import PostgreSQL, Nessus, Metasploit
from msfrpc import MsfClient, MsfConsole
from model import Model
from msf_commands import MsfCommands

################################################################################
# Envionment variable imports (API Keys etc)
################################################################################

load_dotenv()
NESSUS_USERNAME = os.getenv('NESSUS_USERNAME')
NESSUS_PASSWORD = os.getenv('NESSUS_PASSWORD')
NESSUS_HOST = os.getenv('NESSUS_HOST')
NESSUS_PORT = os.getenv('NESSUS_PORT')
POSTGRES_USER = os.getenv('POSTGRES_USER')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD')
POSTGRES_SERVER = os.getenv('POSTGRES_SERVER')
POSTGRES_PORT = os.getenv('POSTGRES_PORT')
POSTGRES_DB_NAME = os.getenv('POSTGRES_DB_NAME')
MSF_WORKSPACE_DEFAULT = os.getenv('MSF_WORKSPACE_DEFAULT')

INTRO = "\n\n            |     '||''|.   '||''''|   .|'''.|  \n           |||     ||   ||   ||  .     ||..  '  \n          |  ||    ||''|'    ||''|      ''|||.  \n         .''''|.   ||   |.   ||       .     '|| \n        .|.  .||. .||.  '|' .||.....| |'....|'  \n        \n        Automated  Recon  &  Exploit  Software\n\n"

################################################################################
# Setup Class - containing setup methods
################################################################################

class Setup(object):

    # Plugins

    def database(self):
        """
        Initialise and return PostgreSQL plugin.
        """
        try:
            print("[*] loading PostgreSQL plugin")
            database = PostgreSQL()
        except Exception as e:
            print('[!] Error3: ', e)
        try:
            database.start_service()
            print("[+] PostgreSQL plugin loaded")
        except Exception as e:
            print('[!] Error4: ', e)
        return database

    def metasploit(self):
        """
        Initialise and return Metasploit plugin.
        """
        try:
            print("[*] loading Metasploit plugin")
            metasploit = Metasploit()
        except Exception as e:
            print('[!] Error3: ', e)
        try:
            metasploit.start_service()
            print("[+] Metasploit plugin loaded")
        except Exception as e:
            print('[!] Error4: ', e)
        return metasploit

    def nessus(self):
        """
        Initialise and return Nessus plugin.
        """
        try:
            print("[*] loading Nessus plugin")
            nessus = Nessus()
        except Exception as e:
            print('[!] Error7: ', e)
        try:
            nessus.start_service()
            print("[+] Nessus plugin loaded")
        except Exception as e:
            print('[!] Error8: ', e)
        return nessus

    # Services

    def planner(self):
        """
        Initialise and return AI Planner.
        """
        try:
            print("[*] connecting to planner")
            planner = Planner()
            print("[+] planner now avaliable")
            return planner
        except Exception as e:
            print('[!] Error12: ', e)

    def msfclient(self):
        """
        Initialise and return MsfRpc Client.
        """
        try:
            print("[*] creating msf rpc client")
            msfclient = MsfClient()
            print("[*] athenticating Metasploit RPC user login")
            msfclient.login()
            print("[+] Metasploit RPC athenticating successful")
            return msfclient
        except Exception as e:
            print("[!] Error5: ", e)
            print("[!] Recommendation: run app from new console as root'")

    def msfconsole(self, msfclient):
        """
        Initialise and return MsfRpc Console.
        """
        try:
            print("[*] creating msf rpc console")
            console = MsfConsole(msfclient)
            print("[+] Metasploit console avaliable, see 'help msf'")
            return console
        except Exception as e:
            print('[!] Error6: ', e)

    # Connections

    def nessus_bridge(self, msfconsole):
        """
        Creates bridge from Metasploit to Nessus.
        """
        try:
            print("[*] creating Nessus to Metasploit bridge")
            cmd = 'load nessus'
            msf_reply = msfconsole.callback(cmd)
        except Exception as e:
            print('[!] Error8: ', e)
        # Nessus - Authentication over bridge
        try:
            print("[*] authenticating Nessus via bridge")
            cmd = "nessus_connect " +       \
                   NESSUS_USERNAME  + ':' + \
                   NESSUS_PASSWORD  + '@' + \
                   NESSUS_HOST      + ':' + \
                   NESSUS_PORT      + ' ok'
            msf_reply = msfconsole.callback(cmd)
        except Exception as e:
            print('[!] Error9: ', e)

    def database_bridge(self, msfconsole):
        """
        Creates bridge from Metasploit to Database.
        """
        try:
            print("[*] connecting Metasploit to database: ", POSTGRES_DB_NAME)
            cmd =  "db_connect "
            cmd += POSTGRES_USER + ":" + POSTGRES_PASSWORD + "@"
            cmd += POSTGRES_SERVER + ":" + POSTGRES_PORT + "/"
            cmd += POSTGRES_DB_NAME
            msf_reply = msfconsole.callback(cmd, verbose=False)
            if POSTGRES_DB_NAME not in msf_reply:
                print("[!] unable to connect to database")
            else:
                print("[+] Metasploit connected to database")
        except Exception as e:
            print('[!] Error11: ', e)

    def workspace(self, msfconsole):
        """
        Setups up workspace on Metasploit.
        """
        try:
            print("[*] setting up Metasploit workspace")
            MsfCommands(msfconsole).workspace(MSF_WORKSPACE_DEFAULT)
        except Exception as e:
            print('[!] Error11: ', e)
