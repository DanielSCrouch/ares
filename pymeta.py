#!/usr/bin/env python3

import os
import requests
import uuid
import msgpack
import time
import sys
import select
from dotenv import load_dotenv
from threading import Timer, Lock, Thread
from optparse import OptionParser

################################################################################
# Envionment imports (API Keys etc)
################################################################################

load_dotenv()
MSF_SERVER = os.getenv('MSF_SERVER')
MSF_PORT = os.getenv('MSF_PORT')
MSF_USER = os.getenv('MSF_USER')
MSF_PASSWORD = os.getenv('MSF_PASSWORD')
NESSUS_USERNAME = os.getenv('NESSUS_USERNAME')
NESSUS_PASSWORD = os.getenv('NESSUS_PASSWORD')

################################################################################
# Metasploit RPC Methods
################################################################################

class MsfRpcMethod(object):
    AuthLogin = 'auth.login'
    AuthLogout = 'auth.logout'
    AuthTokenAdd = 'auth.token_add'
    ConsoleCreate = 'console.create'
    ConsoleDestroy = 'console.destroy'
    ConsoleList = 'console.list'
    ConsoleRead = 'console.read'
    ConsoleWrite = 'console.write'
    ConsoleTabs = 'console.tabs'
    ConsoleSessionKill = 'console.session_kill'
    ConsoleSessionDetach = 'console.session_detach'

################################################################################
# Error Handling
################################################################################

class MsfRpcError(Exception):
    pass

class MsfError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return repr(self.msg)

class MsfAuthError(MsfError):
    def __init__(self, msg):
        self.msg = msg

################################################################################
# MSF Client
################################################################################

class MsfClient(object):
    """Client for MsfRpc login, can spawn multiple consoles"""

    def __init__(self, password, **kwargs):
        self.host = kwargs.get('server', MSF_SERVER)
        self.port = kwargs.get('port', MSF_PORT)
        self.ssl = kwargs.get('ssl', False)
        self.user = kwargs.get('username', MSF_USER)
        #
        self.uri = kwargs.get('uri', '/api/')
        self.headers = {"Content-type": "binary/message-pack"}
        self.consoles = {} # dict of consoles {cid: MsfConsole Object}

        print('[*] Logging in user', self.user)
        self.login(self.user, password)

    def msf_callback(self, method, opts=[]):
        if method != 'auth.login':
            if self.token is None:
                raise MsfAuthError("MsfRPC: Not Authenticated")

        if method != "auth.login":
            opts.insert(0, self.token)

        if self.ssl is True:
            url = "https://%s:%s%s" % (self.host, self.port, self.uri)
        else:
            url = "http://%s:%s%s" % (self.host, self.port, self.uri)

        opts.insert(0, method)
        payload = encode(opts)

        r = requests.post(url, data=payload, headers=self.headers, verify=False)

        opts[:] = []  # Clear opts list

        return convert(decode(r.content))  # convert all keys/vals to utf8

    def login(self, user, password):
        auth = self.msf_callback(MsfRpcMethod.AuthLogin, [user, password])
        try:
            if auth['result'] == 'success':
                self.token = auth['token']
                token = self.add_perm_token()
                self.token = token
                print("[*] Login successful with token ", token)
                return True
        except Exception:
            raise MsfAuthError("MsfRPC: Authentication failed")

    def add_perm_token(self):
        """
        Add a permanent UUID4 API token
        """
        token = str(uuid.uuid4())
        self.msf_callback(MsfRpcMethod.AuthTokenAdd, [token])
        return token

    def logout(self):
        """
        Logs the current user out. Note: do not call directly.
        """
        self.msf_callback(MsfRpcMethod.AuthLogout, [self.token])
        print("User logged out")

################################################################################
# MSF Console
################################################################################

class MsfConsole(object):
    def __init__(self, client, cid=None, callback=None):
        """
        Initialises an msf console object via RPC.

        Mandatory Arguments:
        - client : an msfrpc client object.

        Optional Arguments:
        - consoleid : the console identifier if it exists already otherwise a
        new one will be created.
        """
        self.client = client
        self.cid = cid
        self.msf_prompt = '' # console user prompt
        self.msf_data = {}
        self.msf_lock = Lock()
        self.console_lock = Lock()
        self.running = False
        # create a new msf console
        r = self.client.msf_callback(MsfRpcMethod.ConsoleCreate)
        if 'id' in r:
            self.cid = r['id']
            print("[*] Console created")
        else:
            raise MsfRpcError("[-] Unable to create a new console")
        self.msf_read_write() # discard metasploit startup output
        # start polling for I/O and msf console commands and responses
        Thread(self.start_polling()).start()

    def start_polling(self):
        """I/O and Msf console poller"""
        self.running = True
        while self.running:
            # read user-console input
            input = select.select([sys.stdin], [], [], 1)[0]
            if input:
                command = sys.stdin.readline().strip()
                self.display('echo: ' + command)
                self.execute(command)
            # read msf-console output
            else:
                self.msf_data = self.msf_read_write()
                if self.msf_data['data'] != '':
                    self.display(self.msf_data)
                    self.display(self.msf_prompt)
                if 'prompt' in self.msf_data.keys() and \
                    self.msf_data['prompt'] != self.msf_prompt:
                        self.msf_prompt = self.msf_data['prompt']
                        self.display(self.msf_prompt)
            time.sleep(0.1)

    def execute(self, command):
        """
        Execute a command on the console.
        """
        # run external commands
        if command.startswith('#'):
            if "login nessus" in command:
                command = "nessus_connect " + NESSUS_USERNAME + \
                                              ':' + \
                                              NESSUS_PASSWORD + \
                                              "@kali:8834 ok"
                self.execute(command)
        # run msf commands
        else:
            if not command.endswith('\n'):
                command += '\n'
            # check if console avaliable
            if self.is_busy():
                raise MsfError('Console {} is busy'.format(self.cid))
                self.msf_wait()
            self.msf_read_write(command)

    def msf_read_write(self, command=None):
        """
        Read or write data to the console. Combined to clear buffer and lock.
        """
        self.msf_lock.acquire()
        d = self.client.msf_callback(MsfRpcMethod.ConsoleRead, [self.cid])
        if command:
            if not command.endswith('\n'):
                command += '\n'
            self.client.msf_callback(MsfRpcMethod.ConsoleWrite, \
                                     [self.cid, command])
        self.msf_lock.release()
        return d

    def msf_wait(self):
        """
        Wait for console to become avaliable
        """
        while self.is_busy():
            time.sleep(1)

    def display(self, output):
        """
        Write string to display console
        """
        if type(output) is str:
            output = output.replace('\x01', '').replace('\x02', '')
        elif type(output) is dict:
            # parse msfrpc data types
            if 'data' in output.keys() and output['data']:
                output = output['data']
            elif 'results' in output.keys() and output['result']:
                output = "Results: ' + output['result']"
        print(output)

    def sessionkill(self):
        """
        Kill all active meterpreter or shell sessions.
        """
        self.client.msf_callback(MsfRpcMethod.ConsoleSessionKill, [self.cid])

    def sessiondetach(self):
        """
        Detach the current meterpreter or shell session.
        """
        self.client.msf_callback(MsfRpcMethod.ConsoleSessionDetach, [self.cid])

    def tabs(self, line):
        """
        Tab completion for console commands.
        Mandatory Arguments:
        - line : a partial command to be completed.
        """
        return self.client.msf_callback(MsfRpcMethod.ConsoleTabs, \
                                        [self.cid, line])['tabs']

    def stop_polling(self):
        """Stop console from polling I/O and msf response"""
        self.running = False

    def destroy(self):
        """
        Destroy the console.
        """
        self.client.msf_callback(MsfRpcMethod.ConsoleDestroy, [self.cid])

    def is_busy(self):
        """
        Checks if the console is busy. We can't use .read() because that clears
        the data buffer.
        We must do this by using .list instead.
        """
        cons = self.client.msf_callback(MsfRpcMethod.ConsoleList)['consoles']
        for c in cons:
            if c['id'] == self.cid:
                return c['busy']

################################################################################
# Option Parsing and Encoding
################################################################################

def parseargs():
    p = OptionParser()
    p.add_option("-P", dest="password", \
                       help="Specify the password to access msfrpcd", \
                       metavar="opt")
    p.add_option("-S", dest="ssl", \
                       help="Disable SSL on the RPC socket", \
                       action="store_false", \
                       default=False)
    p.add_option("-U", dest="username", \
                       help="Specify the username to access msfrpcd", \
                       metavar="opt", \
                       default=MSF_USER)
    p.add_option("-a", dest="server", \
                       help="Connect to this IP address", \
                       metavar="host", \
                       default=MSF_SERVER)
    p.add_option("-p", dest="port", \
                       help="Connect to the specified port instead of 55552", \
                       metavar="opt", \
                       default=MSF_PORT)
    o, a = p.parse_args()
    if o.password is None:
        print('[-] Error: a password must be specified (-P)\n')
        p.print_help()
        exit(-1)
    return o

def convert(data):
    """
    Converts all bytestrings to utf8
    """
    if isinstance(data, bytes):  return data.decode('utf-8')
    if isinstance(data, list):   return list(map(convert, data))
    if isinstance(data, set):    return set(map(convert, data))
    if isinstance(data, dict):   return dict(map(convert, data.items()))
    if isinstance(data, tuple):  return map(convert, data)
    return data

def encode(data):
    return msgpack.packb(data)

def decode(data):
    return msgpack.unpackb(data)

################################################################################
# Main
################################################################################

if __name__ == '__main__':
    o = parseargs()
    try:
        client = MsfClient(o.__dict__.pop('password'), **o.__dict__)
        console = MsfConsole(client)
        # m.interact('')
    except MsfRpcError:
        print(str(client))
        exit(-1)
    exit(0)
