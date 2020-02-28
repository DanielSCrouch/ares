#!/usr/bin/env python3

import os
import requests
import uuid
import msgpack
import time
import sys
import select
import queue
from dotenv import load_dotenv
from threading import Timer, Lock, Thread
from optparse import OptionParser
from cmd import Cmd
#
from registrar import Registrar

################################################################################
# Envionment imports (API Keys etc)
################################################################################

load_dotenv()
MSF_SERVER = os.getenv('MSF_SERVER')
MSF_PORT = os.getenv('MSF_PORT')
MSF_USER = os.getenv('MSF_USER')
MSF_PASSWORD = os.getenv('MSF_PASSWORD')

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

    def __init__(self, password=MSF_PASSWORD, **kwargs):
        self.host = kwargs.get('server', MSF_SERVER)
        self.port = kwargs.get('port', MSF_PORT)
        self.ssl = kwargs.get('ssl', False)
        self.user = kwargs.get('username', MSF_USER)
        self.password = password
        #
        self.uri = kwargs.get('uri', '/api/')
        self.headers = {"Content-type": "binary/message-pack"}
        self.consoles = {} # dict of consoles {cid: MsfConsole Object}
        self.token = None

    def login(self):
        auth = self.msf_callback(MsfRpcMethod.AuthLogin,
                                 [self.user, self.password])
        try:
            if auth['result'] == 'success':
                self.token = auth['token']
                token = self.add_perm_token()
                self.token = token
            else:
                raise NameError(auth['result'])
        except Exception as e:
            raise MsfAuthError("MsfRPC: Authentication failed \n", e)

    def msf_callback(self, method, opts=[]):
        """
        Send command/method to msfrpc console.
        """
        time.sleep(0.2) # sync time
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
        try:
            r = requests.post(url, data=payload,            \
                                   headers=self.headers,    \
                                   verify=False,            \
                                   timeout=5.0)
        except Exception as e:
            raise Exception(e)

        opts[:] = []  # Clear opts list
        return convert(decode(r.content))  # convert all keys/vals to utf8

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

class MsfConsole(Cmd):
    prompt = 'msf>>>'

    def __init__(self, client, registrar=Registrar()):
        """
        Initialises an msf console object via RPC.

        Mandatory Arguments:
        - client : an msfrpc client object.

        Optional Arguments:
        - registrar : a registrar object
        for keeping track of input, output pairs
        """
        super(MsfConsole, self).__init__()
        self.client = client
        self.registrar = registrar
        #
        self.cid = None
        self.msf_lock = Lock()
        self.polling = False
        # create a new msf console
        r = self.client.msf_callback(MsfRpcMethod.ConsoleCreate)
        if 'id' in r:
            self.cid = r['id']
        else:
            raise MsfRpcError("unable to create a new console")
        # discard metasploit startup output
        while self.check_busy():
            print('is busy is working')
            time.sleep(0.1)
        time.sleep(1) # wait for intro to print
        self.write_read()
        # check for unexpected outputs
        try:
            Thread(target=self.error_polling).start()
        except Exception as e:
            print("[!] Error: ", e)

    def error_polling(self):
        """
        Poll msfrpc for unexpected outputs,
        i.e commands not generated by callback function.
        """
        self.polling = True
        while self.polling:
            msf_reply = self.write_read()
            if 'data' in msf_reply.keys() and len(msf_reply['data']) > 0:
                print("[!] unexpected console data:")
                self.display(str(msf_reply))
            time.sleep(0.5)

    def precmd(self, cmd):
        return Cmd.precmd(self, cmd)

    def write_read(self, cmd=None):
        """
        Write and read data to/from the msf server, with prompt update.
        Returns msf console response.
        """
        self.msf_lock.acquire()
        # send command
        if cmd and not cmd.endswith('\n'):
            cmd += '\n'
        if cmd:
            opts = [self.cid, cmd]
            self.client.msf_callback(MsfRpcMethod.ConsoleWrite, opts)

        # wait until console not busy
        time.sleep(0.1)
        if self.check_busy():
            print('[*] msfconsole loading...')
        timer = 0
        while self.check_busy() and timer <= 10:
            timer += 0.1
            time.sleep(0.1)
        if self.check_busy() and timer == 10:
            print('[!] msf console timeout: busy for >10s')
        # receive response
        opts = [self.cid]
        msf_reply = self.client.msf_callback(MsfRpcMethod.ConsoleRead, opts)
        # update msf prompt
        if 'prompt' in msf_reply.keys() and \
            msf_reply['prompt'] != self.prompt:
                prompt = msf_reply['prompt'].replace('\x01', '')
                prompt = prompt.replace('\x02', '')
                self.prompt = prompt.replace("msf5 >", "msf>>>")
        # return response
        self.msf_lock.release()
        return msf_reply

    def check_busy(self):
        """
        Checks if the console is busy.
        """
        msf_reply = self.client.msf_callback(MsfRpcMethod.ConsoleList)
        msf_consoles = msf_reply['consoles']
        for console in msf_consoles:
            if console['id'] == self.cid:
                busy_status = console['busy']
                return console['busy']
        raise Exception("[!] Busy check, console not found.")

    def display(self, str):
        """
        Write msf response string to display console
        """
        str = str.replace('\x01', '')
        str = str.replace('\x02', '')
        str = str.replace('[*]', '[m]')
        print(str)

    def default(self, cmd):
        """
        Default console command, defined by cmd superclass.
        """
        self.callback(cmd)

    def callback(self, cmd, verbose=True):
        """
        Forward cmd to msfrpc console then record and display response.
        Optional Arguments:
        - verbose: print to cmd by default, set to false to prevent print 
        """
        msf_data = self.write_read(cmd)['data']
        # record write and read with registrar
        id = str(uuid.uuid4())
        self.registrar.record(id, cmd, msf_data)
        # display reply
        if verbose:
            self.display(msf_data)
        return msf_data

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

    def destroy(self):
        """
        Destroy the console.
        """
        self.client.msf_callback(MsfRpcMethod.ConsoleDestroy, [self.cid])

    def do_exit(self, cmd):
        """
        Exit the metasploit (msf) console
        """
        return True

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
    msf_client = MsfClient()
    msf_client.login()
    msf_console = MsfConsole(msf_client)
    msf_console.cmdloop()

    # o = parseargs()
    # try:
    #     client = MsfClient(o.__dict__.pop('password'), **o.__dict__)
    #     console = MsfConsole(client)
    #     # m.interact('')
    # except MsfRpcError:
    #     print(str(client))
    #     exit(-1)
    # exit(0)
