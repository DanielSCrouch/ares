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

    def __init__(self, client, registrar=None):
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
            if not self.msf_lock:
                msf_reply = self.write_read()
                if 'data' in msf_reply.keys() and len(msf_reply['data']) > 0:
                    print("[!] unexpected console data:")
                    print('data length: ', len(msf_reply['data']))
                    print('data type: ', type(msf_reply['data']))
                    print('data: ', msf_reply['data'])
                    self.display(msf_reply)
            time.sleep(0.5)

    def write_read(self, cmd=None):
        """
        Write and read data to/from the msf server.
        """
        self.msf_lock.acquire()
        # send command
        if cmd:
            if not cmd.endswith('\n'):
                cmd += '\n'
            self.client.msf_callback(MsfRpcMethod.ConsoleWrite, \
                                     [self.cid, cmd])
            # wait for response
            while self.check_busy():
                print('is busy is working')
                time.sleep(0.1)
        # collect response
        msf_reply = self.client.msf_callback(MsfRpcMethod.ConsoleRead, \
                                                            [self.cid])
        # update msf prompt
        if 'prompt' in msf_reply.keys() and \
            msf_reply['prompt'] != self.prompt:
                prompt = msf_reply['prompt'].replace('\x01', '')
                prompt = prompt.replace('\x02', '')
                self.prompt = prompt.replace("msf5 >", "msf>>>")
        # release lock and print response
        self.msf_lock.release()
        return msf_reply

    def check_busy(self):
        """
        Checks if the console is busy.
        Uses .list() method since .read() clears the data buffer.
        """
        cons = self.client.msf_callback(MsfRpcMethod.ConsoleList)['consoles']
        for c in cons:
            if c['id'] == self.cid:
                return False
        return True

    def display(self, output):
        """
        Write msf response string to display console
        """
        if type(output) is str:
            output = output.replace('\x01', '').replace('\x02', '')
        elif type(output) is dict:
            # parse msfrpc data types
            if 'data' in output.keys() and output['data']:
                output = output['data']
            elif 'results' in output.keys() and output['result']:
                output = "Results: " + output['result']
        print(output)

    def default(self, cmd):
        """
        Default console command, defined by cmd
        """
        try:
            self.callback(cmd)
        except Exception as e:
            print("[!] Error: ", e)

    def callback(self, cmd):
        """
        Forward cmd to msfrpc console and record response.
        """
        msf_reply = self.write_read(cmd)
        # display reply
        self.display(msf_reply)
        # record write and read with registrar
        id = str(uuid.uuid4())
        self.registrar.record(id, cmd, msf_reply)

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
    msf_console.start_polling_subprocess()
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
