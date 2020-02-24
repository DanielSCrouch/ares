#!/usr/bin/env python3

import os
import requests
import uuid
import msgpack
import time
from dotenv import load_dotenv
from threading import Timer, Lock
from optparse import OptionParser

# import default password
load_dotenv()
MSF_SERVER = os.getenv('MSF_SERVER')
MSF_PORT = os.getenv('MSF_PORT')
MSF_USER = os.getenv('MSF_USER')
MSF_PASSWORD = os.getenv('MSF_PASSWORD')
NESSUS_USERNAME = os.getenv('NESSUS_USERNAME')
NESSUS_PASSWORD = os.getenv('NESSUS_PASSWORD')


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

##############################################################
### Error Handling

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

##############################################################
### MSF Client

class MsfClient(object):

    def __init__(self, password, **kwargs):
        self.host = kwargs.get('server', MSF_SERVER)
        self.port = kwargs.get('port', MSF_PORT)
        self.ssl = kwargs.get('ssl', False)
        self.user = kwargs.get('username', MSF_USER)
        #
        self.uri = kwargs.get('uri', '/api/')
        self.headers = {"Content-type": "binary/message-pack"}
        self.consoles = {} # dict of consoles {cid: MsfConsole Object}

        print('sssssssssss: ', self.ssl)
        print('Logging in user', self.user)
        time.sleep(0.5)
        self.login(kwargs.get('username', 'msf'), password)


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
                print("Login successful")
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


#####################################################################
### MSF Console

class MsfConsole(object):
    def __init__(self, client, cid=None, callback=None):
        """
        Initialises an msf console object via RPC.

        Mandatory Arguments:
        - client : an msfrpc client object.

        Optional Arguments:
        - consoleid : the console identifier if it exists already otherwise a new one will be created.
        - callback : a callback function that gets called when data is received from the console.
        """
        self.client = client
        self.cid = cid
        self.callback = callback

        self.prompt = '' # console user prompt
        self.lock = Lock()
        self.running = False

        # create a new msf console
        r = self.client.msf_callback(MsfRpcMethod.ConsoleCreate)
        if 'id' in r:
            self.cid = r['id']
        else:
            raise MsfRpcError("[-] Unable to create a new console")
        # self.prompt = '>>> '
        # self.callback(dict(data='', prompt=self.prompt))

        # run i/o poller, lock console while in use
        self.poller()

    def read(self):
        """
        Read data from the console.
        """
        return self.client.msf_callback(MsfRpcMethod.ConsoleRead, [self.cid])

    def write(self, command):
        """
        Write data to the console.
        """
        if not command.endswith('\n'):
            command += '\n'
        self.client.msf_callback(MsfRpcMethod.ConsoleWrite, [self.cid, command])

    def poller(self):
        """Repetivie I/O console poller"""
        self.running = True
        # read console output
        self.lock.acquire()
        data = self.read()
        self.lock.release()

        if data['data'] or self.prompt != data['prompt']:
            self.prompt = data['prompt']
            if self.callback is not None:
                pass
                # self.callback(d)
            else:
                print(data['data'])
        else:
            if data:
                if self.callback is not None:
                    pass
                    # self.callback(dict(data=d, prompt=self.prompt))
                else:
                    print(data)
        Timer(0.5, self.poller).start()

    def execute(self, command):
        """
        Execute a command on the console.

        Mandatory Arguments:
        - command : the command to execute
        """
        if not command.endswith('\n'):
            command += '\n'
        self.lock.acquire()
        self.write(command)
        self.lock.release()

    def delete(self):
        self.lock.acquire()
        if self.type_ == MsfRpcConsoleType.Console:
            self.console.destroy()
        self.running = False
        self.lock.release()

    # def raw_input(self, prompt):
    #     line = InteractiveConsole.raw_input(self, prompt=self.client.prompt)
    #     return "rpc.execute('%s')" % line.replace("'", r"\'")
    #
    # def callback(self, d):
    #     stdout.write('\n%s' % d['data'])
    #     if not self.fl:
    #         stdout.write('\n%s' % d['prompt'])
    #         stdout.flush()
    #     else:
    #         self.fl = False




##############################################################
### MSF Console (Callable)

class MsfConsole1(object):

    def __init__(self, rpc, cid=None):
        """
        Initializes an msf console object.
        Mandatory Arguments:
        - rpc : the msfrpc client object.

        - cid : the console identifier if it exists already otherwise a new one will be created.
        """

        self.rpc = rpc
        if cid is None:
            r = self.rpc.msf_callback(MsfRpcMethod.ConsoleCreate)
            if 'id' in r:
                self.cid = r['id']
            else:
                raise MsfRpcError("Unable to create a new console")

    def read(self):
        """
        Read data from the console.
        """
        return self.rpc.msf_callback(MsfRpcMethod.ConsoleRead, [self.cid])

    def write(self, command):
        """
        Write data to the console.
        """
        if not command.endswith('\n'):
            command += '\n'
        self.rpc.msf_callback(MsfRpcMethod.ConsoleWrite, [self.cid, command])

    def sessionkill(self):
        """
        Kill all active meterpreter or shell sessions.
        """
        self.rpc.msf_callback(MsfRpcMethod.ConsoleSessionKill, [self.cid])

    def sessiondetach(self):
        """
        Detach the current meterpreter or shell session.
        """
        self.rpc.msf_callback(MsfRpcMethod.ConsoleSessionDetach, [self.cid])

    def tabs(self, line):
        """
        Tab completion for console commands.
        Mandatory Arguments:
        - line : a partial command to be completed.
        """
        return self.rpc.msf_callback(MsfRpcMethod.ConsoleTabs, [self.cid, line])['tabs']

    def destroy(self):
        """
        Destroy the console.
        """
        self.rpc.msf_callback(MsfRpcMethod.ConsoleDestroy, [self.cid])

    def is_busy(self):
        """
        Checks if the console is busy. We can't use .read() because that clears the data buffer.
        We must do this by using .list instead.
        """
        cons = self.rpc.msf_callback(MsfRpcMethod.ConsoleList)['consoles']
        for c in cons:
            if c['id'] == self.cid:
                return c['busy']

    def execute(self, command=None):
        """
        Execute a console command and wait for the returned data
        Optional Keyword Arguments:
        - command : the command to be passed to the msfconsole
        """
        print('starting execution')
        # check if console avaliable
        if self.rpc.console.is_busy():
            print("console is busy")
            raise MsfError('Console {} is busy'.format(self.cid))
        # self.read() # clear data buffer
        # run command to console without directly opening a command line
        command_str = command + '\n'
        print(command_str)
        if 'run' in command_str and 'run -z' not in command_str:
            command_str.replace('run', 'run -z')
        print("writing")
        self.write(command_str)
        print("that's finished")
        data = ''
        while data == '' or self.rpc.console.is_busy():
            time.sleep(1)
            data += self.read()['data']
        print('returning data')
        return data

##############################################################
##############################################################
##############################################################
##############################################################
##############################################################
##############################################################
##############################################################
##############################################################







#
##############################################################
##############################################################
##############################################################
##############################################################
##############################################################
##############################################################
##############################################################
# ##############################################################
# ### Option Parsing and Encoding
#
def parseargs():
    p = OptionParser()
    p.add_option("-P", dest="password", help="Specify the password to access msfrpcd", metavar="opt")
    p.add_option("-S", dest="ssl", help="Disable SSL on the RPC socket", action="store_false", default=True)
    p.add_option("-U", dest="username", help="Specify the username to access msfrpcd", metavar="opt", default="msf")
    p.add_option("-a", dest="server", help="Connect to this IP address", metavar="host", default="127.0.0.1")
    p.add_option("-p", dest="port", help="Connect to the specified port instead of 55552", metavar="opt", default=55553)
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


##############################################################
### Testing

if __name__ == "__main__":
    client = MsfClient("K!ng5", username='msf')
    console = MsfConsole(client)
    print("Waiting for the console to load...")
    time.sleep(3)
    print("loading nessus")
    print(console.execute(command="load nessus"))
    time.sleep(3)
    print("running nessus")
    print(console.execute(command='nessus_connect kalikings:K!ng5@kali:8834 ok'))
    time.sleep(8)
    print("running nessus")
    print(console.execute(command='show options'))



# if __name__ == '__main__':
#     o = parseargs()
#     try:
#         m = MsfRpc(o.__dict__.pop('password'), **o.__dict__)
#         m.interact('')
#     except MsfRpcError, m:
#         print str(m)
#         exit(-1)
#     exit(0)
