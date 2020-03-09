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
# Local imports
################################################################################

from .exceptions import MsfRpcError
from .methods import MsfRpcMethod

################################################################################
# Envionment imports (API Keys etc)
################################################################################

load_dotenv()
MSF_SERVER = os.getenv('MSF_SERVER')
MSF_PORT = os.getenv('MSF_PORT')
MSF_USER = os.getenv('MSF_USER')
MSF_PASSWORD = os.getenv('MSF_PASSWORD')

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
        self.connection = None
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
                                   stream=False,            \
                                   timeout=10.0)
        except Exception as e:
            raise Exception(e)

        opts[:] = []  # Clear opts list
        return convert(decode(r.content))  # convert all keys/vals to utf8

    def close_connection(self):
        if self.ssl is True:
            url = "https://%s:%s%s" % (self.host, self.port, self.uri)
        else:
            url = "http://%s:%s%s" % (self.host, self.port, self.uri)

        try:
            r = requests.post(url, headers={'Connection':'close'},    \
                                   verify=False,                      \
                                   timeout=10.0)
        except Exception as e:
            raise Exception(e)

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
# Encoding
################################################################################

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
# Option Parsing
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

################################################################################
# Main
################################################################################

if __name__ == '__main__':
    # msf_client = MsfClient()
    # msf_client.login()
    pass

    # o = parseargs()
    # try:
    #     client = MsfClient(o.__dict__.pop('password'), **o.__dict__)
    #     console = MsfConsole(client)
    #     # m.interact('')
    # except MsfRpcError:
    #     print(str(client))
    #     exit(-1)
    # exit(0)
