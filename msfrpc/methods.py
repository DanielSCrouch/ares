# Provides Metasploit RPC command translations 
#
# Author: Daniel Crouch
# Date created: March 2020

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
