
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
