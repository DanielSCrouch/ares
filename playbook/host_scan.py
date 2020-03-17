
import re
import subprocess
# global variables
# import config

################################################################################
# Generic Console Command Class - containing methods
################################################################################

class HostScan(object):
    """
    Defines a collection of scan methods.
    """

    def scan(self, ip_range, verbose=False):
        """
        Return list of detected hosts.
        """
        # start scan in shell
        cmd = ["nmap -sP " + ip_range]
        process = subprocess.Popen(cmd,       \
                   stdin = subprocess.PIPE,   \
                   stdout = subprocess.PIPE,  \
                   stderr = subprocess.PIPE,  \
                   universal_newlines = True, \
                   shell=True,                \
                   bufsize=0)
        # wait for completion
        process.wait(timeout=10)
        # raise errors
        error_stream = process.stderr
        error = error_stream.read()
        if error:
            raise Exception(error)
        # process output
        output_stream = process.stdout
        output = output_stream.read()
        live_hosts = []
        for word in output.split():
            word = word.replace('(','').replace(')','')
            search = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            if re.match(search, word):
                live_hosts.append(word)
        # display output
        if verbose:
            print('\n    ' + 'hosts' + '\n    ' + '=' * 60)
            for host in live_hosts:
                print('    ' + host + " - live")
        return live_hosts

################################################################################
# Main
################################################################################

if __name__ == '__main__':
    live_hosts = HostScan().scan("10.91.251.100-105")
    print(live_hosts)



#
