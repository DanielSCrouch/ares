
import io
import time
from threading import Thread
from contextlib import redirect_stdout
# local imports
import config

################################################################################
# Unit tests
################################################################################


class Tests(object):
    """
    Defines a collection of tests to be executed through the console
    """

    def test(self, option):
        if option == "1":
            self.test1()
        if option == "2":
            self.test2()
        if option == "3":
            self.test3()
        if option == "4":
            self.test4()
        if option == "5":
            self.test5()
        if option == "6":
            self.test6()

    def test1(self):
        """
        Initial setup test
        """
        print("[*] Running test 1: setup")
        f = io.StringIO()
        with redirect_stdout(f):
            ###
            start_time = time.time()
            try:
                config.CONSOLE.do_setup('')
            except Exception as e:
                print("[!] Exception raised \n", e)
            time_ela = int(time.time() - start_time)
            ###
        s = f.getvalue()
        # checks
        checks = ["[+] PostgreSQL database now avaliable",
                  "[+] Metasploit now avaliable",
                  "[+] Nessus now avaliable",
                  "[+] Metasploit client login successfull",
                  "[+] msf console now avaliable, see 'help msf'",
                  "[+] Nessus now avaliable to msf",
                  "[+] Metasploit connected to database",
                  "[*] setup complete"]
        for check in checks:
            if check not in s:
                print("[!] Test failed on check: ", check)
                return
        print("[*] Test passed in", time_ela, "seconds")

    def test2(self):
        """
        Host scan test
        """
        print("[*] Running test 2: host scanning")
        f = io.StringIO()
        with redirect_stdout(f):
            ###
            start_time = time.time()
            try:
                config.CONSOLE.do_scan('hosts 172.16.231.130-131')
            except Exception as e:
                print("[!] Exception raised \n", e)
            time_ela = int(time.time() - start_time)
            ###
        s = f.getvalue()
        # checks
        checks = ["172.16.231.130 - live",
                  "172.16.231.131 - live"]
        for check in checks:
            if check not in s:
                print("[!] Test failed on check: ", check)
                return
        print("[*] Test passed in", time_ela, "seconds")

    def test3(self):
        """
        Targeting Test
        """
        print("[*] Running test 3: targetting")
        f = io.StringIO()
        with redirect_stdout(f):
            ###
            start_time = time.time()
            try:
                config.CONSOLE.do_setup('')
                config.CONSOLE.do_target('bruce 172.16.231.130')
                config.CONSOLE.do_target('nigel 172.16.231.131')
            except Exception as e:
                print("[!] Exception raised \n", e)
            time_ela = int(time.time() - start_time)
            ###
        s = f.getvalue()
        # checks
        checks = ["bruce 172.16.231.130",
                  "nigel 172.16.231.131"]
        for check in checks:
            if check not in s:
                print("[!] Test failed on check: ", check)
                return
        print("[*] Test passed in", time_ela, "seconds")

    def test4(self):
        """
        Port scan test
        """
        print("[*] Running test 4: port scan")
        f = io.StringIO()
        with redirect_stdout(f):
            ###
            start_time = time.time()
            try:
                config.CONSOLE.do_setup('')
                config.CONSOLE.do_target('bruce 172.16.231.130')
                config.CONSOLE.do_target('nigel 172.16.231.131')
                config.CONSOLE.do_scan('ports bruce')
            except Exception as e:
                print("[!] Exception raised \n", e)
            time_ela = int(time.time() - start_time)
            ###
        s = f.getvalue()
        # checks
        if len(config.TARGETS['bruce'].tcp_ports) != 9 or \
            len(config.TARGETS['bruce'].udp_ports) != 4:
                print("[!] Test failed to find all ports")
                return
        print("[*] Test passed in", time_ela, "seconds")

    def test5(self):
        """
        Import scan test (port and full)
        """
        print("[*] Running test 5: import scan (port and full)")
        f = io.StringIO()
        with redirect_stdout(f):
            ###
            start_time = time.time()
            try:
                config.CONSOLE.do_setup('')
                config.CONSOLE.do_target('bruce 172.16.231.130')
                config.CONSOLE.do_target('nigel 172.16.231.131')
                config.CONSOLE.do_import('port bruce')
                config.CONSOLE.do_import('full bruce')
                config.CONSOLE.do_import('port nigel')
                config.CONSOLE.do_import('full nigel')
            except Exception as e:
                print("[!] Exception raised \n", e)
            time_ela = int(time.time() - start_time)
            ###
        s = f.getvalue()
        # checks
        if len(config.TARGETS['bruce'].tcp_ports) != 10 or \
            len(config.TARGETS['bruce'].udp_ports) != 4 or \
            len(config.TARGETS['nigel'].tcp_ports) != 10 or \
            len(config.TARGETS['nigel'].udp_ports) != 4 or \
            len(config.TARGETS['bruce'].vulns.keys()) != 16 or \
            len(config.TARGETS['nigel'].vulns.keys()) != 16:
                print("[!] Test failed to import all scan data")
                return
        print("[*] Test passed in", time_ela, "seconds")

    def test6(self):
        """
        Planning, initial access
        """
        print("[*] Running test 6: plan (initial access)")
        f = io.StringIO()
        with redirect_stdout(f):
            ###
            start_time = time.time()
            try:
                config.CONSOLE.do_setup('')
                config.CONSOLE.do_target('bruce 172.16.231.130')
                config.CONSOLE.do_target('nigel 172.16.231.131')
                config.CONSOLE.do_import('port bruce')
                config.CONSOLE.do_import('full bruce')
                config.CONSOLE.do_import('port nigel')
                config.CONSOLE.do_import('full nigel')
                # limit initial access options (bruce msql only)
                config.TARGETS['bruce'].action_history = \
                                                    ["exploit_cve_2008_4250"]
                config.TARGETS['nigel'].action_history = \
                                                    ["exploit_cve_2008_4250"]
                config.TARGETS['nigel'].action_history.append(\
                                                    "exploit_msql_brute_force")
                config.CONSOLE.do_plan('')
                # limit initial access options (nigel msql only)
                config.TARGETS['bruce'].action_history = \
                                                    ["exploit_cve_2008_4250"]
                config.TARGETS['nigel'].action_history = \
                                                    ["exploit_cve_2008_4250"]
                config.TARGETS['bruce'].action_history.append(\
                                                    "exploit_msql_brute_force")
                config.CONSOLE.do_plan('')
                # limit initial access options (bruce 4250 only)
                config.TARGETS['bruce'].action_history = \
                                                    ["exploit_msql_brute_force"]
                config.TARGETS['nigel'].action_history = \
                                                    ["exploit_msql_brute_force"]
                config.TARGETS['nigel'].action_history.append(\
                                                    "exploit_cve_2008_4250")
                config.CONSOLE.do_plan('')
                # limit initial access options (bruce msql only)
                config.TARGETS['bruce'].action_history = \
                                                    ["exploit_msql_brute_force"]
                config.TARGETS['nigel'].action_history = \
                                                    ["exploit_msql_brute_force"]
                config.TARGETS['bruce'].action_history.append(\
                                                    "exploit_cve_2008_4250")
                config.CONSOLE.do_plan('')
            except Exception as e:
                print("[!] Exception raised \n", e)
            time_ela = int(time.time() - start_time)
            ###
        s = f.getvalue()
        print("*******************")
        print(s)
        print("*******************")
        # checks
        if "EXPLOIT_MSQL_BRUTE_FORCE BRUCE" not in s \
            or "EXPLOIT_CVE_2008_4250 BRUCE" not in s \
            or "EXPLOIT_MSQL_BRUTE_FORCE NIGEL" not in s\
            or "EXPLOIT_CVE_2008_4250 NIGEL" not in s:
                print("[!] Test failed: no initial access attack planned")
                return
        print("[*] Test passed in", time_ela, "seconds")
