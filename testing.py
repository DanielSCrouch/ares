
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
        if option == "7":
            self.test7()
        if option == "8":
            self.test8()

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
                config.CONSOLE.do_target('t1 172.16.231.130')
                config.CONSOLE.do_target('t2 172.16.231.131')
            except Exception as e:
                print("[!] Exception raised \n", e)
            time_ela = int(time.time() - start_time)
            ###
        s = f.getvalue()
        # checks
        checks = ["t1 172.16.231.130",
                  "t2 172.16.231.131"]
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
                config.CONSOLE.do_target('t1 172.16.231.130')
                config.CONSOLE.do_target('t2 172.16.231.131')
                config.CONSOLE.do_scan('ports t1')
            except Exception as e:
                print("[!] Exception raised \n", e)
            time_ela = int(time.time() - start_time)
            ###
        s = f.getvalue()
        # checks
        if len(config.TARGETS['t1'].tcp_ports) != 9 or \
            len(config.TARGETS['t1'].udp_ports) != 4:
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
                config.CONSOLE.do_target('t1 172.16.231.130')
                config.CONSOLE.do_target('t2 172.16.231.131')
                config.CONSOLE.do_import('port t1')
                config.CONSOLE.do_import('full t1')
                config.CONSOLE.do_import('port t2')
                config.CONSOLE.do_import('full t2')
            except Exception as e:
                print("[!] Exception raised \n", e)
            time_ela = int(time.time() - start_time)
            ###
        s = f.getvalue()
        # checks
        if len(config.TARGETS['t1'].tcp_ports) != 10 or \
            len(config.TARGETS['t1'].udp_ports) != 4 or \
            len(config.TARGETS['t2'].tcp_ports) != 10 or \
            len(config.TARGETS['t2'].udp_ports) != 4 or \
            len(config.TARGETS['t1'].vulns.keys()) != 16 or \
            len(config.TARGETS['t2'].vulns.keys()) != 16:
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
                config.CONSOLE.do_target('t1 172.16.231.130')
                config.CONSOLE.do_target('t2 172.16.231.131')
                config.CONSOLE.do_import('port t1')
                config.CONSOLE.do_import('full t1')
                config.CONSOLE.do_import('port t2')
                config.CONSOLE.do_import('full t2')
                # limit initial access options (t1 msql only)
                config.TARGETS['t1'].action_history = \
                                                    ["exploit_cve_2008_4250"]
                config.TARGETS['t2'].action_history = \
                                                    ["exploit_cve_2008_4250"]
                config.TARGETS['t2'].action_history.append(\
                                                    "exploit_msql_brute_force")
                config.CONSOLE.do_plan('')
                # limit initial access options (t2 msql only)
                config.TARGETS['t1'].action_history = \
                                                    ["exploit_cve_2008_4250"]
                config.TARGETS['t2'].action_history = \
                                                    ["exploit_cve_2008_4250"]
                config.TARGETS['t1'].action_history.append(\
                                                    "exploit_msql_brute_force")
                config.CONSOLE.do_plan('')
                # limit initial access options (t1 4250 only)
                config.TARGETS['t1'].action_history = \
                                                    ["exploit_msql_brute_force"]
                config.TARGETS['t2'].action_history = \
                                                    ["exploit_msql_brute_force"]
                config.TARGETS['t2'].action_history.append(\
                                                    "exploit_cve_2008_4250")
                config.CONSOLE.do_plan('')
                # limit initial access options (t1 msql only)
                config.TARGETS['t1'].action_history = \
                                                    ["exploit_msql_brute_force"]
                config.TARGETS['t2'].action_history = \
                                                    ["exploit_msql_brute_force"]
                config.TARGETS['t1'].action_history.append(\
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
        if "EXPLOIT_MSQL_BRUTE_FORCE t1" not in s \
            or "EXPLOIT_CVE_2008_4250 t1" not in s \
            or "EXPLOIT_MSQL_BRUTE_FORCE t2" not in s\
            or "EXPLOIT_CVE_2008_4250 t2" not in s:
                print("[!] Test failed: no initial access attack planned")
                return
        print("[*] Test passed in", time_ela, "seconds")


    def test7(self):
        """
        Multi-stage
        """
        print("[*] Running test 6: plan (multi-stage)")
        f = io.StringIO()
        with redirect_stdout(f):
            ###
            start_time = time.time()
            try:
                config.CONSOLE.do_setup('')
                config.CONSOLE.do_target('t1 172.16.231.130')
                config.CONSOLE.do_target('t2 172.16.231.130')
                config.CONSOLE.do_target('t3 172.16.231.130')
                config.CONSOLE.do_target('t4 172.16.231.130')
                config.CONSOLE.do_target('t5 172.16.231.130')
                config.CONSOLE.do_target('t25 172.16.231.131')
                # config.CONSOLE.do_import('port t1')
                # config.CONSOLE.do_import('full t1')
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
        print("[*] Test completed in", time_ela, "seconds")

    def test8(self):
        """
        Persistance (command and control)
        """
        print("[*] Running test 8: command and control")
        f = io.StringIO()
        with redirect_stdout(f):
            ###
            start_time = time.time()
            try:
                config.CONSOLE.do_setup('')
                config.CONSOLE.do_target('t1 172.16.231.130')
                config.CONSOLE.do_target('t2 172.16.231.131')
                config.CONSOLE.do_import('port t1')
                # config.CONSOLE.do_import('full t1')
                config.CONSOLE.do_import('port t2')
                # config.CONSOLE.do_import('full t2')
                # config.CONSOLE.do_exploit('cve-2008-4250 t1')
                # original_session = config.TARGETS['t1'].session_id
                # config.CONSOLE.do_exploit('persistance t1')
            except Exception as e:
                print("[!] Exception raised \n", e)
            time_ela = int(time.time() - start_time)
            ###
        s = f.getvalue()
        print("*******************")
        # print(s)
        print("*******************")
        # checks
        # if original_session != config.TARGETS['t1'].session_id:
            # print("[*] Test passed in", time_ela, "seconds")
        # else:
            # print("[*] Test failed")
