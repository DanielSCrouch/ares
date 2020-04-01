
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
            time_ela = time.time() - start_time
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


    def test7(self):
        """
        Multi-stage
        """
        print("[*] Running test 7: plan (multi-stage)")
        f = io.StringIO()
        with redirect_stdout(f):
            ###
            start_time = time.time()
            try:
                # config.CONSOLE.do_setup('')
                config.CONSOLE.do_target('bruce1 172.16.231.130')
                config.CONSOLE.do_target('bruce2 172.16.231.130')
                config.CONSOLE.do_target('bruce3 172.16.231.130')
                config.CONSOLE.do_target('bruce4 172.16.231.130')
                config.CONSOLE.do_target('bruce5 172.16.231.130')
                config.CONSOLE.do_target('bruce6 172.16.231.130')
                config.CONSOLE.do_target('bruce7 172.16.231.130')
                config.CONSOLE.do_target('bruce8 172.16.231.130')
                config.CONSOLE.do_target('bruce9 172.16.231.130')
                config.CONSOLE.do_target('bruce0 172.16.231.130')
                #
                config.CONSOLE.do_target('nigel1 172.16.231.131')
                config.CONSOLE.do_target('nigel2 172.16.231.131')
                config.CONSOLE.do_target('nigel3 172.16.231.131')
                config.CONSOLE.do_target('nigel4 172.16.231.131')
                config.CONSOLE.do_target('nigel5 172.16.231.131')
                config.CONSOLE.do_target('nigel6 172.16.231.131')
                config.CONSOLE.do_target('nigel7 172.16.231.131')
                config.CONSOLE.do_target('nigel8 172.16.231.131')
                config.CONSOLE.do_target('nigel9 172.16.231.131')
                config.CONSOLE.do_target('nigel0 172.16.231.131')
                #
                config.CONSOLE.do_target('luna1 172.16.231.131')
                config.CONSOLE.do_target('luna2 172.16.231.131')
                config.CONSOLE.do_target('luna3 172.16.231.131')
                config.CONSOLE.do_target('luna4 172.16.231.131')
                config.CONSOLE.do_target('luna5 172.16.231.131')
                config.CONSOLE.do_target('luna6 172.16.231.131')
                config.CONSOLE.do_target('luna7 172.16.231.131')
                config.CONSOLE.do_target('luna8 172.16.231.131')
                config.CONSOLE.do_target('luna9 172.16.231.131')
                config.CONSOLE.do_target('luna0 172.16.231.131')
                # # #
                # config.CONSOLE.do_target('cat1 172.16.231.131')
                # config.CONSOLE.do_target('cat2 172.16.231.131')
                # config.CONSOLE.do_target('cat3 172.16.231.131')
                # config.CONSOLE.do_target('cat4 172.16.231.131')
                # config.CONSOLE.do_target('cat5 172.16.231.131')
                # config.CONSOLE.do_target('cat6 172.16.231.131')
                # config.CONSOLE.do_target('cat7 172.16.231.131')
                # config.CONSOLE.do_target('cat8 172.16.231.131')
                # config.CONSOLE.do_target('cat9 172.16.231.131')
                # config.CONSOLE.do_target('cat0 172.16.231.131')
                # # #
                # config.CONSOLE.do_target('dog1 172.16.231.131')
                # config.CONSOLE.do_target('dog2 172.16.231.131')
                # config.CONSOLE.do_target('dog3 172.16.231.131')
                # config.CONSOLE.do_target('dog4 172.16.231.131')
                # config.CONSOLE.do_target('dog5 172.16.231.131')
                # config.CONSOLE.do_target('dog6 172.16.231.131')
                # config.CONSOLE.do_target('dog7 172.16.231.131')
                # config.CONSOLE.do_target('dog8 172.16.231.131')
                # config.CONSOLE.do_target('dog9 172.16.231.131')
                # config.CONSOLE.do_target('dog0 172.16.231.131')
                # # #
                # config.CONSOLE.do_target('sparrow1 172.16.231.131')
                # config.CONSOLE.do_target('sparrow2 172.16.231.131')
                # config.CONSOLE.do_target('sparrow3 172.16.231.131')
                # config.CONSOLE.do_target('sparrow4 172.16.231.131')
                # config.CONSOLE.do_target('sparrow5 172.16.231.131')
                # config.CONSOLE.do_target('sparrow6 172.16.231.131')
                # config.CONSOLE.do_target('sparrow7 172.16.231.131')
                # config.CONSOLE.do_target('sparrow8 172.16.231.131')
                # config.CONSOLE.do_target('sparrow9 172.16.231.131')
                # config.CONSOLE.do_target('sparrow0 172.16.231.131')
                # #
                # config.CONSOLE.do_target('sparrowa1 172.16.231.131')
                # config.CONSOLE.do_target('sparrowa2 172.16.231.131')
                # config.CONSOLE.do_target('sparrowa3 172.16.231.131')
                # config.CONSOLE.do_target('sparrowa4 172.16.231.131')
                # config.CONSOLE.do_target('sparrowa5 172.16.231.131')
                # config.CONSOLE.do_target('sparrowa6 172.16.231.131')
                # config.CONSOLE.do_target('sparrowa7 172.16.231.131')
                # config.CONSOLE.do_target('sparrowa8 172.16.231.131')
                # config.CONSOLE.do_target('sparrowa9 172.16.231.131')
                # config.CONSOLE.do_target('sparrowa0 172.16.231.131')
                # #
                # config.CONSOLE.do_target('sparrowb1 172.16.231.131')
                # config.CONSOLE.do_target('sparrowb2 172.16.231.131')
                # config.CONSOLE.do_target('sparrowb3 172.16.231.131')
                # config.CONSOLE.do_target('sparrowb4 172.16.231.131')
                # config.CONSOLE.do_target('sparrowb5 172.16.231.131')
                # config.CONSOLE.do_target('sparrowb6 172.16.231.131')
                # config.CONSOLE.do_target('sparrowb7 172.16.231.131')
                # config.CONSOLE.do_target('sparrowb8 172.16.231.131')
                # config.CONSOLE.do_target('sparrowb9 172.16.231.131')
                # config.CONSOLE.do_target('sparrowb0 172.16.231.131')
                # #
                # config.CONSOLE.do_target('sparrowc1 172.16.231.131')
                # config.CONSOLE.do_target('sparrowc2 172.16.231.131')
                # config.CONSOLE.do_target('sparrowc3 172.16.231.131')
                # config.CONSOLE.do_target('sparrowc4 172.16.231.131')
                # config.CONSOLE.do_target('sparrowc5 172.16.231.131')
                # config.CONSOLE.do_target('sparrowc6 172.16.231.131')
                # config.CONSOLE.do_target('sparrowc7 172.16.231.131')
                # config.CONSOLE.do_target('sparrowc8 172.16.231.131')
                # config.CONSOLE.do_target('sparrowc9 172.16.231.131')
                # config.CONSOLE.do_target('sparrowc0 172.16.231.131')
                # #
                # config.CONSOLE.do_target('sparrowd1 172.16.231.131')
                # config.CONSOLE.do_target('sparrowd2 172.16.231.131')
                # config.CONSOLE.do_target('sparrowd3 172.16.231.131')
                # config.CONSOLE.do_target('sparrowd4 172.16.231.131')
                # config.CONSOLE.do_target('sparrowd5 172.16.231.131')
                # config.CONSOLE.do_target('sparrowd6 172.16.231.131')
                # config.CONSOLE.do_target('sparrowd7 172.16.231.131')
                # config.CONSOLE.do_target('sparrowd8 172.16.231.131')
                # config.CONSOLE.do_target('sparrowd9 172.16.231.131')
                # config.CONSOLE.do_target('sparrowd0 172.16.231.131')
                # # #
                # config.CONSOLE.do_target('sparrowde1 172.16.231.131')
                # config.CONSOLE.do_target('sparrowde2 172.16.231.131')
                # config.CONSOLE.do_target('sparrowde3 172.16.231.131')
                # config.CONSOLE.do_target('sparrowde4 172.16.231.131')
                # config.CONSOLE.do_target('sparrowde5 172.16.231.131')
                # config.CONSOLE.do_target('sparrowde6 172.16.231.131')
                # config.CONSOLE.do_target('sparrowde7 172.16.231.131')
                # config.CONSOLE.do_target('sparrowde8 172.16.231.131')
                # config.CONSOLE.do_target('sparrowde9 172.16.231.131')
                # config.CONSOLE.do_target('sparrowde0 172.16.231.131')
                # #
                # config.CONSOLE.do_target('sparrowdf1 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdf2 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdf3 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdf4 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdf5 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdf6 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdf7 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdf8 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdf9 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdf0 172.16.231.131')
                # #
                # config.CONSOLE.do_target('sparrowdg1 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdg2 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdg3 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdg4 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdg5 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdg6 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdg7 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdg8 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdg9 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdg0 172.16.231.131')
                # #
                # config.CONSOLE.do_target('sparrowdh1 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdh2 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdh3 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdh4 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdh5 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdh6 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdh7 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdh8 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdh9 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdh0 172.16.231.131')
                # #
                # config.CONSOLE.do_target('sparrowdi1 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdi2 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdi3 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdi4 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdi5 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdi6 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdi7 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdi8 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdi9 172.16.231.131')
                # config.CONSOLE.do_target('sparrowdi0 172.16.231.131')


                # config.CONSOLE.do_import('port bruce')
                # config.CONSOLE.do_import('full bruce')
                config.CONSOLE.do_plan('')
            except Exception as e:
                print("[!] Exception raised \n", e)
            time_ela = time.time() - start_time
            ###
        s = f.getvalue()
        print("*******************")
        print(s)
        print("*******************")
        # checks
        # if "EXPLOIT_MSQL_BRUTE_FORCE BRUCE" not in s \
        #     or "EXPLOIT_CVE_2008_4250 BRUCE" not in s \
        #     or "EXPLOIT_MSQL_BRUTE_FORCE NIGEL" not in s\
        #     or "EXPLOIT_CVE_2008_4250 NIGEL" not in s:
        #         print("[!] Test failed: no initial access attack planned")
        #         return
        print("[*] Test completed in", time_ela, "seconds")
