
import io
import time
from threading import Thread
from contextlib import redirect_stdout
# local imports
import config
from console import Console

################################################################################
# Unit tests
################################################################################

CONSOLE = Console()

def console_test():
    f = io.StringIO()
    with redirect_stdout(f):
        ###
        Thread(target=CONSOLE.cmdloop).start()
        ###
    s = f.getvalue()
    print(s)

def add_target_test():
    f = io.StringIO()
    with redirect_stdout(f):
        ###
        CONSOLE.do_target('bruce 192.168.1.190')
        CONSOLE.do_target('nigel 192.168.1.191')
        ###
    s = f.getvalue()
    print(s)

def import_scan_test():
    f = io.StringIO()
    with redirect_stdout(f):
        ###
        CONSOLE.do_import('full bruce')
        ###
    s = f.getvalue()
    print(s)

def show_target_test():
    f = io.StringIO()
    with redirect_stdout(f):
        ###
        CONSOLE.do_show('target bruce')
        ###
    s = f.getvalue()
    print(s)

def plan1_test():
    f = io.StringIO()
    with redirect_stdout(f):
        ###
        CONSOLE.do_plan('')
        ###
    s = f.getvalue()
    print(s)

def plan2_test():
    f = io.StringIO()
    with redirect_stdout(f):
        ###
        config.TARGETS['bruce'].port_scanned = True
        CONSOLE.do_plan('')
        ###
    s = f.getvalue()
    print(s)

def plan3_test():
    f = io.StringIO()
    with redirect_stdout(f):
        ###
        config.TARGETS['bruce'].full_scanned = True
        CONSOLE.do_plan('')
        ###
    s = f.getvalue()
    print(s)

def plan4_test():
    f = io.StringIO()
    with redirect_stdout(f):
        ###
        config.TARGETS['nigel'].port_scanned = True
        CONSOLE.do_plan('')
        ###
    s = f.getvalue()
    print(s)

def plan5_test():
    f = io.StringIO()
    with redirect_stdout(f):
        ###
        config.TARGETS['nigel'].full_scanned = True
        CONSOLE.do_plan('')
        ###
    s = f.getvalue()
    print(s)

def plan6_test():
    f = io.StringIO()
    with redirect_stdout(f):
        ###
        config.TARGETS['bruce'].action_history.append("exploit_msql_brute_force")
        config.TARGETS['bruce'].session_id = '1'
        config.TARGETS['bruce'].access = 'user'
        CONSOLE.do_plan('')
        ###
    s = f.getvalue()
    print(s)

def plan7_test():
    f = io.StringIO()
    with redirect_stdout(f):
        ###
        config.TARGETS['bruce'].action_history.append("exploit_cve_2008_4250")
        config.TARGETS['bruce'].session_id = '1'
        config.TARGETS['bruce'].access = 'admin'
        CONSOLE.do_plan('')
        ###
    s = f.getvalue()
    print(s)

def plan8_test():
    f = io.StringIO()
    with redirect_stdout(f):
        ###
        config.TARGETS['bruce'].action_history.append("exploit_hashdump")
        config.TARGETS['bruce'].admin_user = "Administrator"
        config.TARGETS['bruce'].admin_hash = "123123123"
        CONSOLE.do_plan('')
        ###
    s = f.getvalue()
    print(s)

# config.COMMANDS.scan_import('full', 'bruce')

# self.do_exploit('cve-2008-4250 bruce')
# self.do_exploit('hashdump bruce')
# self.do_exploit('psexec bruce nigel')



################################################################################
# Main
################################################################################

if __name__ == '__main__':
    print("test1: console \n" + "*" * 60 )
    console_test()
    time.sleep(1)
    print("test2: add target \n" + "*" * 60 )
    add_target_test()
    time.sleep(1)
    print("test3: import scan \n" + "*" * 60 )
    import_scan_test()
    time.sleep(1)
    print("test4: show target \n" + "*" * 60 )
    show_target_test()
    time.sleep(1)
    print("test5: plan1 test \n" + "*" * 60 )
    plan1_test()
    time.sleep(1)
    print("test6: plan2 test \n" + "*" * 60 )
    plan2_test()
    time.sleep(1)
    print("test7: plan3 test \n" + "*" * 60 )
    plan3_test()
    time.sleep(1)
    print("test8: plan4 test \n" + "*" * 60 )
    plan4_test()
    time.sleep(1)
    print("test9: plan5 test \n" + "*" * 60 )
    plan5_test()
    time.sleep(1)
    print("test10: plan6 test \n" + "*" * 60 )
    plan6_test()
    time.sleep(1)
    print("test11: plan7 test \n" + "*" * 60 )
    plan7_test()
    time.sleep(1)
    print("test12: plan8 test \n" + "*" * 60 )
    plan8_test()
