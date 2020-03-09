console_input = select.select([sys.stdin], [], [], 1)[0]
if console_input:
    command = sys.stdin.readline().strip()

##############

cmd = "nessus_scan_new " +       \
       SCAN_UUID         + ' ' + \
       SCAN_NAME         + ' ' + \
       SCAN_DESCRIPTION  + ' ' + \
       TARGETS
