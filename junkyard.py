console_input = select.select([sys.stdin], [], [], 1)[0]
if console_input:
    command = sys.stdin.readline().strip()

    
