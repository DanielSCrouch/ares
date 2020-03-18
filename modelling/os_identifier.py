

def get_os(plugin_output):
    os_list = []
    lines = (line for line in plugin_output.splitlines())
    for line in lines:
        if "one of these operating systems :" in line:
            break
    for line in lines:
        if 'Service Pack 3' in line:
            os_list.append(line)
    return os_list
