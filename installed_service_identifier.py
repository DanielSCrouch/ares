

def get_services(plugin_output):
    print(plugin_output)
    is_list = []
    lines = (line for line in plugin_output.splitlines())
    for line in lines:
        if "following softare are installed on the remote host :" in line:
            break
    for line in lines:
        break
    for line in lines:
        if len(line) == 0:
            break
        else:
            start = line.find('[')
            end = line.find('[')
            if start != -1 and end != -1:
                rline = line[start:end+1]
                nline = line.replace(rline, "")
                is_list.append(nline)

    print("!!!!!!!!!!!!!Not tested")
    return is_list
