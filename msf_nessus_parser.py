

def policy_list_parser(str):
    policies = {}
    lines = (line for line in str.splitlines())
    # discard first two lines
    next(lines)
    next(lines)
    for line in lines:
        try:
            name = line.split()[1]
            uuid = line.split()[2]
            policies[name] = uuid
        except:
            pass
    return policies
