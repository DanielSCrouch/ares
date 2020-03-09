
def generate_problem(self, depth=0):
    """
    Generates a PDDL problem file for use with planner.
    - optional arguments:
    depth: determines how many progress steps required to achieve goal
    """
    # path = glob.glob("/problem_test.txt")
    cwd = Path.cwd()
    problem_file = Path.cwd() / 'pddl_files' / 'problem.pddl'
    problem = PDDLTranslate(self).get_header()
    problem += PDDLTranslate(self).get_objects()
    problem += PDDLTranslate(self).get_init(depth)
    problem += PDDLTranslate(self).get_goals(depth)
    problem += '\n\n)'
    problem_file.write_text(problem)
    print('Done!')
    

class PDDLTranslate(object):
    """
    Defines a collection of methods for translating models to PDDL problems
    """
    def __init__(self, model):
        self.model = model

    def get_header(self):
        p = "(define (problem attackvector) (:domain attacksurface)"
        return p

    def get_objects(self):
        p = "\n\n(:objects"
        # add hosts
        p += "\n    placeholder - host"
        for host_name in self.model.get_host_names():
            host_name = self.get_legal(host_name)
            p += "\n    " + host_name + " - host"
        # add vulns
        p += "\n    placeholder - vuln"
        for vuln_name in self.model.get_vuln_names():
            vuln_name = self.get_legal(vuln_name)
            p += "\n    " + vuln_name + " - vuln"
        # add os
        p += "\n    placeholder - os"
        # port
        p += "\n    placeholder - port"
        # end
        p += "\n    )"
        return p

    def get_init(self, depth):
        p = "\n\n(:init"
        p += "(is placeholder)"
        for host in self.model.get_hosts():
            host_name = self.get_legal(host.host)
            # add found hosts
            if host.found:
                p += "\n    (found " + host_name + ")"
        p += "\n    )"
        return p

    def get_goals(self, depth):
        p = "\n\n(:goal"
        if len(self.model.get_host_names()) > 1:
            p += " (or"
            for host_name in self.model.get_host_names():
                host_name = self.get_legal(host_name)
                p += "\n    (has_progress" + str(depth) + " " + host_name + ")"
            p += "\n    "
        else:
            for host_name in self.model.get_host_names():
                host_name = self.get_legal(host_name)
                p += "\n    (has_progress" + str(depth) + " " + host_name + ")"
        p += "\n    )"
        return p

    def get_legal(self, name):
        if name[0].isdigit():
            name = 'xx' + name
        name = name.replace('.', '_')
        return name
