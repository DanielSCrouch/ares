from threading import Lock

################################################################################
# Registrar
################################################################################

class Registrar(object):
    """
    Class defining a thread safe registrar for maintaining a history of inputs
    and corresponding outputs.
    """
    def __init__(self, bound=100):
        self.bound = bound
        #
        self.ids = []
        self.inputs = []
        self.outputs = []
        self.lock = Lock()

    def record(self, id, input, output):
        """
        Add an input and output pair to the history records.
        Order newest (i=0) to oldest (i=99)
        """
        self.lock.acquire()
        if len(self.ids) != len(self.inputs) != len(self.outputs):
            raise NameError("registrar input/output records out of sync")
        if len(self.inputs) <= self.bound:
            self.inputs = [input] + self.inputs[:]
            self.outputs = [output] + self.outputs[:]
        else:
            self.id = [id] + self.ids[1:self.bound-1]
            self.inputs = [input] + self.inputs[1:self.bound-1]
            self.outputs = [output] + self.outputs[1:self.bound-1]
        if len(self.inputs) > self.bound:
            raise NameError("registrar exceeded bound limit of " + \
                            str(self.bound))
        self.lock.release()

    def get_count(self):
        """
        Return the total count of current records.
        """
        self.lock.acquire()
        return len(self.inputs)
        self.lock.release()

    def get_record(self, id):
        """
        Return the record (input, output) for given id.
        """
        self.lock.acquire()
        try:
            index = self.ids.index(id)
            input = self.inputs[index]
            output = self.outputs[index]
            self.lock.release()
            return input, output
        except Exception as e:
            raise Exception(e)
            self.lock.release()
            return None, None
