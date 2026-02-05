import re

class Node:
    """
    This class describes all the information of a node in minimal provenance for privilege controller system
    """
    def __init__(self, time, uid, pid, ppid, type, comm):
        self.time = time
        self.uid = uid
        self.pid = pid
        self.ppid = ppid
        self.type = type
        if 'exec' in self.type:
            self.comm = comm
        else:
            self.comm = ''
    def Format(self):
        self.NewLineLog = str(self.time) + "|" + str(self.uid) + "|" + str(self.pid) + "|" + str(self.ppid) + "|" + str(self.type) + "|" + str(self.comm)
    def AddNode(self):
        ProveFile = open('/ProvenanceLog', 'a')
        ProveFile.write(self.NewLineLog)
    
class Provenance:
    """
    Docstring for Provenance
    """
    #form for everysingle node inside provenance tree
    def NodeForm(self, time, uid, pid, ppid, type, comm, child):
        return {
            'time': time,
            'uid': uid,
            'pid': pid,
            'ppid': ppid,
            'type': type,
            'comm': comm,
            'child': child
        }
    def DataLoader(self):
        ProveLogFile = open('ProvenanceLog', 'r')
        data = ProveLogFile.readlines()
        data1 = data
        pattern = r"(?P<timestamp>\d+)\|(?P<pid>\d+)\|(?P<ppid>\d+)\|(?P<uid>\d+)\|(?P<action>\w+)\|(?P<command>\w+)"
        result_array = []
        #loop through the list twice to build provenance tree
        for line in data:
            line.strip().split('\n')
            match = re.search(pattern, line)
            if match:
                child_array = []
                for line1 in data1:
                    line1.strip().split('\n')
                    temp_match = re.search(pattern, line1)
                    if match[3] == temp_match[4]:
                        child_array.append(self.NodeForm(temp_match[1],temp_match[2],temp_match[3],temp_match[4],temp_match[5],temp_match[6],[]))
                result_array.append(self.NodeForm(match[1],match[2],match[3],match[4],match[5],match[6],child_array))
                if len(child_array)>0:
                    print(result_array[len(result_array)-1])
        return result_array
    
    def __init__(self, pid):
        self.pid = pid
        tree = []

if __name__ == '__main__':
    prove1 = Provenance('2020')
    prove1.DataLoader()