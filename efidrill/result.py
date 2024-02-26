import json
import os
from efidrill.config import config
from efidrill.ida_work.ida_support import Vuln_Report_Window
class Result:
    def __init__(self) -> None:
        self.data = {}
        
    def update(self,vultype,item):
        if vultype not in self.data.keys():
            self.data[vultype] = []
        self.data[vultype].append(item)
        return self
        
    def dump(self):
        with open(os.path.join(config.dump_file_path,config.res_filename),'w') as f:
            s = json.dumps(self.data)
            f.write(s)
            f.close()
        return self

    def load(self):
        #TODO: load result form json
        return self

    def show(self):
        if config.to_ui:
            v = Vuln_Report_Window()
            v.Create("Efidrill")
            for t,vulns in self.data.items():
                for i in vulns:
                    v.add_line(i[0],i[1])
            v.Show()
        else:
            print(self.data)
        return self

res = Result()