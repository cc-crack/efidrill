import json
import os
import idautils
import binascii

class Cfg(dict):    
    def __init__(self,json_str):
        p = json.loads(json_str)
        if p is not None:
            for k,v in p.items():
                self[k] = v
        return super().__init__()

    def __key(self, key):
        return "" if key is None else key.lower()

    def __str__(self):
        return json.dumps(self)

    def __setattr__(self, key, value):
        self[self.__key(key)] = value

    def __getattr__(self, key):
        return self.get(self.__key(key))

    def __getitem__(self, key):
        return super().get(self.__key(key))

    def __setitem__(self, key, value):
        return super().__setitem__(self.__key(key), value)
    
    def init_workdir(self):
        self.workdir = os.path.abspath(os.path.expanduser(config.workdir))
        if os.path.exists(self.workdir) is False:
            os.mkdir(config.workdir)
        return self
    
    def init_dump_file_path(self):
        input_file_hash_str = binascii.hexlify(idautils.GetInputFileMD5()).decode('utf-8')
        self.dump_file_path = os.path.join(self.workdir,input_file_hash_str)
        if os.path.exists(config.dump_file_path) is False:
            os.mkdir(config.dump_file_path)



try:
    efidrillpath = os.path.split(os.path.abspath(__file__))[0]
    configpath = os.path.join(efidrillpath,'config.json')
    with open(configpath,'r') as f:
        s = f.read()
        config=Cfg(s)
        f.close()
    config.efidrillpath = efidrillpath
    config.configpath = configpath
except Exception as e:
    print(e)
    config = Cfg\
    ('{\
    "deep_size": 15,\
    "max_function_deep": 5,\
    "workdir":"~/efidrill_workspace/",\
    "logging_path":  "efi_digging.log",\
    "just_data_taint" : 1,\
    "debug_flag": 0,\
    "to_ui" : 1,\
     "res_filename": "res.json"\
     "efidrillpath": ""\
     "configpath":""\
     }')

config.init_workdir()

