 
#coding=utf-8
from efidrill.config import config
from efidrill.logging import Logger
from efidrill.result import res
from efidrill.rd_analysis import RD_Analysis
import os


import idaapi

 
class Efidrill(idaapi.plugin_t):
    comment = "Efidrill is a vunlerability hunting tool of EFI." 
    help = "Press Ctrl-Alt-M"                                  
    wanted_name = "Efidrill"             
    wanted_hotkey = "Ctrl-Alt-M"                   
    flags=0


    def __init__(self):
        super(Efidrill,self).__init__()
        self.rd_analysis = None
        

    def term(self):
        print("[+] Finish Efidrill......")
 
    def init(self):
        print("[+] Init Efidrill.....")
        return idaapi.PLUGIN_OK                   
 
    def run(self,arg):
        config.init_dump_file_path()
        Logger(log_file=os.path.join(config.dump_file_path, config.logging_path))
        self.rd_analysis = RD_Analysis()
        self.rd_analysis.init_efiXplorer64()
        self.rd_analysis.work()
        res.dump().show()

# register IDA plugin
def PLUGIN_ENTRY():
    return Efidrill()





    



























        