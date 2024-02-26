from efidrill.plugin.base_plugin import Base_Plugin
from efidrill.function_support import *
from efidrill.logging import Logger

logger = Logger()

class Indirect_Call(Base_Plugin):
    
    def __init__(self, rd_analysis, ):
        super().__init__(rd_analysis)

    def vulnerability_find(self, current_func,  use_list, def_list, use_list_all):
        current_address = self.rd_analysis.function_support.get_current_addr(current_func)
        if self.rd_analysis.ida_support.is_call(current_address):
            if use_list and not self.rd_analysis.ida_support.get_function_address(current_func.current_ins_addr):
                if self.check_new_vuln_address(current_address):
                    self.vulnerability_log(current_address,"Noice:indirect function call with outside data address == "+hex(current_address))     
            # Indirect calls are a weakness point to problems, and identifying which indirect calls contain data that we can control
        
            
PLUGIN_CLASS = Indirect_Call