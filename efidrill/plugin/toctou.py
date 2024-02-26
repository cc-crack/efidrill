from efidrill.plugin.base_plugin import Base_Plugin
from efidrill.logging import Logger
logger = Logger()

class Toctou(Base_Plugin):
    
    def __init__(self, rd_analysis):
        super().__init__(rd_analysis)
        self.toctou_mmap = {}
        
    
    def copy_use_var(self,current_func, caller_func, use_var):
        if current_func not in self.toctou_mmap.keys():
            self.toctou_mmap[current_func] = {}
        if use_var not in self.toctou_mmap[current_func].keys():
            self.toctou_mmap[current_func][use_var] = []
        self.toctou_mmap[current_func][use_var].extend(self.toctou_mmap[caller_func][use_var])
    

    
    
    def vulnerability_find(self, current_func, use_list, def_list, use_list_all):
       
        offset_get, mem_var, is_use= self.get_mem_analysis(def_list, use_list_all)
        if not mem_var:
            return 
 
        current_address = self.rd_analysis.function_support.get_current_addr(current_func)
        if is_use == 0:
            one_var_list = self.rd_analysis.function_support.get_def_use_data(current_func, current_address)
        else:
            one_var_list = use_list
        call_register_name = self.rd_analysis.function_support.memory_register_search(current_func,mem_var)
        for use_var in one_var_list:

            if not self.rd_analysis.mdis_support.is_register(use_var[0]):
                continue   
            if use_var[0].name not in call_register_name:
                continue 
            if use_var not in self.toctou_mmap[current_func].keys():
                continue


            for toctou_memory in self.toctou_mmap[current_func][use_var]:      
                if offset_get in toctou_memory.keys():
                    # toctou_mmap is a list that stores which offset have been used. If this offset already exists in the list, it is a toctou
                    
                    have_path = 0
                    for source_path in toctou_memory[offset_get]:
                        
                        have_path|= self.rd_analysis.function_support.is_have_path(current_func, current_address, source_path)
                    if not have_path:
                        continue
                    if self.check_new_vuln_address(current_address):
                        self.vulnerability_log(current_address,"Vulnerability: Find TOCTOU offset == "+hex(offset_get)+" address == "+hex(current_address))
                else:
                    
                    if  -1 in toctou_memory.keys() : 
                        pass
                    else:
                        if offset_get not in toctou_memory.keys():
                            toctou_memory[offset_get] = []    
                        toctou_memory[offset_get].append(current_address)
                

    def add_interesting_memory_map_list(self, current_func, def_var, use_list=[], is_alias=0, default_value={}):
            if 'toctou' in default_value.keys():
                 self.toctou_mmap[current_func][def_var] = []
                 self.toctou_mmap[current_func][def_var].append(default_value['toctou'])
                 return

            if is_alias and len(use_list) == 1:
                self.toctou_mmap[current_func][def_var] = []
                
                for use_var in use_list:
                    self.toctou_mmap[current_func][def_var].extend(self.toctou_mmap[current_func][use_var])
            else:
                if current_func not in self.toctou_mmap.keys():
                    self.toctou_mmap[current_func] = {}
                self.toctou_mmap[current_func][def_var] = [{}]
            
PLUGIN_CLASS = Toctou