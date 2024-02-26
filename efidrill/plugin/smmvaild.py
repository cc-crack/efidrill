from efidrill.plugin.base_plugin import Base_Plugin
from efidrill.config import config
from efidrill.logging import Logger
logger = Logger()

class Smm_Vaild(Base_Plugin):
    
    def __init__(self, rd_analysis):
        super().__init__(rd_analysis)
        self.smm_vaild_size = {}


        
    def copy_use_var(self, current_fun, caller_func, use_var):
        if current_fun not in self.smm_vaild_size.keys():
            self.smm_vaild_size[current_fun] = {}
        if use_var not in self.smm_vaild_size[current_fun].keys():
            self.smm_vaild_size[current_fun][use_var] = []
        self.smm_vaild_size[current_fun][use_var].extend(self.smm_vaild_size[caller_func][use_var])


    def search_check_size(self,current_func, rdx_var, current_address):
        offset = self.rd_analysis.ida_support.get_op_imm_value(rdx_var[1],1)
        check_size = 0
        int_data = None
        if offset:
            check_size = offset
        else:

                
            if rdx_var:
                rdx_var_from = self.rd_analysis.function_support.get_var_from(current_func ,current_address, rdx_var)

    
                if rdx_var_from in self.rd_analysis.function_support.get_interesting_op_list(current_func):                    
                    has_path_addr = self.rd_analysis.function_support.get_have_path(current_func, current_address)
                    min_list = self.rd_analysis.function_support.get_min_list(current_func,
                        rdx_var_from,has_path_addr) 
                    if min_list:
                        int_data = max(min_list)



                if int_data != None:
                    check_size = int_data
        return check_size

            
    def search_data_and_check_size(self,current_func, use_list, use_list_all, current_address):

        check_size = None

        rcx_var = self.rd_analysis.function_support.get_var_by_regiter_name(current_func,use_list_all, self.rd_analysis.arch.function_param[0])
        rdx_var = self.rd_analysis.function_support.get_var_by_regiter_name(current_func,use_list_all, self.rd_analysis.arch.function_param[1])
        if rcx_var:
            rcx_var_from = self.rd_analysis.function_support.get_var_from(current_func,current_address, rcx_var)
            check_size = self.search_check_size(current_func,rdx_var, current_address)

            if rcx_var_from in self.smm_vaild_size[current_func].keys():

                for vaild_memory in  self.smm_vaild_size[current_func][rcx_var_from]:
                    if check_size not in vaild_memory.keys():
                        vaild_memory[check_size] = []    
                    vaild_memory[check_size].append(current_address)


    
    def vulnerability_find(self, current_func, use_list, def_list, use_list_all):   
        current_address = self.rd_analysis.function_support.get_current_addr(current_func)

        if self.rd_analysis.ida_support.is_call(current_address) and use_list:
            
            self.search_data_and_check_size(current_func, use_list, use_list_all, current_address)

            return 
        offset_get, mem_var, is_use = self.get_mem_analysis(def_list, use_list_all) 
       
        if not mem_var or  self.rd_analysis.ida_support.is_call(current_address):
            return 
        
        one_var_list = []
        if is_use == 0:
            one_var_list = self.rd_analysis.function_support.get_def_use_data(current_func, current_address)
        else:
            one_var_list = use_list
        call_register_name = self.rd_analysis.function_support.memory_register_search(current_func,mem_var)
        for one_var in one_var_list:
            
            if one_var not in self.rd_analysis.function_support.get_interesting_op_list(current_func):
                continue
            
            if not self.rd_analysis.mdis_support.is_register(one_var[0]):
                continue 
            if  one_var[0].name not in call_register_name:
                continue          
                            
            for vaild_memory in self.smm_vaild_size[current_func][one_var]:
                if len(vaild_memory) == 0:
                    if self.check_new_vuln_address(current_address):                        
                        self.vulnerability_log(current_address,"Vulnerability:SMRAM OOB offset_get == "+hex(offset_get)+" address == "+hex(current_address))           
                        
                    return
                is_oob = 1
                if current_address == 0x15c5:
                    
                    print(offset_get, vaild_memory)
                    print(one_var)
                for size, source_path_list in vaild_memory.items():
                    if offset_get>= size:
                        continue

                    for source_path in source_path_list:
                        if self.rd_analysis.function_support.is_have_path(current_func, current_address, source_path):
                            is_oob = 0
                            
                if is_oob:
                    if self.check_new_vuln_address(current_address):
                        
                        self.vulnerability_log(current_address,"Vulnerability: SMRAM OOB offset_get == "+hex(offset_get)+" address == "+hex(current_address))           
                    break
                
                

    def add_interesting_memory_map_list(self, current_func, def_var, use_list=[], is_alias=0, default_value={}):
            #logger.info(self.smm_vaild_size[current_func])
            
            breakpoint()
            if 'smm_vaild_size' in default_value.keys():
                self.smm_vaild_size[current_func][def_var] = []
                self.smm_vaild_size[current_func][def_var].append(default_value['smm_vaild_size'])
                return 
            
            if is_alias and len(use_list) == 1:
                self.smm_vaild_size[current_func][def_var] = []
                for use_var in use_list:
                    self.smm_vaild_size[current_func][def_var].extend(self.smm_vaild_size[current_func][use_var])
            else:
                if current_func not in self.smm_vaild_size.keys():
                    self.smm_vaild_size[current_func] = {}
                self.smm_vaild_size[current_func][def_var] = [{}]


PLUGIN_CLASS = Smm_Vaild





