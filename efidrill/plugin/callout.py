from efidrill.plugin.base_plugin import Base_Plugin



class Plugin_Callout(Base_Plugin):
    def __init__(self, rd_analysis):
        super().__init__(rd_analysis)
        self.is_smi_only = 0
    def vulnerability_find(self,  current_func, use_list, def_list, use_list_all):  

        current_address = self.rd_analysis.function_support.get_current_addr(current_func)

        if self.rd_analysis.ida_support.is_call(current_address) and use_list:

            use_list_call, def_list = self.rd_analysis.function_support.get_use_def(current_func, current_address)
            
            call_register_name = self.rd_analysis.function_support.memory_register_search(current_func,use_list_call[0])
            use_list_name = []
            # Find out whether the function pointer contains variables we can control

            for use_var in use_list:
                if self.rd_analysis.mdis_support.is_register(use_var[0]) and\
                      self.rd_analysis.function_support.get_value_guess(current_func, use_var) == {}:
                    use_list_name.append(use_var[0].name)

            if set(use_list_name) & set(call_register_name):
                           
                if self.check_new_vuln_address(current_address):
                    self.vulnerability_log(current_address, "Vulnerability:call out find address == "+hex(current_address))


PLUGIN_CLASS = Plugin_Callout