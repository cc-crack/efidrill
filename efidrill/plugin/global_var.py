from efidrill.plugin.base_plugin import Base_Plugin
from efidrill.function_support import *


class Global_Var(Base_Plugin):

    def vulnerability_find(self, current_func, use_list, def_list, use_list_all):
        current_address = self.rd_analysis.function_support.get_current_addr(
            current_func
        )
        for def_var in def_list:

            if self.rd_analysis.mdis_support.is_global_mem(def_var[0]) and use_list:
                if self.check_new_vuln_address(current_address):
                    self.vulnerability_log(
                        current_address,
                        "Noice:Find Global var save a outside data address == "
                        + hex(current_address),
                    )
        # Storing an externally controllable address into a variable in SMRAM is a weakness


PLUGIN_CLASS = Global_Var
