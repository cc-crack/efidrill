from efidrill.logging import Logger
from efidrill.config import config
from efidrill.result import res
import time

logger = Logger()


class Base_Plugin:

    def __init__(self, rd_analysis):
        self.save_to_global = []
        self.vuln_address = {}
        self.rd_analysis = rd_analysis
        self.start_time = 0
        self.is_smi_only = 1

    def get_mem_analysis(self, def_list, use_list):
        # Find the offset of the current variable

        for use_var in use_list:

            offset, is_mem = self.rd_analysis.mdis_support.search_int(use_var[0])

            if offset is not None:

                return offset, use_var, 1
        for def_var in def_list:
            offset, is_mem = self.rd_analysis.mdis_support.search_int(def_var[0])
            if offset is not None:

                return offset, def_var, 0
        return None, None, 0

    def copy_use_var(self, current_func, caller_func, use_var):
        self.rd_analysis.function_support.copy_var(current_func, caller_func, use_var)

        pass

    def add_interesting_memory_map_list(
        self, current_func, def_var, use_list=[], is_alias=0, default_value={}
    ):
        pass

    def vulnerability_find(self, current_func, use_list, def_list, use_list_all):
        pass

    def check_new_vuln_address(self, address):
        if address not in self.vuln_address.keys():
            self.vuln_address[address] = ""
            return 1
        return 0

    def finish_work(self):
        return

    def vulnerability_log(self, address, print_string):
        self.vuln_address[address] = print_string

    def print_log(self):
        for address, log_data in self.vuln_address.items():
            logger.warning(log_data)
            res.update(self.__class__.__name__, (address, log_data))
