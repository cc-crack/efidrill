from efidrill.plugin_mgr import PluginMgr
from efidrill.function_type.function_ana_loader import function_type
from queue import Queue


class Check_Engine:
    def __init__(self, rd_analysis):
        self.function_type_list = []

        self.function_queue = Queue()
        self.ea_function = {}
        self.rd_analysis = rd_analysis

    def get_function_by_ea(self, ea, name=None):
        is_new = 0
        if ea in self.ea_function.keys():
            ret_function = self.ea_function[ea]
        else:
            is_new = 1
            if not name:
                name = self.rd_analysis.ida_support.get_func_name(ea)

            ret_function = function_type(self.rd_analysis, ea, name)
            if ret_function:
                self.ea_function[ea] = ret_function

        return ret_function, is_new
