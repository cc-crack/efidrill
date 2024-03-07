import json


class Function_Support:
    def __init__(self, rd_analysis):
        self.rd_analysis = rd_analysis

    def search_register(self, function_alalysis, var_list):
        return function_alalysis.function_var.search_register(var_list)

    def search_mem(self, function_alalysis, var_list):
        return function_alalysis.function_var.search_register(var_list)

    def get_var_from(self, func_analysis, ins_addr, use_var):

        return func_analysis.function_var.search_from(ins_addr, use_var)

    def get_var_by_regiter_name(self, function_alalysis, use_list, register_name):

        return function_alalysis.function_var.search_register(use_list, register_name)

    def get_var_by_mem(self, function_alalysis, use_list):
        return function_alalysis.function_var.search_mem(use_list)

    def get_min_list(self, function_alalysis, use_var, has_path_addr):
        return function_alalysis.function_var.get_min_list(use_var, has_path_addr)

    def get_interesting_op_list(self, function_alalysis):
        return function_alalysis.interesting_op_list

    def get_current_addr(self, function_alalysis):
        return function_alalysis.current_in_addr

    def get_start_addr(self, function_alalysis):
        return function_alalysis.start_addr

    def get_end_addr(self, function_alalysis):
        return function_alalysis.end_addr

    def get_use_def(self, function_alalysis, ins_addr):
        return function_alalysis.get_use_def(ins_addr)

    def get_def_use_data(self, function_alalysis, current_address):
        return function_alalysis.get_def_use_data(current_address)

    def get_have_path(self, function_alalysis, ins_addr):
        return function_alalysis.have_path_dict[ins_addr]

    def get_struct_map(self, function_alalysis, use_var):
        return function_alalysis.function_var.struct_mmap[use_var]

    def get_value_guess(self, function_alalysis, use_var):
        return function_alalysis.function_var.value_guess[use_var]

    def memory_register_search(self, function_alalysis, use_var):
        call_use_list = self.rd_analysis.mdis_support.use_var_search(use_var[0])
        register_name_list = []

        for call_use in call_use_list:
            if self.rd_analysis.mdis_support.is_register(call_use):
                register_name_list.append(call_use.name)
        return register_name_list

    def is_have_path(self, function_alaiysis, ins_addr, source):
        return function_alaiysis.is_have_path(ins_addr, source)

    def get_current_addr(self, function_alalysis):
        return function_alalysis.current_ins_addr

    def get_all_ir(self, function_alalysis, address):
        if address in function_alalysis.all_ir.keys():
            return function_alalysis.all_ir[address]
        else:
            return []

    def dump_struct(self, function_analysis, save_file, use_var):

        struct_mmap = function_analysis.function_var.struct_mmap[use_var]

        for one_struct_mmap in struct_mmap:
            last_offset = 0
            struct_data = []

            for offset, one_var_list in one_struct_mmap.items():
                json_data = {}
                is_point = 0
                if offset - last_offset > 0:
                    json_data["size"] = offset - last_offset

                json_data["offset"] = offset
                last_offset = offset
                for one_var in one_var_list:
                    if (
                        one_var in function_analysis.function_var.struct_mmap.keys()
                        and len(function_analysis.function_var.struct_mmap[one_var])
                    ):
                        is_point = 1
                    if (
                        one_var in function_analysis.function_var.value_guess.keys()
                        and len(function_analysis.function_var.value_guess[one_var])
                    ):
                        json_data["value_guess"] = (
                            function_analysis.function_var.value_guess[one_var]
                        )
                    else:
                        json_data["value_guess"] = None
                if is_point:
                    json_data["type_guess"] = "Point"
                else:
                    json_data["type_guess"] = "Data"
                struct_data.append(json_data)

            save_file.write(json.dumps(struct_data))
            save_file.write("\n")

    def is_smi(self, function_anlysis):
        return function_anlysis.is_smi

    def copy_var(self, function_anlysis, caller_function, use_var):

        caller_function.function_var.copy_var(function_anlysis.function_var, use_var)
