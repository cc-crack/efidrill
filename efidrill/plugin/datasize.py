from efidrill.plugin.base_plugin import Base_Plugin
from efidrill.config import config
from efidrill.logging import Logger

logger = Logger()


class Datasize(Base_Plugin):
    def __init__(self, rd_analysis):
        super().__init__(rd_analysis)
        self.data_size_offest = {}
        self.is_smi_only = 0

    def search_datasize(self, current_func):
        search_address = self.rd_analysis.function_support.get_current_addr(
            current_func
        )
        for i in range(config.deep_size):
            search_address = current_func.rd_analysis.ida_support.get_prev_ins_addr(
                search_address
            )
            defs_list = self.rd_analysis.function_support.get_use_def(
                current_func, search_address
            )[1]
            use_list = []

            for def_var in defs_list:
                if self.rd_analysis.mdis_support.is_register(
                    def_var[0], self.rd_analysis.arch.function_param[3]
                ):
                    use_list = self.rd_analysis.function_support.get_use_def(
                        current_func, search_address
                    )[0]

            for use_var in use_list:

                if self.rd_analysis.mdis_support.is_op(use_var[0]):
                    return use_var, search_address
        return None, None

    def vulnerability_find(self, current_func, use_list, def_list, use_list_all):
        # TODO: sub     rsp, xxh  don`t deal with
        current_address = self.rd_analysis.function_support.get_current_addr(
            current_func
        )
        if self.rd_analysis.ida_support.is_call_name(
            current_func.current_ins_addr, "GetVariable"
        ):
            datasize_var, search_address = self.search_datasize(current_func)
            if datasize_var == None:
                logger.error("some error in GetVariable" + hex(current_address))
                return
            if (
                datasize_var
                in self.rd_analysis.function_support.get_interesting_op_list(
                    current_func
                )
                and not self.rd_analysis.function_support.get_value_guess(
                    current_func, datasize_var
                )
            ):
                if self.check_new_vuln_address(current_address):
                    self.vulnerability_log(
                        current_address,
                        "Vulnerability:GetVariable overflow address == "
                        + hex(current_address),
                    )

            current_func.add_interesting_memory_map_list(
                datasize_var, default_value={"smm_vaild_size": {0xFFFFFFFFFFFFFFFF: []}}
            )

            offest = self.get_mem_analysis([], [datasize_var])[0]

            if offest:

                call_register_name = (
                    self.rd_analysis.function_support.memory_register_search(
                        current_func, datasize_var
                    )
                )
                if (
                    call_register_name
                    and call_register_name[0] in self.rd_analysis.arch.stack_register
                ):

                    stack_offest = (
                        self.rd_analysis.ida_support.rsp_to_rbp(search_address, 1)
                        + offest
                    )

                    if stack_offest:
                        if current_func not in self.data_size_offest:
                            self.data_size_offest[current_func] = {}
                        if stack_offest in self.data_size_offest[
                            current_func
                        ] and not self.rd_analysis.function_support.get_value_guess(
                            current_func,
                            self.data_size_offest[current_func][stack_offest],
                        ):
                            if self.check_new_vuln_address(current_address):
                                self.vulnerability_log(
                                    current_address,
                                    "Vulnerability:GetVariable overflow address == "
                                    + hex(current_address),
                                )

                        self.data_size_offest[current_func][stack_offest] = datasize_var


PLUGIN_CLASS = Datasize
