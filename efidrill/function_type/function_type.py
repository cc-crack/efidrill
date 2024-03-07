import copy
import logging

from efidrill.config import config
import time
from efidrill.logging import Logger
from efidrill.function_var import Var_List
from efidrill.user_define_work import *

logger = Logger()


class Function_type:
    def __init__(self, rd_analysis, start_addr, is_smi=0):

        self.rd_analysis = rd_analysis
        self.start_addr = start_addr
        self.end_addr = self.rd_analysis.ida_support.get_end_addr(self.start_addr)
        self.current_ins_addr = self.start_addr
        self.function_var = None
        self.all_defs = None
        self.all_uses = None
        self.have_path_dict = {}
        self.ircfg = None

        # ir class in miasm
        self.current_ins_addr = start_addr
        self.interesting_op_list = []
        # The variable we want to track
        self.mmap_ir_address = None
        self.mmap_address_ir = None
        # Map about (block.loc_key, ass_index) and  address

        # we can`t analysis function with out time out , so we have a max function deep in our analysis
        self.input_miasm = {}
        # the call param in this function {"reg name":var}
        self.is_smi = is_smi
        self.is_init = 0
        self.start_time = 0
        self.def_use = {}
        try:
            self.init_function_analysis()
        except:
            print("init error")

    def __hash__(self):
        return hash(self.start_addr)

    def __eq__(self, other):
        if isinstance(other, Function_type):
            return self.start_addr == other.start_addr
        return False

    def init_function_analysis(self):

        if self.is_init:
            return

        start_addr = self.start_addr
        self.ircfg = self.rd_analysis.mdis_engine.get_ircfg(start_addr)
        self.mmap_ir_address, self.mmap_address_ir = (
            self.rd_analysis.mdis_support.get_mmap_ir_to_address(self.ircfg)
        )
        self.all_ir = self.rd_analysis.mdis_engine.gather_ir_data(
            self.ircfg, self.mmap_ir_address
        )

        self.all_uses, self.all_defs = self.rd_analysis.mdis_engine.get_use_def(
            self.ircfg, self.mmap_ir_address
        )
        # Generate rd through mdis in mdis_ engine
        self.def_use = self.rd_analysis.mdis_support.mmap_ir_to_address(
            self.mmap_ir_address, self.all_uses.def_use
        )
        self.all_uses = self.rd_analysis.mdis_support.mmap_ir_to_address(
            self.mmap_ir_address, self.all_uses
        )

        self.all_defs = self.rd_analysis.mdis_support.mmap_ir_to_address(
            self.mmap_ir_address, self.all_defs
        )

        # gather have path
        self.have_path_dict = self.rd_analysis.mdis_engine.have_path_gather(
            self.ircfg, self.mmap_ir_address
        )

        self.have_path_dict = self.rd_analysis.mdis_support.mmap_ir_to_address(
            self.mmap_ir_address, self.have_path_dict
        )

        self.function_var = Var_List(self.rd_analysis, self)

        # Map (block.loc_key, ass_index) in disk to address
        self.is_init = 1

    def is_have_path(self, address, source):

        return source in self.have_path_dict[address]

    def vulnerability_find(self, use_list, def_list, use_list_all):
        self.rd_analysis.pluginmgr.callplugin_on_vulnerability_find(
            self, use_list, def_list, use_list_all
        )

    def add_interesting_memory_map_list(
        self,
        def_var,
        use_list=[],
        ins_addr=-1,
        is_alias=0,
        use_list_all=[],
        default_value={},
    ):
        mem_use_var = None
        is_alias_tmp = self.function_var.add_var(ins_addr, def_var, use_list_all)
        if not is_alias:
            is_alias = is_alias_tmp
        for use_var in use_list:
            if self.rd_analysis.mdis_support.is_mem(use_var[0]):
                self.add_interesting_memory_map_list(use_var)
                mem_use_var = use_var

        if def_var not in self.interesting_op_list:
            self.interesting_op_list.append(def_var)
            self.rd_analysis.pluginmgr.callplugin_on_add_interesting_memory_map_list(
                self, def_var, use_list, is_alias, default_value
            )

    def get_new_insteresting_use(self, use_list):
        new_use_list = []
        for use_var in use_list:
            if use_var in self.interesting_op_list:
                if self.rd_analysis.mdis_support.is_useful_register(
                    use_var[0], self.rd_analysis.arch.register_list
                ):
                    new_use_list.append(use_var)
                elif not self.rd_analysis.mdis_support.is_register(use_var[0]):
                    new_use_list.append(use_var)
        return new_use_list

    def fix_call_out(self, ins_addr, use_list, function_deep):

        if not self.rd_analysis.ida_support.is_call(ins_addr):
            return

        if self.rd_analysis.function_callback.function_call_fix(
            self, use_list, function_deep
        ):
            return

        ea = self.rd_analysis.ida_support.get_function_address(ins_addr)

        # We need to find the subfunction through the initial address of the function.
        # If the calling address and function address have already been used, no new function will be created
        if ea:
            sub_function, is_new = self.rd_analysis.check_engine.get_function_by_ea(
                ea, "SubFunction"
            )

            if sub_function:
                is_update_flag = 0
                for use_var in use_list:
                    if self.rd_analysis.mdis_support.is_register(
                        use_var[0]
                    ) and self.rd_analysis.mdis_support.is_useful_register(
                        use_var[0], self.rd_analysis.arch.function_param
                    ):
                        if use_var[0].name not in sub_function.input_miasm.keys():
                            sub_function.input_miasm[use_var[0].name] = []
                        if use_var not in sub_function.input_miasm[use_var[0].name]:
                            is_update_flag = 1
                            sub_function.input_miasm[use_var[0].name].append(use_var)
                            self.rd_analysis.pluginmgr.callplugin_on_copy_use_var(
                                sub_function, self, use_var
                            )
                            # We should copy the status from father function to sub function
                if is_update_flag or (is_new and config.just_data_taint == 0):
                    self.rd_analysis.check_engine.function_queue.put(
                        (sub_function, function_deep + 1)
                    )

    def ana_ins_addr(self, ins_addr, function_deep):
        use_list_all, def_list = self.get_use_def(ins_addr)

        # Analyze each assembly

        use_list = self.get_new_insteresting_use(use_list_all)
        # search for use var which one in the self.interesting_op_list

        self.fix_call_out(ins_addr, use_list, function_deep)

        if not self.function_var.guess_work(ins_addr, use_list_all):  # just pass xor
            self.vulnerability_find(use_list, def_list, use_list_all)
            if use_list and not self.rd_analysis.ida_support.is_call(
                self.current_ins_addr
            ):

                self.function_var.fix_def(ins_addr, def_list, use_list)

                for def_var in def_list:
                    if not self.rd_analysis.mdis_support.is_useful_register(
                        def_var[0], self.rd_analysis.arch.register_list
                    ):
                        if self.rd_analysis.mdis_support.is_register(def_var[0]):
                            continue
                    self.add_interesting_memory_map_list(
                        def_var=def_var,
                        use_list=use_list,
                        ins_addr=ins_addr,
                        use_list_all=use_list_all,
                    )
            else:
                for def_var in def_list:
                    if not self.rd_analysis.mdis_support.is_useful_register(
                        def_var[0], self.rd_analysis.arch.register_list
                    ):
                        if self.rd_analysis.mdis_support.is_register(def_var[0]):
                            continue
                    is_alias_tmp = self.function_var.add_var(
                        ins_addr, def_var, use_list_all
                    )

    def get_def_use_data(self, ins_addr):
        def_use_list = []
        if ins_addr in self.def_use.keys():
            def_use_list_tmp = self.def_use[ins_addr]
        for def_use in def_use_list_tmp:
            if def_use[1] != ins_addr:
                def_use_list.append(def_use)
        return def_use_list

    def get_use_def(self, ins_addr):
        # Return the use def we previously generated
        """
        all_uses = [address:[(miasm_exp, def_address)]]
        all_defs = [address:[(miasm_exp, def_address)]]


        """
        if ins_addr in self.all_uses.keys():
            all_uses = self.all_uses[ins_addr]
        else:
            all_uses = []

        if ins_addr in self.all_defs.keys():
            all_defs = self.all_defs[ins_addr]
        else:
            all_defs = []
        return all_uses, all_defs

    def analysis(self, function_deep):

        self.check_interesting_variables()

        while self.current_ins_addr < self.end_addr:

            self.ana_ins_addr(self.current_ins_addr, function_deep)

            self.current_ins_addr = self.rd_analysis.ida_support.get_next_ins_addr(
                self.current_ins_addr
            )

    def check_interesting_variables(self):
        if self.rd_analysis.function_callback.user_def_check(self):
            return
        # Find the initial positions of all variables that interest us during the initialization phase
        current_ins_addr = self.start_addr
        while current_ins_addr < self.end_addr:
            # Search for ReadSaveState and move forward to find the memory used
            if self.rd_analysis.ida_support.is_call_name(
                current_ins_addr, "EFI_SMM_CPU_PROTOCOL.ReadSaveState"
            ):
                # try:

                use_var = self.search_readsavestate(current_ins_addr)

                if use_var:
                    def_var = use_var
                    self.add_interesting_memory_map_list(
                        def_var=def_var,
                        default_value={
                            "toctou": {-1: []},
                            "struct": 1,
                            "smm_vaild_size": {0xFFFFFFFFFFFFFFFF: []},
                            "data_min": 0,
                        },
                    )
                    # Because the memory returned by storing ReadSaveState itself is in SMRAM, toctou is set to -1, and the symbol for judging smi input is set to 1 for struct
            # except Exception as e:
            #     print("search_readsavestate",e)

            if current_ins_addr in self.all_uses.keys():

                for use_var in self.all_uses[current_ins_addr]:

                    if self.rd_analysis.mdis_support.is_register(use_var[0]):
                        if (
                            use_var[0].name in self.input_miasm.keys()
                            and use_var[1] == -1
                        ):
                            def_var = use_var
                            father_use_list = self.input_miasm[use_var[0].name]
                            self.add_interesting_memory_map_list(
                                def_var=def_var,
                                use_list=father_use_list,
                                is_alias=1,
                                default_value={"struct": 1},
                            )
                            # Add external controllable variables as input for function parameters to the tracking list, including r8 and r9 of childsmi
                    if self.rd_analysis.mdis_support.check_is_address(
                        0x40E, use_var[0]
                    ):
                        def_var = use_var
                        self.add_interesting_memory_map_list(
                            def_var=def_var,
                            default_value={
                                "smm_vaild_size": {0xFFFFFFFFFFFFFFFF: []},
                                "data_min": 0,
                            },
                        )
                        # search 40E
                    if self.rd_analysis.ida_support.is_var_name(
                        current_ins_addr, "gBS", 1
                    ) or self.rd_analysis.ida_support.is_var_name(
                        current_ins_addr, "gST", 1
                    ):

                        if self.rd_analysis.mdis_support.is_mem(use_var[0]):
                            def_var = use_var

                            self.add_interesting_memory_map_list(
                                def_var=def_var,
                                default_value={
                                    "smm_vaild_size": {0xFFFFFFFFFFFFFFFF: []},
                                    "data_min": 0,
                                },
                            )
                            # search gBS

            current_ins_addr = self.rd_analysis.ida_support.get_next_ins_addr(
                current_ins_addr
            )

    def search_readsavestate(self, search_address):
        buffer_use = None

        for deep in range(config.deep_size):
            search_address = self.rd_analysis.ida_support.get_prev_ins_addr(
                search_address
            )
            defs_list = self.get_use_def(search_address)[1]
            mem_def = None

            for def_var_one in defs_list:

                if self.rd_analysis.mdis_support.is_mem(def_var_one[0]):
                    register_list = self.rd_analysis.mdis_support.get_mem_register_name(
                        def_var_one[0]
                    )
                    if (
                        self.rd_analysis.arch.stack_register[0] in register_list
                        or self.rd_analysis.arch.stack_register[1] in register_list
                        or self.rd_analysis.arch.stack_register[2] in register_list
                    ):
                        mem_def = def_var_one
                    break

            if mem_def:
                uses_list = self.get_use_def(search_address)[0]

                register_def = None
                for use_var_one in uses_list:
                    if self.rd_analysis.mdis_support.is_register(use_var_one[0]):
                        register_def = use_var_one
                        break

                uses_list = self.get_use_def(register_def[1])[0]

                for use_var_one in uses_list:
                    if self.rd_analysis.mdis_support.is_op(use_var_one[0]):
                        buffer_use = use_var_one
                        break

            if buffer_use:
                break

        return buffer_use

    @staticmethod
    def check_function(ea, name):
        pass
