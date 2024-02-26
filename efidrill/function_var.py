class Var_List:
    def __init__(self, rd_analysis, func_analysis ):
        self.var_list = []
        self.rd_analysis = rd_analysis
        self.func_analysis = func_analysis
        self.struct_mmap = {}
        self.value_guess = {}
    def check_alias(self, ins_addr):
        is_alias = 0
        register_type = 1
        if self.rd_analysis.ida_support.print_insn_mnem(ins_addr) == 'lea':
            is_alias = 1
        elif  self.rd_analysis.ida_support.print_insn_mnem(ins_addr) == 'mov' and self.rd_analysis.ida_support.is_op_type(ins_addr,1,(register_type,)):
            is_alias = 2
        return is_alias
    def init_var(self, one_var, is_alias):
        if one_var not in self.var_list:
            self.var_list.append(one_var)
            self.struct_mmap[one_var] = []
            self.value_guess[one_var] = {}
        if is_alias == 0:
            self.struct_mmap[one_var].append({})

    def add_var(self,ins_addr, def_var, use_list=[]):
        if def_var in self.var_list:
            return 0
        if ins_addr!= -1:
            is_alias = self.check_alias(ins_addr)
        else:
            is_alias = 0
        if is_alias==1:
            self.init_var(def_var,is_alias)
            for use_var in use_list:
                if self.rd_analysis.mdis_support.is_mem(use_var[0]):
                    if use_var not in self.var_list:
                        self.init_var(use_var, 0)

                    self.struct_mmap[def_var].extend(self.struct_mmap[use_var])
                    self.value_guess[def_var] = self.value_guess[use_var]
        elif is_alias == 2:
            self.init_var(def_var,is_alias)
            for use_var in use_list:
                if self.rd_analysis.mdis_support.is_register(use_var[0]):
                    if use_var not in self.var_list:
                        self.init_var(use_var,0)
                    
                    self.struct_mmap[def_var].extend(self.struct_mmap[use_var])
                    self.value_guess[def_var] = self.value_guess[use_var]
        else:


            self.init_var(def_var,is_alias)
            
            search_offset = 0
            register_list = []
            
            for use_var in use_list:
                if self.rd_analysis.mdis_support.is_mem(use_var[0]):
                    
                    search_offset, is_mem = self.rd_analysis.mdis_support.search_int(use_var[0])
                    register_list = self.rd_analysis.mdis_support.get_mem_register(use_var[0])    
                    break

            if search_offset:

                for use_var in use_list:
                    if use_var not in self.var_list:
                        continue
                    
                    if use_var[0] in register_list:
                        for one_struct_mmap in  self.struct_mmap[use_var]:
                            if search_offset not in one_struct_mmap:
                                one_struct_mmap[search_offset] = []
                            one_struct_mmap[search_offset].append(def_var)


            
                
        return is_alias != 0
    
    def get_guess_analysis(self):
        # Find the imm of the current variable
        offset = self.rd_analysis.ida_support.get_op_imm_value(self.func_analysis.current_ins_addr,0)
        if offset:
            return offset
        offset = self.rd_analysis.ida_support.get_op_imm_value(self.func_analysis.current_ins_addr,1)
        return offset
    def search_case(self, ins_addr,offset_imm):
        # TODO signed jump
        jmp_comm_addr = self.rd_analysis.ida_support.get_next_ins_addr(ins_addr)
        jmp_addr = self.rd_analysis.ida_support.get_jmp_address(jmp_comm_addr)
        next_addr = self.rd_analysis.ida_support.get_next_ins_addr(jmp_comm_addr)
        if jmp_addr> self.func_analysis.end_addr or jmp_addr < self.func_analysis.start_addr:
            return None,None
        if self.rd_analysis.ida_support.is_bigger(jmp_comm_addr):
            return (jmp_addr, [(offset_imm+1,0xefffffffffffffff)]), (next_addr,[(0, offset_imm)]) 
        elif self.rd_analysis.ida_support.is_not_small(jmp_comm_addr):
            return (jmp_addr, [(offset_imm,0xefffffffffffffff)]),(next_addr,[(0, offset_imm-1)]) 
        elif self.rd_analysis.ida_support.is_not_bigger(jmp_comm_addr):
            return (jmp_addr, [(0, offset_imm)]),(next_addr,[(offset_imm+1,0xefffffffffffffff)]) 

        elif self.rd_analysis.ida_support.is_small(jmp_comm_addr):
            return (jmp_addr, [(0, offset_imm-1)]),(next_addr,[(offset_imm,0xefffffffffffffff)]) 

        elif self.rd_analysis.ida_support.is_eq(jmp_comm_addr):
            return (jmp_addr, [(offset_imm,offset_imm)]), (next_addr,[(0, offset_imm-1),(offset_imm+1,0xefffffffffffffff)])
        elif self.rd_analysis.ida_support.is_uneq(jmp_comm_addr):
            return (jmp_addr, [(0, offset_imm-1),(offset_imm+1,0xefffffffffffffff)]), (next_addr,[(offset_imm,offset_imm)])
        else:
            return None,None


    def guess_work(self,ins_addr, use_list_all):
        if self.rd_analysis.ida_support.is_to_zero(ins_addr):
            return 1
        

        op_name = self.rd_analysis.ida_support.is_guess(self.func_analysis.current_ins_addr)# check cmp == 1 and == 2
        offset_imm =  self.get_guess_analysis()
        if not offset_imm:
            return 0
        if op_name == 1:
            value1, value2 = self.search_case(ins_addr, offset_imm)
            if value1 == None:
                return 0
            search_use_var = None

            for use_var in use_list_all:
                if self.rd_analysis.ida_support.is_op_type(self.func_analysis.current_ins_addr,0,(2,3,4)) or \
                    self.rd_analysis.ida_support.is_op_type(self.func_analysis.current_ins_addr,1,(2,3,4)):

                    if self.rd_analysis.mdis_support.is_mem(use_var[0]):
                        search_use_var = use_var
                        break
                elif self.rd_analysis.mdis_support.is_register(use_var[0]):          
                    search_use_var = use_var                   
            if search_use_var:
                if search_use_var in self.var_list:
                    
                    self.value_guess[search_use_var][value1[0]] = value1[1]
                    self.value_guess[search_use_var][value2[0]] = value2[1]
            return 0
                
        elif op_name == 2:
            value = (ins_addr,(0,offset_imm))
            search_use_var = None

            for use_var in use_list_all:
                if self.rd_analysis.ida_support.is_op_type(self.func_analysis.current_ins_addr,0,(2,3,4)) or \
                    self.rd_analysis.ida_support.is_op_type(self.func_analysis.current_ins_addr,1,(2,3,4)):

                    if self.rd_analysis.mdis_support.is_mem(use_var[0]):
                        search_use_var = use_var
                        break
                elif self.rd_analysis.mdis_support.is_register(use_var[0]):          
                    search_use_var = use_var                   
            if search_use_var:
                if search_use_var in self.var_list:
                    self.value_guess[search_use_var][value[0]] =value[1] 
            return 0   
        else:
            
            return 0     

    def get_min_list(self, use_var, useful_address_list):
        min_list = []
        if use_var in self.var_list:
            
            for address, value_data_set  in self.value_guess[use_var].items():
                if address in useful_address_list:
                    for value_data in value_data_set:
                        min_list.append(value_data[0])
        return min_list
    def get_max_list(self, use_var, useful_address_list):
        max_list = []
        if use_var in self.var_list:
            for address, value_data_set  in self.value_guess[use_var].items():
                if address in useful_address_list:
                    for value_data in value_data_set:
                        max_list.append(value_data[0])
        return max_list
    def get_value_guess(self, use_var):
        if use_var in self.value_guess.keys():
            return self.value_guess[use_var]
        else:
            return []
    def search_register(self, use_list, register_name):
        for use_var in use_list:

            if self.rd_analysis.mdis_support.is_register(use_var[0], register_name):
                return use_var
            
    def search_mem(self, use_list):
        for use_var in use_list:    
            if self.rd_analysis.mdis_support.is_mem(use_var[0]):
                return use_var
    def search_from(self,ins_addr, input_var):
        use_list, def_list = self.func_analysis.get_use_def(input_var[1])
        var_get_from_list = use_list

        for var_get_from in var_get_from_list:
            if self.rd_analysis.mdis_support.is_mem(var_get_from[0]) and self.rd_analysis.ida_support.is_op_type(input_var[1],1,(2,3,4)):
                return var_get_from
            elif self.rd_analysis.mdis_support.is_register(var_get_from[0]) and self.rd_analysis.ida_support.is_op_type(input_var[1],1,(1,)):
                return var_get_from
    def fix_def(self, ins_addr,def_list, use_list):
        for use_var in use_list:
            if self.rd_analysis.mdis_support.is_mem(use_var[0]) and self.rd_analysis.ida_support.is_op_type(ins_addr,1,(2,3,4))\
                and use_var[1] == -1:
                call_use_list = self.rd_analysis.mdis_support.use_var_search(use_list[0][0])
                for call_var in call_use_list:
                    if call_var in self.func_analysis.interesting_op_list:
                        def_list.append(use_var)
                        return
                    
    def copy_var(self,sub_func_var , use_var):
        if use_var not in self.var_list:
            return 
        if use_var not in sub_func_var.var_list:
            sub_func_var.init_var(use_var,0)
        
        
        sub_func_var.struct_mmap[use_var].extend(self.struct_mmap[use_var])
        sub_func_var.value_guess[use_var] = self.value_guess[use_var]
