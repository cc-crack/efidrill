from miasm.expression.expression import ExprId, ExprMem, ExprSlice, ExprOp, ExprInt
from future.utils import viewitems, viewvalues


class Mdis_Support:
    def __init__(self, rd_analtsis):
        self.rd_analysis = rd_analtsis

    def mmap_ir_to_address(self, mmap_ir_address, old_dict):
        fix_dict = {}

        for address, definition in old_dict.items():

            if address not in mmap_ir_address.keys():
                continue
            if mmap_ir_address[address] not in fix_dict.keys():
                fix_dict[mmap_ir_address[address]] = []
            if type(definition) == dict:

                for element, address_in_set in definition.items():

                    for address_in in address_in_set:
                        if address_in[0] == -1:
                            fix_dict[mmap_ir_address[address]].append((element, -1))
                        else:

                            fix_dict[mmap_ir_address[address]].append(
                                (element, mmap_ir_address[address_in])
                            )
            elif type(definition) == set:

                for address_in in definition:
                    fix_dict[mmap_ir_address[address]].append(
                        mmap_ir_address[address_in]
                    )

        return fix_dict

    def use_var_search(self, exp_ir):
        use_var_list = []
        if type(exp_ir) == ExprOp:

            if exp_ir.op in ("+", "-", "&", "|", "^"):
                use_var_list.append(exp_ir)
            for arg in exp_ir.args:
                use_var_list.extend(self.use_var_search(arg))
        elif type(exp_ir) == ExprMem:
            use_var_list.append(exp_ir)
            use_var_list.extend(self.use_var_search(exp_ir.get_arg()))
        elif type(exp_ir) == ExprId:

            use_var_list.append(exp_ir)
        elif type(exp_ir) == ExprSlice:
            use_var_list.extend(self.use_var_search(exp_ir.arg))
        return use_var_list

    def get_mmap_ir_to_address(self, ircfg):
        mmap_ir_address = {}
        mmap_address_ir = {}
        for block in viewvalues(ircfg.blocks):
            for index, assignblk in enumerate(block):
                if assignblk.instr.offset not in mmap_address_ir.keys():
                    mmap_address_ir[assignblk.instr.offset] = []
                mmap_ir_address[(block.loc_key, index)] = assignblk.instr.offset
                mmap_address_ir[assignblk.instr.offset].append((block.loc_key, index))
        return mmap_ir_address, mmap_address_ir

    def check_is_address(self, address, op):
        if type(op) == ExprMem:
            if type(op.get_arg()) == ExprInt:

                if address == int(op.get_arg()):
                    return 1
        return 0

    def is_register(self, op, register_name=None):
        if type(op) == ExprId:
            if register_name:
                if op.name == register_name:
                    return 1
                else:
                    return 0
            else:
                return 1
        else:
            return 0

    def get_int(self, op):
        if type(op) == ExprInt:
            return int(op)
        else:
            return None

    def is_global_mem(self, op):
        flag = 1

        if type(op) == ExprMem:
            flag = self.is_global_mem(op.get_arg())
        elif type(op) == ExprInt:
            flag = 1
        elif type(op) == ExprOp:
            for arg in op.args:
                flag &= self.is_global_mem(arg)
        else:
            flag = 0

        return flag

    def is_mem(self, op):
        if type(op) == ExprMem:
            return 1
        return 0

    def is_op(self, op):
        if type(op) == ExprOp:
            return 1
        return 0

    def is_useful_register(self, op, register_list):
        if self.is_register(op):
            if op.name in register_list:
                return 1
        return 0

    def get_mem_register_name(self, op):
        mem_op = op.get_arg()
        result = []
        if type(mem_op) == ExprId:
            result.append(mem_op.name)
        else:
            for arg in mem_op.args:
                if type(arg) == ExprId:
                    result.append(arg.name)
        return result

    def get_mem_register(self, op):
        new_op = op.get_arg()
        result = []
        if type(new_op) == ExprId:
            result.append(new_op)
        elif type(new_op) == ExprOp:

            for arg in new_op.args:
                if type(arg) == ExprId:
                    result.append(arg)

        return result

    def search_int(self, exp_ir):
        has_register = 0
        offset = None
        if type(exp_ir) == ExprMem:
            exp_ir = exp_ir.get_arg()
            if type(exp_ir) == ExprId:
                offset = 0
                has_register = 1
                return offset, has_register

        if type(exp_ir) == ExprOp:

            if exp_ir.op in ("+", "-", "&", "|", "^"):
                for arg in exp_ir.args:
                    if type(arg) == ExprInt:
                        offset = int(arg)

                    if type(arg) == ExprId:
                        has_register = 1

                if has_register:
                    return offset, 1
        return None, 0
