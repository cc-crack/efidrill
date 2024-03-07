import idc
import idautils
import ida_funcs
import ida_ua
import idaapi
import ida_kernwin
import ida_lines
from idaapi import simplecustviewer_t

import os
import json
from efidrill.arch.x64 import *
from efidrill.config import config


class Vuln_Report_Window(simplecustviewer_t):
    def __init__(self):
        super().__init__()
        self.jmp_address = []

    def Create(self, title):

        # Create the customviewer
        if not simplecustviewer_t.Create(self, title):
            return False

        return True

    def OnDblClick(self, shift):
        """
        User dbl-clicked in the view
        @param shift: Shift flag
        @return: Boolean. True if you handled the event
        """
        line_number = self.GetLineNo()
        if line_number >= 0 and line_number <= len(self.jmp_address):
            ida_kernwin.jumpto(self.jmp_address[line_number])

        return True

    def add_line(self, addr, data):
        self.jmp_address.append(addr)
        pfx = ida_lines.COLSTR(data, ida_lines.SCOLOR_KEYWORD)
        self.AddLine(pfx)


class IDA_Support:

    def __init__(self, rd_analysis):
        self.rd_analysis = rd_analysis
        pass

    def get_func_name(self, ea):
        return ida_funcs.get_func_name(ea)

    def get_end_addr(self, start_addr):
        return idc.get_func_attr(start_addr, idc.FUNCATTR_END)

    def get_prev_ins_addr(self, ins_addr):
        return idc.prev_head(ins_addr)

    def get_next_ins_addr(self, ins_addr):
        return idc.next_head(ins_addr)

    def get_op_type(self, ins_addr, op_index):
        return idc.get_operand_type(ins_addr, op_index)

    def check_op_equal_read(self, op_type):

        return op_type in (idc.o_displ, idc.o_mem)

    def get_op_imm_value(self, ins_addr, op_index):
        op_type = self.get_op_type(ins_addr, op_index)

        if op_type != idc.o_imm:
            return 0

        ins = idautils.DecodeInstruction(ins_addr)

        if op_index == 0:
            return ins.Op1.value
        else:
            return ins.Op2.value

    def get_function_address_list(self):
        return idautils.Functions()

    def get_offset(self, ins_addr, op_index):

        ins = idautils.DecodeInstruction(ins_addr)
        if op_index == 0:
            offset = ins.Op1.addr
        else:
            offset = ins.Op2.addr

        return offset

        """
        #define o_void        0  // No Operand                           ----------
        #define o_reg         1  // General Register (al, ax, es, ds...) reg
        #define o_mem         2  // Direct Memory Reference  (DATA)      addr
        #define o_phrase      3  // Memory Ref [Base Reg + Index Reg]    phrase
        #define o_displ       4  // Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
        #define o_imm         5  // Immediate Value                      value
        #define o_far         6  // Immediate Far Address  (CODE)        addr
        #define o_near        7  // Immediate Near Address (CODE)        addr
        #define o_idpspec0    8  // IDP specific type
        #define o_idpspec1    9  // IDP specific type
        #define o_idpspec2   10  // IDP specific type
        #define o_idpspec3   11  // IDP specific type
        #define o_idpspec4   12  // IDP specific type
        #define o_idpspec5   13  // IDP specific type
        """

    def is_op_type(self, address, op_index, want_type):
        return self.get_op_type(address, op_index) in want_type

    def is_call(self, address):
        return idc.print_insn_mnem(address) == self.rd_analysis.arch.call_name

    def is_guess(self, address):
        if idc.print_insn_mnem(address) == self.rd_analysis.arch.cmp_name:
            return 1
        elif idc.print_insn_mnem(address) == self.rd_analysis.arch.and_name:
            return 2

    def is_to_zero(self, address):
        if idc.print_insn_mnem(address) == self.rd_analysis.arch.xor_name:
            return 1
        elif (
            idc.print_insn_mnem(address) == self.rd_analysis.arch.mul_name
            and idc.get_operand_value(address, 1) == 0
        ):
            return 1
        elif (
            idc.print_insn_mnem(address) == self.rd_analysis.arch.sub_name
            and self.is_op_type(address, 0, (1,))
            and self.is_op_type(address, 1, (1,))
        ):
            return 1
        return 0

    def is_call_name(self, address, name):

        if idc.print_insn_mnem(address) == self.rd_analysis.arch.call_name:
            if idc.print_operand(address, 0).find(name) != -1:
                return 1
        return 0

    def is_var_name(self, address, name, op_index):

        if idc.print_operand(address, op_index).find(name) != -1:
            return 1
        return 0

    def get_op_name(self, address, op_index):
        return idc.print_operand(address, op_index)

    def print_insn_mnem(self, address):
        return idc.print_insn_mnem(address)

    def is_register(self, address, name):
        dis_asm = idc.GetDisasm(address)

        return dis_asm.find(name.lower()) != -1

    def get_function_address(self, ins_addr):
        if idc.print_insn_mnem(ins_addr) == self.rd_analysis.arch.call_name:

            maybe_address = idc.get_operand_value(ins_addr, 0)
            if maybe_address in self.get_function_address_list():
                return maybe_address
            elif idc.get_qword(maybe_address) in self.get_function_address_list():
                return idc.get_qword(maybe_address)

        return 0

    def get_jmp_address(self, ins_addr):

        maybe_address = idc.get_operand_value(ins_addr, 0)

        return maybe_address

    def rsp_to_rbp(
        self,
        ins_addr,
        op_index,
    ):
        res = idaapi.insn_t()
        idaapi.decode_insn(res, ins_addr)
        if res.ops[op_index].phrase == 4:
            return idc.get_spd(ins_addr)
        return 0

    def user_ui(self, window_name, ea_addr):

        return

    def is_bigger(self, ins_addr):
        return idc.print_insn_mnem(ins_addr) in self.rd_analysis.arch.bigger_jmp

    def is_small(self, ins_addr):
        return idc.print_insn_mnem(ins_addr) in self.rd_analysis.arch.small_jmp

    def is_eq(self, ins_addr):
        return idc.print_insn_mnem(ins_addr) in self.rd_analysis.arch.equal_jmp

    def is_uneq(self, ins_addr):
        return idc.print_insn_mnem(ins_addr) in self.rd_analysis.arch.unequal_jmp

    def is_not_bigger(self, ins_addr):
        return idc.print_insn_mnem(ins_addr) in self.rd_analysis.arch.not_bigger_jmp

    def is_not_small(self, ins_addr):
        return idc.print_insn_mnem(ins_addr) in self.rd_analysis.arch.not_small_jmp
