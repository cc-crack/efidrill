import struct
from ctypes import *
import shutil
import platform
import traceback
from efidrill.check_engine import Check_Engine
from efidrill.ida_work.ida_support import IDA_Support
from efidrill.mdis.mdis_support import Mdis_Support
from efidrill.mdis.mdis_engine import Mdis_Engine
from efidrill.logging import Logger
from efidrill.config import config
from efidrill.arch.x64 import x64
from efidrill.function_support import Function_Support
from efidrill.user_define_work import User_Function_Define
from efidrill.plugin_mgr import PluginMgr
"""
from rd_analysis.get_guid import getGUID
from miasm.arch.x86.arch import is_op_segm
from miasm.expression.expression import ExprId, ExprMem, ExprSlice, ExprOp
"""
logger = Logger()

class RD_Analysis:
    def __init__(self):
           
        self.mdis_engine  =   Mdis_Engine(self)
        self.check_engine =   Check_Engine(self) 
        self.ida_support  =   IDA_Support(self)
        self.mdis_support = Mdis_Support(self)
        self.function_support = Function_Support(self)
        self.arch = x64
        self.is_all = 0
        self.function_callback = User_Function_Define(self)
        self.pluginmgr = PluginMgr().load_plugins(self)
     
    def get_smi_ea(self):
        for ea in self.ida_support.get_function_address_list():
            smi_function, is_new = self.check_engine.get_function_by_ea(ea)
            if smi_function:
                self.check_engine.function_queue.put((smi_function, 0))

    def get_dxe_ea(self):
        for ea in self.ida_support.get_function_address_list():
            search_function, is_new = self.check_engine.get_function_by_ea(ea,"SubFunction")
            if is_new:
                self.check_engine.function_queue.put((search_function, config.max_function_deep-1))

        return 
    def work(self):
        self.get_smi_ea()
        logger.info("ttttt")
        return

        while(1):
            if self.check_engine.function_queue.qsize() == 0:
                if self.is_all:
                    break
                self.get_dxe_ea()
                
                self.is_all = 1
                self.pluginmgr.switch_SMI_to_Normal()
                continue
            init_error = 0
            # try:
            element =  self.check_engine.function_queue.get()

            ana_function=element[0]
            function_deep =element[1] 
            logger.info("Begin Function Analyzer, Function address=="+hex(ana_function.start_addr))
            logger.info("function_size== "+ str(len(self.check_engine.ea_function.keys()))+" size of ana_function_list =="+str(self.check_engine.function_queue.qsize()))
            if function_deep>=config.max_function_deep:
                continue
            # ana_function.init_function_analysis()
            # except:
            #      init_error = 1
            #      print("error init")
            if not init_error:
                try:
                    ana_function.analysis(function_deep)
                except:
                    logger.error("Error! Function Analyzer Failed, Function address=="+hex(ana_function.start_addr))
                    logger.info(traceback.format_exc())
                    continue
            logger.info("Finish Function Analyzer Success, Function address=="+hex(ana_function.start_addr))

        self.pluginmgr.dump_all_log()

       
                
    def init_efiXplorer64(self):
        try:
            import ida_loader
            ida_loader.load_and_run_plugin("efiXplorer64",7)
        except:
            logger.error("Error! Load efiXplorer64 failed! Please check if efiXplorer has been installed correctly.")
        
    def finish_plugin(self):
        for ana_function in self.check_engine.ea_function.values():
            if ana_function.is_smi:
                ana_function.check_work_dict['Check_Struct'].finish_work()
    
    def rd_test(self):
        smi_function, is_new = self.check_engine.get_function_by_ea(0xa84,"SubFunction")
        # smi_function.init_function_analysis()
        smi_function.analysis(0)

        return 
