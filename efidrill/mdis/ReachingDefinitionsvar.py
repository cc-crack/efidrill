from miasm.analysis.data_flow import DeadRemoval, ReachingDefinitions
from miasm.expression.expression import ExprId, ExprMem, ExprSlice, ExprOp
from miasm.arch.x86.arch import is_op_segm
from efidrill.mdis.mdis_support import Mdis_Support
from future.utils import viewitems, viewvalues
from efidrill.logging import Logger
from efidrill.config import config

logger = Logger()
class ReachingDefinitionsVar(ReachingDefinitions):
        def __init__(self,ircfg, mmap_ir_to_address):
            self.mmap_ir_to_address = mmap_ir_to_address
            self.def_use = {}
            super().__init__(ircfg)

        def compute(self):
            """This is the main fixpoint"""
            modified = True
            while modified:
                modified = False
                for block in viewvalues(self.ircfg.blocks):
                    modified |= self.process_block(block)
            
            self.fix_use()
            
            

            
        def use_var_search(self, exp_ir):
            use_var_list = []
            if type(exp_ir) == ExprOp:

                if exp_ir.op in ("+","-"):
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

        def ir_log(self,loc_key,ass_index,  data):
            if config.debug_flag:
                logger.info(hex(self.mmap_ir_to_address[(loc_key, ass_index)]))
                logger.info(str(data))
        def fix_use(self):
            for block in viewvalues(self.ircfg.blocks):
                for assignblk_index, assignblk in enumerate(block):
                    new_address_dict = {}


                    for op in assignblk:
                        
                        get_use_list = self.use_var_search(op)
                        self.ir_log(block.loc_key, assignblk_index, op)
                        self.ir_log(block.loc_key, assignblk_index,get_use_list)
                        

                        for get_use in get_use_list:
                            
                            if get_use in self[(block.loc_key, assignblk_index)].keys():
                                
                                new_address_dict.update({get_use:self[(block.loc_key, assignblk_index)][get_use]})
                    
                    
                    self.def_use[(block.loc_key, assignblk_index)] = new_address_dict  


                    new_address_dict = {}


                    for op in assignblk.values():
                        
                        get_use_list = self.use_var_search(op)
                        self.ir_log(block.loc_key, assignblk_index, op)
                        self.ir_log(block.loc_key, assignblk_index,get_use_list)
                        

                        for get_use in get_use_list:
                            
                            if get_use not in self[(block.loc_key, assignblk_index)].keys():
                                new_address_dict.update({get_use: [(-1 ,-1)]})
                            else:
                                new_address_dict.update({get_use:self[(block.loc_key, assignblk_index)][get_use]})
                            
                    
                    self[(block.loc_key, assignblk_index)] = new_address_dict
                    
            
                    
