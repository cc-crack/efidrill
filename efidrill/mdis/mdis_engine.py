from miasm.core.locationdb import LocationDB
from miasm.analysis.machine import Machine
from miasm.core.bin_stream_ida import bin_stream_ida
from miasm.analysis.data_flow import DeadRemoval
from efidrill.mdis.ReachingDefinitionsvar import ReachingDefinitionsVar
from efidrill.mdis.ReachingDefinitionscfg import ReachingDefinitionsCFG
from future.utils import viewitems, viewvalues

from miasm.arch.x86.disasm import cb_x86_funcs
def block_cb(mdis,block,offset):
    for i,v in enumerate(block.lines):
        if v.name == 'WBINVD':
            print(f"!!!!!Patch WBINVD to NOP on {block} line {i}")
            v.name = "NOP"


class Mdis_Engine:
    def __init__(self, rd_analysis) -> None:
        self.loc_db = LocationDB()
        self.machine = Machine("x86_64")
        bin_stream = bin_stream_ida()
        self.rd_analysis = rd_analysis
        self.mdis = self.machine.dis_engine(bin_stream, loc_db=self.loc_db, dont_dis_nulstart_bloc=True)
        self.mdis.follow_call = True
    

    def get_ircfg(self, function_start_address):
        cb_x86_funcs.append(block_cb)
        asmcfg = self.mdis.dis_multiblock(function_start_address)
        lifter = self.machine.lifter_model_call(loc_db=self.loc_db)
        DeadRemoval(lifter)
        try:
            ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)
        except Exception as e:
            ins = str(e).split(" ")[1].strip()
            print(f"Unsuppot instrustion {ins}")
            ircfg = None 
        return ircfg





    def get_def(self, use_info, ircfg):
        def_info = {}
        for address, definition in use_info.items():
            for element, set_address in  definition.items():
                

                for address_in in set_address:
                   
                    if address_in[0] == -1:
                        continue
                        
                    if address_in not in def_info.keys():
                        def_info[address_in] = {}     
                    
                    def_info[address_in].update({element:[address_in]})
        
        for address in use_info.keys():
            if address not in def_info.keys():
                def_info[address] = {}
                if address[1]>= len(ircfg.blocks[address[0]]):
                    continue
                for lval in ircfg.blocks[address[0]][address[1]]:
                    def_info[address].update({lval:[address]})
                    
        
        return def_info
    
    def get_use_def(self, ircfg, mmap_ir_to_address):
        use_info = ReachingDefinitionsVar(ircfg, mmap_ir_to_address)
        
        def_info = self.get_def(use_info, ircfg)
        
        return use_info, def_info
    
    def have_path_gather(self, ircfg, mmap_ir_to_address):
        path_info = ReachingDefinitionsCFG(ircfg, mmap_ir_to_address)
        return path_info
    
    def gather_ir_data(self,ircfg, mmap_ir_to_address):
        all_ir = {}
        for block in viewvalues(ircfg.blocks):
            for assignblk_index in range(len(block)):
                assignblk = block[assignblk_index]
                address = mmap_ir_to_address[(block.loc_key,assignblk_index)]
                if  address not in all_ir:
                    all_ir[address] = []
                all_ir[address].append(assignblk)
        return all_ir