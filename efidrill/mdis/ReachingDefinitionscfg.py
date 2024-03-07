from miasm.analysis.data_flow import DeadRemoval, ReachingDefinitions
from miasm.expression.expression import ExprId, ExprMem, ExprSlice, ExprOp
from miasm.arch.x86.arch import is_op_segm
from efidrill.mdis.mdis_support import Mdis_Support
from future.utils import viewitems, viewvalues
from efidrill.logging import Logger
from efidrill.config import config


class ReachingDefinitionsCFG(ReachingDefinitions):
    def __init__(self, ircfg, mmap_ir_to_address):
        self.mmap_ir_to_address = mmap_ir_to_address
        super().__init__(ircfg)

    def get_definitions(self, block_lbl, assignblk_index):

        return self.get((block_lbl, assignblk_index), set())

    def process_block(self, block):
        """
        Fetch reach definitions from predecessors and propagate it to
        the assignblk in block @block.
        """
        predecessor_state = set()
        for pred_lbl in self.ircfg.predecessors(block.loc_key):
            if pred_lbl not in self.ircfg.blocks:
                continue
            pred = self.ircfg.blocks[pred_lbl]
            predecessor_state = predecessor_state | self.get_definitions(
                pred_lbl, len(pred)
            )

        modified = self.get((block.loc_key, 0)) != predecessor_state
        if not modified:
            return False
        self[(block.loc_key, 0)] = predecessor_state

        for index in range(len(block)):
            modified |= self.process_assignblock(block, index)
        return modified

    def process_assignblock(self, block, assignblk_index):
        """
        Updates the reach definitions with values defined at
        assignblock @assignblk_index in block @block.
        NB: the effect of assignblock @assignblk_index in stored at index
        (@block, @assignblk_index + 1).
        """

        assignblk = block[assignblk_index]
        defs = self.get_definitions(block.loc_key, assignblk_index).copy()
        defs.add((block.loc_key, assignblk_index))

        modified = self.get((block.loc_key, assignblk_index + 1)) != defs
        if modified:
            self[(block.loc_key, assignblk_index + 1)] = defs

        return modified
