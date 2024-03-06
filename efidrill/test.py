from miasm.core.locationdb import LocationDB
from miasm.analysis.machine import Machine
from miasm.core.bin_stream_ida import bin_stream_ida
from miasm.analysis.data_flow import DeadRemoval, ReachingDefinitions, DiGraphDefUse
from future.utils import viewitems, viewvalues
import os


loc_db = LocationDB()
machine = Machine("x86_64")
bin_stream = bin_stream_ida()

mdis = machine.dis_engine(bin_stream, loc_db=loc_db, dont_dis_nulstart_bloc=True)
mdis.follow_call = True


asmcfg = mdis.dis_multiblock(0x38753)
lifter = machine.lifter_model_call(loc_db=loc_db)
deadrm = DeadRemoval(lifter)
ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

# print(reaching_defs)
for block in viewvalues(ircfg.blocks):
    for test in block:
        print(test)
    break

