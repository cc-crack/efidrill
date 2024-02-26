from efidrill.function_type.child_smi import Child_Smi
from efidrill.function_type.sw_smi import Sw_Smi
from efidrill.function_type.sub_function import Sub_Function

def function_type(rd_analysis, ea, name):
    if Child_Smi.check_function(ea, name):
        return Child_Smi(rd_analysis, ea, is_smi=1)
    
    if Sw_Smi.check_function(ea, name):
        return Sw_Smi(rd_analysis, ea, is_smi=1)
    
    if Sub_Function.check_function(ea, name):
        return Sub_Function(rd_analysis, ea)
    return None


