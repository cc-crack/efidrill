from efidrill.function_type.function_type import Function_type
from efidrill.config import config


class Sw_Smi(Function_type):

    @staticmethod
    def check_function(ea, name):
        if name.find("ChildSwSmiHandler") == -1 and name.find("SwSmiHandler") != -1:
            return 1
        return 0
