from efidrill.function_type.function_type import Function_type


class Sw_Smi(Function_type):

    @staticmethod
    def check_function(ea, name):
        if name.find("ChildSwSmiHandler") == -1 and name.find("SwSmiHandler") != -1:
            return 1
        return 0
