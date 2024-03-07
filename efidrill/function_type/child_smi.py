from efidrill.function_type.function_type import Function_type


class Child_Smi(Function_type):
    def __init__(self, rd_analysis, start_addr, is_smi):
        super().__init__(rd_analysis, start_addr, is_smi)
        self.input_miasm[rd_analysis.arch.function_param[2]] = []
        self.input_miasm[rd_analysis.arch.function_param[3]] = []

    @staticmethod
    def check_function(ea, name):
        if name.find("ChildSwSmiHandler") != -1:
            return 1
        return 0
