from efidrill.function_type.function_type import Function_type


class Sub_Function(Function_type):

    @staticmethod
    def check_function(ea, name):
        if name.find("SubFunction") != -1:
            return 1
        return 0
