from efidrill.plugin.base_plugin import Base_Plugin
from efidrill.config import config


class Struct_build(Base_Plugin):

    def finish_work(self, current_func):

        interesting_op_list = self.rd_analysis.function_support.get_interesting_op_list(
            current_func
        )
        dump_path = config.dump_file_path + "/struct.json"
        if not self.rd_analysis.function_support.is_smi(current_func):
            return
        with open(dump_path, "w+") as dump_file:
            for interesting_op in interesting_op_list:
                if (
                    self.rd_analysis.mdis_support.is_register(
                        interesting_op[0], self.rd_analysis.arch.function_param[2]
                    )
                    and interesting_op[1] == -1
                ):
                    start_address = self.rd_analysis.function_support.get_start_addr(
                        current_func
                    )
                    self.rd_analysis.function_support.dump_struct(
                        current_func, dump_file, interesting_op
                    )


PLUGIN_CLASS = Struct_build
