from efidrill.plugin.base_plugin import Base_Plugin


class Check_Memcory(Base_Plugin):
    def vulnerability_find(self, current_func, use_list, def_list, use_list_all):
        current_address = self.rd_analysis.function_support.get_current_addr(
            current_func
        )
        if (
            self.rd_analysis.ida_support.is_call_name(current_address, "MEMCOPY")
            and use_list
        ):
            use_list, def_list = self.rd_analysis.function_support.get_use_def(
                current_func, current_address
            )
            use_list_name = []
            # Find out whether the function pointer contains variables we can control
            for use_var in use_list:
                if (
                    self.rd_analysis.mdis_support.is_register(
                        use_var, self.rd_analysis.arch.function_param[2]
                    )
                    and self.rd_analysis.function_support.get_value_guess(
                        current_func, use_var
                    )
                    == {}
                ):
                    use_list_name.append(use_var.name)
                if self.rd_analysis.mdis_support.is_register(
                    use_var, self.rd_analysis.arch.function_param[1]
                ):
                    use_list_name.append(use_var.name)

            if len(use_list_name) == 2:

                if self.check_new_vuln_address(current_address):
                    self.vulnerability_log(
                        current_address,
                        "Vulnerability:memcopy OOB find address == "
                        + hex(current_address),
                    )


PLUGIN_CLASS = Check_Memcory
