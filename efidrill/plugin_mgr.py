import glob
import importlib
import os
from efidrill.config import config
from efidrill.logging import Logger

logger = Logger()


class PluginMgr:
    def __init__(self) -> None:
        self.plugins = {}
        self.save_plugins = {}

    def load_plugins(self, rd_analysis):

        def import_all_from(module_path, module_name):
            module_spec = importlib.util.spec_from_file_location(
                module_name, module_path
            )
            module = importlib.util.module_from_spec(module_spec)
            module_spec.loader.exec_module(module)
            return module

        module_files = glob.glob(os.path.join(config.efidrillpath, "plugin/*.py"))
        for m in module_files:
            if m.find("base_plugin") != -1:
                continue
            dirname, filename = os.path.split(m)
            module = import_all_from(m, filename[:-3])
            if module is None:
                logger.error(f"Load {filename} failed!")
            elif getattr(module, "PLUGIN_CLASS") is None:
                logger.warning(f"Invaild Plugin {filename}")
            else:
                self.plugins[module.PLUGIN_CLASS.__name__] = module.PLUGIN_CLASS(
                    rd_analysis
                )
                logger.info(f"Load {filename} success!")
        return self

    def get_plugin(self, name):
        return self.plugins[name]

    def callplugin_on_vulnerability_find(self, fuc, use_list, def_list, use_list_all):
        for p in self.plugins.values():
            p.vulnerability_find(fuc, use_list, def_list, use_list_all)

    def callplugin_on_add_interesting_memory_map_list(
        self, fuc, def_var, use_list, is_alias, default_value
    ):
        for p in self.plugins.values():
            p.add_interesting_memory_map_list(
                fuc, def_var, use_list, is_alias, default_value
            )

    def callplugin_on_copy_use_var(self, func, caller_func, use_var):
        for p in self.plugins.values():
            p.copy_use_var(func, caller_func, use_var)

    def dump_all_log(self):
        for p in self.save_plugins.values():
            p.print_log()

    def switch_SMI_to_Normal(self):
        self.save_plugins = self.plugins
        self.plugins = {}
        for plugin_name, plugin in self.save_plugins.items():
            if not plugin.is_smi_only:
                self.plugins[plugin_name] = plugin
