
from efidrill.rd_analysis import RD_Analysis
from efidrill.result import res
from efidrill.config import config
from efidrill.logging import Logger
import os

class efidrill_test():
    def __init__(self) -> None:
        pass
    def run(self):
        config.init_dump_file_path()
        Logger(log_file=os.path.join(config.dump_file_path, config.logging_path))
        a=  RD_Analysis()
        a.init_efiXplorer64()
        breakpoint()
        a.work()
        res.dump().show()


efidrill_test().run()






















        