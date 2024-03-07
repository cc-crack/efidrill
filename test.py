import os

from efidrill.config import config
from efidrill.debug import DBG
from efidrill.logging import Logger
from efidrill.rd_analysis import RD_Analysis
from efidrill.result import res


class EfidrillTest:
    def __init__(self) -> None:
        pass

    @staticmethod
    def run():
        config.init_dump_file_path()
        Logger(log_file=os.path.join(config.dump_file_path, config.logging_path))
        a = RD_Analysis()
        a.init_efiXplorer64()
        a.work()
        res.dump().show()


if __name__ == "__main__":
    DBG()
    EfidrillTest().run()
