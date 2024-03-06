import pydevd_pycharm


def DBG():
    pydevd_pycharm.settrace(
        "localhost", port=2233, stdoutToServer=True, stderrToServer=True
    )
