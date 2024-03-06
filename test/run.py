#!/usr/bin/env/ python
import os
import subprocess

ida_path = "idat64"
work_dir = os.path.abspath("./modules")
script_path = os.path.abspath("./analysis.py")

modules = []
modules.extend(
    [
        os.path.join(work_dir, "smm", file)
        for file in os.listdir(os.path.join(work_dir, "smm"))
    ]
)
modules.extend(
    [
        os.path.join(work_dir, "dxe", file)
        for file in os.listdir(os.path.join(work_dir, "dxe"))
    ]
)

for file in modules:
    # cmd_str = ida.exe -Lida.log -c -A -Sanalysis.py pefile
    cmd_str = f"{ida_path} -Lida.log -c -A -S{script_path} {file}"
    print(cmd_str)
    p = subprocess.Popen(cmd_str, shell=True)
    p.wait()
