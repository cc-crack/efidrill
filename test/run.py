#!/usr/bin/env/ python
import os
import subprocess
ida_path = "/Applications/IDA Pro 8.2/idabin/idat64"
work_dir = os.path.abspath('./modules')
script_path = os.path.abspath("./analysis.py")

moduels = []
moduels.append(os.listdir(os.path.join(work_dir,"smm")))
moduels.append(os.listdir(os.path.join(work_dir,"dxe")))
for file in moduels:
    # cmd_str = ida.exe -Lida.log -c -A -Sanalysis.py pefile
    cmd_str = f'"{ida_path}" -Lida.log -c -A -S{script_path} {os.path.join(work_dir, file)}'
    print(cmd_str)
    p = subprocess.Popen((cmd_str),shell=True)
    p.wait()

import check
check.clean_result()