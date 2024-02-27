#!/usr/bin/env python3

import glob
import os
import shutil


def clean_result():
    workspace = os.path.expanduser("~\\efidrill_workspace")
    for i in glob.glob(
        os.path.join(os.path.expanduser(workspace), "*\\res.json"), recursive=True
    ):
        with open(i) as f:
            s = f.read()
            f.close()
        if s == "{}":
            dir, name = os.path.split(i)
            shutil.move(dir, dir + "_empty")

    os.system(
        f'7z a -tzip -mx=9 {os.path.join(os.path.expanduser(workspace), "empty.zip")} {os.path.join(os.path.expanduser(workspace), "*_empty")}'
    )
    directories = glob.glob(os.path.join(os.path.expanduser(workspace), "*_empty"))

    for directory in directories:
        shutil.rmtree(directory)
