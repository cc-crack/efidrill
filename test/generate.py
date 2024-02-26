#!/usr/bin/env python

import os
import glob
import re
import shutil
import sys
import hashlib
import logging


console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',filename='gen.log')
logger = logging.getLogger("generate")
logger.addHandler(console_handler)

def calculate_md5(file_path):
    # 创建 MD5 哈希对象
    md5_hash = hashlib.md5()

    # 以二进制方式打开文件，并逐块更新哈希对象
    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b''):
            md5_hash.update(chunk)

    # 获取最终的 MD5 值（以十六进制表示）
    md5_value = md5_hash.hexdigest()

    return md5_value



def download_BIOSBIN(folder):
    p = os.path.abspath(os.path.expanduser(folder))
    os.system("wget -r -np -nd  -nH -R index.html  http://192.168.51.155:9999/ -P " + folder)
    for f in glob.glob(os.path.join(p,"index.*")):
        os.remove(f)

def extract(biosfile,bforce = False):
    if os.path.exists(biosfile+".report.txt") and os.path.exists(biosfile+".dump"):
        logger.info(f"{biosfile} already extracted!")
        if bforce:
            try:
                shutil.rmtree(biosfile+".dump")
            except Exception as e:
                logger.info(e)
            try:
                os.remove(biosfile+".report.txt")
            except Exception as e:
                logger.info(e)
    else:
        logger.info("call extract " + biosfile)
        bforce = True
    if bforce == True:
        os.system("UEFIExtract \"" + biosfile + "\"")
    return (biosfile+".report.txt", biosfile+".dump")

"""
report: report file path
return: a list pair of SMM and DEX files
"""
def report_parser(report):
    def parserline(s):
        items = s.split("|")
        if len(items) == 7:
            guid = items[-2].strip().replace("\n","")
            name = items[-1].strip().replace("\n","")
        else:
            guid = items[-1].strip().replace("\n","")
            name = "None"
        result = re.match(r"\S+\s(.*)", guid)
        if result:
            guid = result.group(1)
        return (guid,name)
    
    with open(report) as f:
        lines = f.readlines()
        x= [parserline(l) for l in lines if l.find("SMM module") != -1]
        y= [parserline(l) for l in lines if l.find("DXE driver") != -1]
        f.close()
        return x,y
    
def search_directory(directory, keyword):
    matching_files = []
    for root, dirs, files in os.walk(directory):
        for d in dirs:
            if keyword in d:
                matching_files.append(os.path.join(root, d))
    return matching_files

def find_module_PE_file(dumpdir,guid,name):
    modulepath = []
    if guid:
        modulepath = search_directory(dumpdir,guid)

    if len(modulepath) == 0 and name!="None":
        modulepath = search_directory(dumpdir,name)
    
    if len(modulepath) == 0:
        return None
    else:
        ## check guid
        fd = None        
        for m in modulepath:
            with open(os.path.join(m,"info.txt")) as f:
                fd = m if f.read().find(guid) != -1 else None
                f.close()
            if fd:
                break

        if not fd:
            return None
        
        # find PE folder
        pefd = search_directory(fd,"PE32 image")
        if len(pefd) == 0:
            return None
        pefilename = os.path.join(pefd[0],"body.bin")
        return pefilename

def pickup_all_modules(indir,outdir,skipsmm = False):
    pin = os.path.abspath(os.path.expanduser(indir))
    pout = os.path.abspath(os.path.expanduser(outdir))
    try:
        os.mkdir(pout)
    except:
        pass
    binfiles = glob.glob(os.path.join(pin,"*"))
    for f in binfiles:
        logger.info(f)
        report, dump = extract(f)
        try:
            smmlist,dxelist = report_parser(report)
            if len(smmlist):
                try:
                    smmdir = os.path.join(pout,"smm")
                    os.mkdir(smmdir)
                except:
                    pass
            if len(dxelist):
                try:
                    dxedir =os.path.join(pout,"dxe")
                    os.mkdir(dxedir)
                except:
                    pass
            if not skipsmm:
                for (smmguid,smmname) in smmlist:
                    fname = find_module_PE_file(os.path.abspath(dump),smmguid,smmname)
                    if fname:
                        logger.info(fname)
                        newfname = "_".join((smmguid,smmname) + (calculate_md5(fname),))
                        logger.info(newfname)
                        shutil.copyfile(fname,os.path.join(smmdir,newfname))
                    else:
                        logger.debug(f"SMM module {smmguid}, {smmname} not found!")
            for (dxeguid,dxename) in dxelist:
                try:
                    fname = find_module_PE_file(os.path.abspath(dump),dxeguid,dxename)
                    if fname:
                        logger.info(fname)
                        newfname = "_".join((dxeguid,dxename) + (calculate_md5(fname),))
                        logger.info(newfname)
                        shutil.copyfile(fname,os.path.join(dxedir,newfname))
                    else:
                        logger.debug(f"DXE module {dxeguid}, {dxename} not found!")
                except Exception as ee:
                    logger.debug(f"Exception at {dxeguid} {dxename} {fname}")
                    logger.debug(ee)
        except Exception as e:
            logger.debug(e)
        finally:
            continue


if __name__ == "__main__":
    download_BIOSBIN("./biosfiles")
    pickup_all_modules("./biosfiles","./modules")