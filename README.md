[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0)

<div align="center">
<img src=./icon/logo.png width=30%>
</div>

**Efidrill** - IDA plugin for  UEFI firmware vulnerability hunting base on data flow analysis

__Supported versions of IDA:__ Well tested on IDA pro 8.2

__Supported Platforms:__ Windows, Linux and OSX.


## Plugin installation

1. `git clone https://git.csl.secx/bios-research/efidrill.git`
2. `ln -s {efidrill path}/efidrill.py ~/.idapro/plugin/`
3. `ln -s {efidrill path}/efidrill ~/.idapro/plugin/`

## Configeration

TODO:

## 目录结构

    RD_Analysis 主程序
    ida_support ida 相关支持封装
    check_engine 漏洞分析引擎，里面加载了所有漏洞分析插件，并且会进行函数类的初始化
    function_type 针对不同函数的处理类的封装，并且会初始化smram外部输入数据
    check_work_plugin 所有分析插件
    mdis 可达定义分析的实现库，封装了mdisam
    mdis_engine 生成use def 的引擎
    mdis_support 封装ir处理的文件

## 重要结构体

        self.interesting_op_list 存储所有感兴趣的内容 [def_var]（toctou只有-1一个元素说明，当前变量不分析toctou）
        self.all_uses, self.all_defs 存储所有 use def {address:[define]}
        self.current_ins_addr 当前分析地址
        self.ircfg 当前 ir
        self.mmap_ir_address ir地址和address的映射[(block_index,assm_index),address]
        变量 (mdiasm_struct,address)
        miasm中的变量 (mdiasm_struct,(block_index,assm_index))
    
        
        mdiasm结构体 存储各种op，id（寄存器），int，mem，参考链接： https://miasm.re/miasm_doxygen/classmiasm_1_1expression_1_1expression_1_1_expr_mem.html

## 如何实现一个插件
        继承check_work_plugin
        add_interesting_memory_map_list函数会在一个新的def被加入感兴趣的变量中时被调用， 并且use_list是调用def时感兴趣的use_list，is_alias是判断这个变量是否是一个变量的别名
        vulnerability_find在每一条地址都会执行，use_list是该地址使用的所有感兴趣的变量，def_list是该地址定义的所有变量
        注意，因为一个def_var会对应多个use_var所以变量赋值需要以def_var对use_list的列表映射

## RD问题说明
        请注意 toctou和struct插件不是rd问题，所以存在路径爆炸（他的栈深度不会超过最大限制），其他问题是rd问题，所以不存在路径爆炸问题
        


## 重要函数

       mmap_ir_to_address 映射 字典中的ir地址和地址
       check_insteresting_variables 找到感兴趣的变量（0x40e，readsavesatate， commbuffer）不同函数不同
       ana_ins_addr 分析每一条汇编
       add_interesting_memory_map_list 向interesting_op_list 添加新的define
       vulnerability_find check_engine引擎，调用所有插件
       fix_use 找到远跳use(def不在当前函数中), 远跳块ir地址为（-1，-1），地址为-1
       get_def 生成def

## TODO list
    写一个Fuzz模块

## Can Do List
    datasize处理 栈别名问题
    启发表达式跳转判断不全

## 目前不完备的假设
    SMRAM越界访问最安全假设：一个函数将rcx作为外部输入我们假定他是调用，无论实际与否（可能漏报）
    外部数据地址假定：一个数据只要从外部而来，我们不考虑本身PC中的内存位置与SMM的位置（可能误报）

## Test cases build

### upload

https://nas01.csl.secx/sharing/ERaoFgUK3

### download

http://192.168.51.155:9999/

## Running test

`cd ./test`

`python3 ./generate.py` for extracting all modules from the raw BIOS bin files.

`python3 ./run.py` for running Efidrill on all modules.

## Check result

If everything is done, you can find the result in your workspace folder.


### Credit

Xuxiang Yang, Security researcher @ Security Lab GIC Lenovo

Qingzhe Jiang, Security researcher, Manager, @ Security Lab GIC Lenovo

### Thanks

Zhaoxing Sun helps to do some tests.

Xiaomin Li helps to create the project logo.