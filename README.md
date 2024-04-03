[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0)

<div align="center">
<img src=./icon/logo.png width=30% alt="EFIDrill Logo">
</div>

**EFIDrill** - IDA plugin for UEFI firmware vulnerability hunting base on data flow analysis

**Supported versions of IDA:** Well tested on [IDA pro](https://hex-rays.com/ida-pro/) 8.2 and 8.3

**Supported Platforms:** Windows, Linux and OS X

## Plugin installation

### Linux / OS X

1. `git clone https://github.com/cc-crack/efidrill.git`
2. `ln -s <EFIDRILL_PATH>/efidrill.py <IDA_DIR>/plugins`
3. `ln -s <EFIDRILL_PATH>/efidrill <IDA_DIR>/plugins`

### Windows

1. `git clone https://github.com/cc-crack/efidrill.git`
2. `mklink <IDA_DIR>\plugins\efidrill.py <EFIDRILL_PATH>\efidrill.py`
3. `mklink <IDA_DIR>\plugins\efidrill <EFIDRILL_PATH>\efidrill`

## Configuration

Configurations of EFIDrill
are in [config.json](efidrill/config.json.template),
you can modify it to fit your needs.

It locates in the same directory as the plugin.

### Template

We provide a template for you to modify:

```json
{
  "deep_size": 15,
  "max_function_deep": 5,
  "workdir": "~/efidrill_workspace/",
  "logging_path": "efi_digging.log",
  "just_data_taint": 1,
  "debug_flag": 0,
  "to_ui": 1,
  "res_filename": "res.json"
}
```

### Configuration items

- `deep_size`: The maximum number of instructions to be analyzed in a function.
- `max_function_deep`: The maximum recursive depth of functions to be analyzed.
- `workdir`: The directory where the analysis results and artifacts are stored.
- `logging_path`: The path of the log file.
- `just_data_taint`: Whether to perform only data taint analysis.
- `debug_flag`: Whether to enable debug mode.
- `to_ui`: Whether to output the analysis results to the UI of IDA Pro.
- `res_filename`: The name of the analysis result file.

## Directory structure

```text
|   check_engine.py #Loaded with all plug-ins and initializes function classes
|   config.json.template
|   config.py
|   debug.py
|   function_support.py
|   function_var.py
|   logging.py
|   plugin_mgr.py
|   rd_analysis.py  #Main program
|   result.py
|   test.py
|   user_define_work.py
|   __init__.py
|
+---arch
|       x64.py
|
+---function_type   #processing classes for different functions
|       child_smi.py
|       find_entry_point.py
|       function_ana_loader.py
|       function_type.py    #SMRAM external input data is initialized here
|       sub_function.py
|       sw_smi.py
|
+---ida_work
|       ida_support.py  #Encapsulation of the IDA library
|
+---mdis    #library that reaching definition analysis and encapsulates miasm
|       mdis_engine.py  #Generate use def engine
|       mdis_support.py #Encapsulate files processed by IR
|       ReachingDefinitionscfg.py
|       ReachingDefinitionsvar.py
|
\---plugin  #All analysis plug-ins
        base_plugin.py
        callout.py
        datasize.py
        global_var.py
        indirect_call.py
        memcopy.py
        smmvaild.py
        struct_build.py
        toctou.py
```

## Important structures

* `Function_type.interesting_op_list`: Store all the content of interest `def_var` (toctou only has a -1 element
  description, the current variable does not analyze toctou).
* `Function_type.all_uses`, `Function_type.all_defs`: Store all use def `{address:define}`.
* `Function_type.current_ins_addr`: The `address` of the current analysis.
* `Function_type.ircfg`: Current `IR`.
* `Function_type.mmap_ir_address`: Mapping of IR addresses and addresses: `(block_index,assm_index), address`.
* `variable`: `{miasm_struct,address}`.
* `Variables in miasm`: `{miasm_struct,(block_index,assm_index)}`.
* [`miasm structure`:](https://miasm.re/miasm_doxygen/classmiasm_1_1expression_1_1expression_1_1_expr_mem.html) Stores
  various `OP`, `ID` (registers), `int`, `MEM`.

## Implement a custom plugin

1. Inherit the Base_Plugin class in the [base_plugin.py](efidrill/plugin/base_plugin.py) file.
2. The [add_interesting_memory_map_list](efidrill/plugin/base_plugin.py) function is called when a new def is added to the list of interesting variables,
   and use_list is the use_list of interest when calling the def, is_alias indicates whether this variable is an alias
   for another variable.
3. [vulnerability_find](efidrill/plugin/base_plugin.py) is executed at each address, use_list is all the variables of interest used by that address, and
   def_list is all variables defined by that address.
   > Note that since one def var corresponds to multiple use vars, variable assignment requires a list mapping of def
   var to use list.

## Reaching definition(RD) problem

Note that the toctou and struct plugins do not have RD issues, so there is a path explosion (his stack depth does not
exceed the maximum limit), and the other plugins have RD issues, so there is no path explosion problem.

## Important functions

* `mmap_ir_to_address`: map intermediate representation (IR) addresses to actual addresses in a binary file.
* `check_interesting_variables`: Find the variables of interest (0x40e,readsavesatate, commbuffer), different functions
  have different variables of interest.
* `ana_ins_addr`: Analyze each assembly instruction.
* `add_interesting_memory_map_list`: Add new define to the interesting_op_list.
* `vulnerability_find`: Call all plug-ins.
* `fix_use`: Find the far jump use(def is not in the current function), the address of the far jump block ir is (-1,-1),
  and the actual address is -1.
* `get_def`: generate def.

## TODO list

* UEFI Firmware Library and Automated Analysis
* Cross Architecture(ARM,MIPS,...)
* Variable Value Prediction Improve
* Writing a Fuzz Module

## Can Do List

* datasize handling stack aliasing issues
* Incomplete judgment of heuristic expression jump

## Incomplete hypothesis at present

* The safest assumption for SMRAM out-of-bounds access: a function takes rcx as external input and we assume that it is
  called, whether it is actual or not (_possibly false positives_).
* The external data address assumes that as long as a data comes from outside, we do not consider the memory location
  and SMM location in our PC (_possibly false positives_).

## Running test

`cd ./test`

`python3 ./generate.py` for extracting all modules from the raw BIOS bin files.

`python3 ./run.py` for running Efidrill on all modules.

## Check result

If everything is done, you can find the result in your workspace folder.

## Credit

Xuxiang Yang, Security researcher @ Security Lab GIC Lenovo

Qingzhe Jiang, Security researcher, Manager, @ Security Lab GIC Lenovo

Weixiao Ji, Security researcher @ Security Lab GIC Lenovo

## Thanks

Zhaoxing Sun helps to do some tests.

Xiaomin Li helps to create the project logo.