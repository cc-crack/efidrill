# Efidrill ——Automated Hunting UEFI Firmware Vulnerability through Data-Flow Analysis

Xuxiang Yang, Security researcher @ Security Lab GIC Lenovo

Qingzhe Jiang, Security researcher, Manager, @ Security Lab GIC Lenovo

July 2023

## Abstract 摘要

This white paper is intended as a support and reference for the Black Hat EU 2023 presentation "Efidrill - Automated
Hunting UEFI Firmware Vulnerability through Data-Flow Analysis". The speech and this article revolved around our newly
developed automated UEFI firmware vulnerability mining tool EFIDrill, introduced the limitations of existing open source
tools and how EFIDrill extended better detection capabilities based on existing open source projects, including real
0day Vulnerability analysis and implementation details of EFIDrill.

本白皮书旨在作为 Black Hat EU 2023 演讲“Efidrill ——Automated Hunting UEFI Firmware Vulnerability through Data-Flow
Analysis”的支持与参考。
演讲和本文围绕我们新开发的自动化UEFI固件漏洞挖掘工具EFIDrill，介绍了已有开源工具的局限性以及EFIDrill如何在已有开源项目的基础上扩展了更好的检测能力，其中包含了真实的0day漏洞分析和EFIDrill的实现细节。

## Content Primer

在过去的几年中，随着针对UEFI的安全研究不断进行，安全研究者发现了许多SMM漏洞，这也进一步提升了UEFI的安全性，诸如efiexplorer等工具的问世，也极大的简化了UEFI固件的逆向成本。

通过Binarly-IO的安全公告结果可以看到，大部分的漏洞都存在于SMM模块和DEX模块中，而且中高危漏洞最多的更是集中在SMM模块中。

<div align="center">
<img src=./pics/bio-adv.png width=80%>
</div>

系统管理模式（System Management
mode）（以下简称SMM）是Intel引入x86体系结构的一种CPU的执行模式。系统管理模式只能通过系统管理中断进入，并只能通过执行RSM指令退出。SMM模式对操作系统透明，被称为ring-2。如果恶意攻击者能够拿到SMM的控制权，那么恶意攻击者就可以绕过secure
boot，获取bitlocker密钥，或者种植一个操作系统无法感知的rootkit。

SMM存在许多攻击面，经过我们的整理，我们确认了系统启动以后的攻击面如下：

- CommBuffer：可以携带外部数据，然后通过对应的GUID，可以在child smi中被使用
- SMI请求的port和data
- 0x40E：SMM外部地址同样会在兼容legacy的时候被SMM使用，即使它可能并不安全
- Getvariable:变量获取的数据可能在启动阶段或者Setvariable等函数修改，它同样是不安全的
- Runtime Service接口，它们本身被存储在SMM外部，在SMM中调用这个接口将触发call out
- ReadSaveState：SMM的ReadSaveState请求能够获取调用时的寄存器信息，然而这个寄存器的值本身并不一定可信

通过上述的接口，SMM外的代码可以将数据传入SMM中，当SMM代码不正确的处理这些数据时便会存在漏洞。

TODO: 再补充点基础信息

## Motivations

我们对UEFI BIOS安全漏洞的研究开始于2022年初，通过一年的研究我们熟悉了大部分常见的UEFI漏洞。
2022年11月左右，我们跟踪到Intel发布的一个安全公告intel-sa-00688，其中引用的CVE-2022-21198是一个7.9分的高危漏洞。安全公告里并没有太多细节，只是提到它是一个TOCTOU的漏洞。
这个漏洞让我们产生了很大兴趣，因此我们通过逆向分析找到了相关的模块--`SpiSmmStub`。
并定位到了漏洞点。

<div align="center">
<img src=./pics/CVE-2022-21198_0.png width=80%>
</div>
<div align="center">
<img src=./pics/CVE-2022-21198_1.png width=80%>
</div>

可以看到上面的`if`语句中的检查使用了攻击者可控的指针，这导致最后的`copymem`调用中目的地址和长度都可以被攻击者控制。
当SMI调用产生时，攻击者通过DMA attack可以很容易利用这个漏洞。（因为SMI call中含有io操作，这是非常棒的DMA attack窗口）。
回顾这个漏洞，我们发现如果可以对SMI handler做数据流分析，这类问题应该可以准确的被识别出来。

而随着研究的深入，我们发现许多UEFI漏洞位于很深层次的位置，中间经过了复杂的参数传递和数据交换。现有的UEFI漏洞挖掘工具聚焦于Fuzz或者简单的匹配汇编指令，没有一个公开的工具可以能够基于数据流追踪分析的方法，自动化的检测发现UEFI中的安全漏洞。为此我们提出了首个公开的对UEFI固件进行数据流分析的开源
IDA 插件——EfiDrill。

我们开源了我们的工具EFIDrill，这个工具具备数据流追踪的功能，它可以对SMM外部数据进行污点追踪，结构体分析，漏洞识别，数值预测等。通过这个工具，我们在大约1个月的时间里发现了几十个UEFI固件的BUG，并且其中的十多个被各家知名厂商作为漏洞接受。我们在此完全开源我们的工具，并且我们将我们的工具做成一个IDA插件，以便您可以方便的使用它。

## UEFI静态分析技术现状

#### 1 静态分析概述

静态漏洞挖掘技术指在不运行目标程序的前提下对目标程序进行分析，这里又可以分为针对源码以及针对二进制程序进行分析其词法、语法、语义等，并通过相关工具获得其AST,
CFG, DDG, PDG, CPG等进行辅助分析固件的执行逻辑，来进行漏洞挖掘。

#### 2 静态分析技术在UEFI固件分析中的应用

通过静态分析技术，我们可以在没有设备和调试能力的情况下发现UEFI安全问题，并且静态分析可以帮助我们更好的理解代码的逻辑，许多在模糊测试下难以触发的代码逻辑，可以通过静态分析技术发现。现在公开的UEFI静态分析工具例如IDA,UEFI
Tool大多关注于对于固件符号的恢复，这很大程度上的降低了人工审计的的难度，而另一方面例如efiXloader等工具通过匹配Double
Getvariable，runtime serice调用等行为进行自动化静态漏洞挖掘，可以更好的大规模发现UEFI固件中的漏洞。

#### 3 UEFI固件静态分析挑战

我们研究了目前公开的UEFI漏洞挖掘工具，这方面的工具相对较少，所以我们列出了所有我们能够找到的工具

EfiXplorer:首款UEFI自动化静态分析工具，可以进行double Getvariable，runtime call
out等漏洞的挖掘，同时它能够帮助在IDA中识别出一些GUID，以帮助我们能够更好的进行逆向工程

Efi_fuzz:首个模拟执行UEFI固件的fuzz工具，可以通过fuzz找到内存破坏类的漏洞

chipsec：Intel推出的UEFI固件检测模块，可以支持真机SMI fuzz，配置安全检测等

通过这些强大的工具已经发现了许多UEFI漏洞，为UEFI产品的安全性做出了贡献，但是针对UEFI的复杂漏洞，这些工具都会遇到较大的瓶颈。我们希望引入数据流分析等成熟的漏洞挖掘方法，帮助挖掘一些复杂深层漏洞，这促使了我们新的漏洞挖掘工具的诞生。

## 工具设计与实现

### 工具概述

我们开源了我们的工具EFIDrill，它具备如下功能：

- 数据流分析功能
- 变量数值预测功能
- 自动化漏洞挖掘插件
- 自动化结构体类型预测

通过这个工具，我们在大约1个月的时间里发现了几十个UEFI固件的BUG，并且其中的十多个被各家知名厂商作为漏洞接受。我们在此完全开源我们的工具，并且我们将我们的工具做成一个IDA插件，以便您可以方便的使用它。

### 架构概述

我们的调度，分析，漏洞挖掘三个大功能将我们的工具分成如下几个部分：

- 管理调度层，该层包含了所有的待分析函数列表和分析插件控制
- 数据流分析层，该层用于处理具体分析工作，它将处理具体的每条分析工作，进行变量数值预测和数据流关系的保存
- 检测插件层，该层会分析当前函数中是否存在对应规则的问题

(架构图没画好)

### 分析引擎构建

#### 1 通过可达定义分析算法构建数据和路径的use-def链条

作为我们工作的第一步，我们需要先将我们的固件进行逆向，并且将逆向生成的汇编代码转换成为ir语言，接着我们通过可达定义分析构建数据的use-def集合和进行地址可达性分析。我们通过如下步骤完成上述工作：

- 我们首先将二进制程序的汇编代码以函数为单位抽象出了IR语言

- 接着针对每一个函数，我们通过使用可达定义分析算法构建出当前函数在每一个地址上的use-def变量

- 通过将地址作为def变量并进行可达定义分析，我们可以找到两个地址之间是否存在可达路径

- 同时为了能够分析函数间的变量传递关系，当我们遇到函数调用时，我们将函数作为代码块，进行use-def分析。

#### 2 通过上下文分析和别名分析构造数据流追踪模块

接着我们需要通过上下文分析和别名分析来对SMM外部可控的变量进行标注，我们通过如下步骤完成上述工作：

- 查找指定函数中SMM外部可控的初始变量作为我们追踪列表中最开始的部分。

- 通过分析上下文生找到use-def变量的传递数据流关系。

- 通过别名分析算法，我们将部分变量识别成另一个变量的别名。

- 我们将不断地添加新的变量到我们SMM外部可控变量的列表中

（数据流追踪图没画好）

#### 3 初始SMM外部可控变量标注

为了能够更加全面的发现UEFI固件漏洞，我们总结了我们能找到的所有可能的来源于SMM外部的攻击面，我们将按照前文所述将所有这些SMM外不可控的攻击面所对应的变量作为我们的初始变量。这些攻击面如下所示：

- CommBuffer and CommBufferSize

- ReadSaveState

- 0xc0000以下的绝对跳转

- gRT和gBS

- Getvariable的Datasize和Data

- 父函数传递进来的参数

#### 4 变量数值预测模块

为了能够进一步的提高分析的准确性，我们还提供了简单的数值预测功能，通过对特定语法的解析，我们可以预测一个变量在某个分支上可能的数值，通过这种方法，我们可以判断诸如MemCopy和SmmBufferValidation，callout等调用发生时，变量是否必须等于有限约束的范围内的数据，从而发现脆弱性代码。

（数值预测图没画好）

### 检测插件

#### 漏洞检测插件

利用前文的数据流追踪分析方法，开发了TOC-TOU、SMMOOB等7个插件，可用于检测UEFI中对应的7种类型脆弱性。

##### 1 callout检测

目前已有的检测方法，均为判断call中是否包含gRT与gBS，然而将诸如0x40E地址，CommBuffer，ReadSaveState返回，Getvariable返回当作函数调用参数地址的行为同样会导致CallOut发生，我们可以通过判断跳转发生时，其中包含的参数变量是否为SMM外部可控来找到这种漏洞。

<div align="center">
<img src=./pics/callout.png width=80%>
</div>

##### 2 Get variable溢出检测

目前已有的检测方法，通过判断datasize是否进行初始化或者是否存在double
Getvariable来判断是否存在漏洞，然而，通过SMM外部可控数据传递进来的datasize同样会造成变量长度不可控，从而导致缓冲区溢出。我们同样通过判断datasize参数是否为SMM外部传递进来的可控数据流来判断是否存在漏洞。

##### 3 SMM OOB检测

SMRAM OOB是一种常见的安全问题，开发者往往可以通过SmmBufferValidation 或者
amiSmmBufferValidation来进行检测，从而避免这种安全问题。我们的脚本会找到可能的SmmBufferValidation函数，然后通过查看长度参数的是否存在数值约束范围来判断是否对某一个输入数据的指定长度进行检测。当我们发现了一个SMM外部输入数据的指定偏移被使用时，我们会判断在所有可达路径上记录的SmmBufferValidation检测长度是否小于当前偏移来找到这种漏洞。

<div align="center">
<img src=./pics/oob.png width=80%>
</div>

##### 4 TOCTOU (CWE-367)检测

不成熟的开发者常常认为写了一些条件判断输入就万无一失了，然而这种的检测不是总能奏效的。不严谨的检查可以通过构造竞争条件被绕过，比如在10年前的杀毒软件的驱动中可能很容易找到类似这样的代码

```C

UNICODE_STRING filename = Irp->AssociatedIrp.SystemBuffer; // filename.Buffer is pointed to an user controlled address.
if(is_malicious(filename)){
    block();
    alert();
}else{
    pass();
}

```

而常见的操作是杀毒软件在ring3的hook中通过一个ioctl传递一个文件名并通知kernel模块做一些检查，如果这时候我们开启另一个线程对`filename.Buffer`
指向的内存进行修改这样就完成了竞争条件的构造，当`if(is_malicious(filename))`执行之前，攻击者将`filename.Buffer`
修改为一个合法的文件路径就可以避开检查了，这是TOCTOU的经典场景。

而在UEFI世界中TOCTOU漏洞也仍然存在，比如当SMI被触发时，虽然CPU被独占，但是很多外部设备比如显卡、硬盘、thunderbolt
devcie等等仍然可以通过DMA方式访问内存，这样攻击者完全可以利用外设的这一特性在SMI调用时构造出竞争条件，虽然DMA不能直接读写SMM
RAM但是SMI调用的参数地址仍然是有可能访问的。

在批量的测试中我们发现了很多模块的SMI
handler都存在TOCTOU这种问题，因此Efidrill中专门实现了一个插件用于toctou漏洞的检测，通过判断一个SMM外部输入数据被当作指针时，指定偏移所对应的内存是否被多次使用来找到这种漏洞。

<div align="center">
<img src=./pics/toctou.png width=80%>
</div>

##### 5 MEMCOPY溢出检测

不止Getvarable会导致溢出，当一个SMM外部可控数据被拷贝时同样会发生溢出。我们通过和检测SMM
OOB漏洞类似的方法来检测这种漏洞，当我们发现拷贝长度来自外部可控数据时，我们会认为这种漏洞发生。

##### 6 脆弱性检测：间接调用参数为外部输入检测

部分代码中存在将一个SMM外部的数据作为间接调用的参数来使用，然而由于这种间接调用的函数处理者不一定能够意识到这个输入源自于SMM外部的不可信数据，从而导致可能的问题，在这种情况中，我们同样在间接调用发生时，判断其参数的变量是否是SMM外部数据可控的，来找到这种风险。

<div align="center">
<img src=./pics/incall1.png width=80%>
</div>

<div align="center">
<img src=./pics/incall2.png width=80%>
</div>

##### 7 脆弱性检测：SMM外部数据存入全局变量检测

部分代码中存在将一个SMM外部的数据传入SMM的全局变量中来留作之后使用，然而，将一个指针传入全局变量可能导致风险，因为开发者在使用这种全局变量时并不总能意识到这个指针是不可信的，我们通过判断一个可控指针（数据）是否传入全局变量来识别可能的风险。


<div align="center">
<img src=./pics/global.png width=80%>
</div>

#### 漏洞检测插件大规模测试

为了能够减少人力研究的成本，我们提供了大规模自动化测试脚本，我们的脚本可以提供如下功能

- 批量拉去并解包UEFI固件
- 拉起IDA并执行我们的插件
- 以哈希作为标签将插件结果保存在预设的Work Space的不同子目录中

#### 用户界面与漏洞检测报告生成

我们提供了两种不同的报告生成方式，首先可以在ida中看到针对不同插件生成的统一风格的弹窗，双击弹窗中的问题列表，可以跳转到问题代码。同时我们也支持将数据导出到报告中，以便进行进一步的自动化开发。

<div align="center">
<img src=./pics/ida_demo.png width=80%>
</div>

### 结构体类型自动化分析功能

对于Fuzz或者逆向我们往往需要知道SMM外部输入数据的结构体类型，从而理解一个SMM外部输入数据被怎样使用，以及是否存在问题。当一个内存被使用时，它会包含如下属性。

- 使用的寄存器
- 使用的偏移
- 取址符

我们记录下这个寄存器作为基地址所使用的数值偏移，且记录下这个偏移被使用时所定义的新的可达定义变量，这样我们就可以形成一个由可达定义的变量所形成的多叉树。如果列表中的一个可达定义变量被当作一个指针使用时（也就是说它父节点的的指定偏移里面的数据被当作了基地址），那么我们就可以判断这个可达定义变量是一个指针类型，存储了这个节点的父节点中对应的偏移就会被当作一个存储指针的变量类型。

同时为了应对联合问题，我们会记录一个节点对应的可达地址范围，通过这个来判断它是不是同一个路径分支下的同类型变量，以描述一个输入可能的多个结构类型。

当进行模糊测试时，这些自动重建的结构体类型可以用于更好的发生种子生成。

(类型图没画好)

### 扩展检测插件

为了能够方便以后修改和扩展我们的插件，我们留下了若干个回调和类来用作扩展。

我们提供了函数处理回调来解决外部调用通过继承User_Function_Define并实现如下函数，您可以处理和修复外部调用的函数和初始化变量逻辑

- function_call_fix
- user_def_check

同时也可以添加新的检测插件，我们的工具通过在添加use-def变量到追踪列，处理每一句代码，函数调用发生时，所有函数分析结束时分别调用不同的回调来供扩展

- add_interesting_memory_map_list
- vulnerability_find
- copy_use_var
- finish_work

(接口图没画好)

## Vulerabilities 成果

我们找到了许多此前未被发现的未公开漏洞，它们中的一部分甚至来自于UEFI固件供应商，所以有理由相信，它们广泛的存在于各种不同厂商的固件中。

- Vulnerability in DELL T7920
- Vulnerability in DELL T7920
- Vulnerability in DELL T7910
- OOB Vulnerability in ASUS D900MD
- OOB Vulnerability in ASUS D900MD
- INTEL-W54FWSHJ
- INTEL-8T9BT8MW
- INTEL-G4O15ERY
- INTEL-T0WK2MUJ
- INTEL-EUCZ5F1V

除此之外我们还发现了一些供应链的问题，这些问题可能曾经在其他平台上被发现过，或者在当前平台上已经修补过，但是仍然存在使用旧版本的固件，已知但未修复，修复但有问题的情况，导致安全问题仍然存在。这些旧版本的固件可能是非供应商编译的，所以通过哈希特征匹配同样很难发现他们

- INTEL-6AYUD87U
- INTEL-VAJCIV59
- CVE-2021-33164（ASUS）

## References

[Binarly Advisories https://www.binarly.io/advisories](https://www.binarly.io/advisories)

[Binarly Blog https://www.binarly.io/advisories](https://www.binarly.io/posts)

[CVE-2022-21198](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00688.html)

[The Memory Sinkhole](https://www.blackhat.com/docs/us-15/materials/us-15-Domas-The-Memory-Sinkhole-Unleashing-An-x86-Design-Flaw-Allowing-Universal-Privilege-Escalation.pdf)
BlackHat USA 2015

efi_fuzz(https://www.blackhat.com/eu-20/arsenal/schedule/index.html#efi_fuzz-groundwork-to-the-metaphysics-of-coverage-guided-uefi-fuzzing-21777)
对
EFIDrill中集成了[efiXplorer](https://github.com/binarly-io/efiXplorer)用于获取guids