# Efidrill ——Automated Hunting UEFI Firmware Vulnerability through Data-Flow Analysis

UEFI一直是电脑启动的早期阶段，针对UEFI的攻击可以破坏电脑启动的Secure Boot机制，从而插入UEFI Rootkit。由于这类Rootkit存在于SMM或者BootLoader中，因此可以长期隐秘的控制受害者的电脑。

在过去的几年中，随着针对UEFI的安全研究不断进行，安全研究者发现了许多SMM漏洞，这也进一步提升了UEFI的安全性，诸如efiexplorer等工具的问世，也极大的简化了UEFI固件的逆向成本。

然而，这就足够了吗？答案是否定的。

许多UEFI漏洞隐藏的十分深入，现有的UEFI漏洞挖掘工具聚焦于Fuzz或者简单的匹配汇编指令，没有一个公开的工具可以能够基于数据流追踪分析的方法，自动化的检测发现UEFI中的安全漏洞。

Efidrill - 首个对UEFI固件进行数据流分析的开源 IDA 插件。

所提供的 IDA 插件通过数据流追踪，具备对UEFI固件进行污点追踪，结构体自动化分析，变量数值预测，自动化漏洞识别等功能。并在来自常见供应商（如华硕、因特尔、戴尔、惠普等）的硬件平台中发现了多个以前未报告的漏洞。
