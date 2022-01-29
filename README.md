# Memory-Forensic-with-Volatility
Memory Forensic with Volatility for Malware Analysis

Accurated list of Volatility commands for memory forensic 

Image Identification
For a high level summary of the memory sample you’re analyzing, use the imageinfo command. Most often this command is used to identify the operating system, service pack, and hardware architecture (32 or 64 bit), but it also contains other useful information such as the DTB address and time the sample was collected.The imageinfo output tells you the suggested profile that you should pass as the parameter to --profile=PROFILE when using other plugins.

vol.py -f test.vmem|test.raw imageinfo

KDBGSCAN
The KDBG is a structure maintained by the Windows kernel for debugging purposes. It contains a list of the running processes and loaded kernel modules. It also contains some version information that allows you to determine if a memory dump came from a Windows XP system versus Windows 7, what Service Pack was installed, and the memory model (32-bit vs 64-bit).
Sometimes in process analysis by volatility pslist command doesn't show any output. The pslist plugin relies on finding the process list head which is pointed to by KDBG. However, the plugin takes the first KDBG found in the memory sample, which is not always the best one.You may run into this problem if a KDBG with an invalid PsActiveProcessHead pointer is found earlier in a sample (i.e. at a lower physical offset) than the valid KDBG. In order to "fix" pslist in these cases, you would simply need to supply the (--kdbg=address of Offset (V) in kdbgscan command output) to the plist plugin.

vol.py -f test.vmem|test.raw kdbgscan

KPCRSCAN
This plug-in is used to scan for KPCR (Kernel Processor Control Region) structures. A KPCR is a data structure used by the kernel to store the processor-specific data. Kpcrscan searches for and dumps potential KPCR values. Each processor on a multi-core system has its own KPCR. 
vol.py -f test.vmem kpcrscan

_EPROCESS, Process Environment Block,ActiveProcessLinks
Each Windows process is represented by an executive process structure called _EPROCESS. EPROCESS contains many attributes related to process and it also points to a number of other related data structures.Process Environment Block (PEB) is one of the structures that EPROCESS points to. PEB contains many process-related information like image name, loaded modules(dlls), image file path, command line parameters passed with the process etc.
One of the fields in EPROCESS data structure is ActiveProcessLinks which is a pointer to a CIRCULAR DOUBLY LINK LIST that tracks all active processes. The modules like pslist picks up this point and traverse through this series of pointers to get the list of the active processes.


