# Memory-Forensic-with-Volatility
Memory Forensic with Volatility for Malware Analysis

Accurated list of Volatility commands for memory forensic 

Image Identification
For a high level summary of the memory sample you’re analyzing, use the imageinfo command. Most often this command is used to identify the operating system, service pack, and hardware architecture (32 or 64 bit), but it also contains other useful information such as the DTB address and time the sample was collected.The imageinfo output tells you the suggested profile that you should pass as the parameter to --profile=PROFILE when using other plugins.

vol.py -f memdump.vmem imageinfo

KDBGSCAN
The KDBG is a structure maintained by the Windows kernel for debugging purposes. It contains a list of the running processes and loaded kernel modules. It also contains some version information that allows you to determine if a memory dump came from a Windows XP system versus Windows 7, what Service Pack was installed, and the memory model (32-bit vs 64-bit).
Sometimes in process analysis by volatility pslist command doesn't show any output. The pslist plugin relies on finding the process list head which is pointed to by KDBG. However, the plugin takes the first KDBG found in the memory sample, which is not always the best one.You may run into this problem if a KDBG with an invalid PsActiveProcessHead pointer is found earlier in a sample (i.e. at a lower physical offset) than the valid KDBG. In order to "fix" pslist in these cases, you would simply need to supply the (--kdbg=address of Offset (V) in kdbgscan command output) to the plist plugin.

vol.py -f memdump.vmem kdbgscan

KPCRSCAN
This plug-in is used to scan for KPCR (Kernel Processor Control Region) structures. A KPCR is a data structure used by the kernel to store the processor-specific data. Kpcrscan searches for and dumps potential KPCR values. Each processor on a multi-core system has its own KPCR. 
vol.py -f test.vmem kpcrscan

_EPROCESS, Process Environment Block,ActiveProcessLinks
Each Windows process is represented by an executive process structure called _EPROCESS. EPROCESS contains many attributes related to process and it also points to a number of other related data structures.Process Environment Block (PEB) is one of the structures that EPROCESS points to. PEB contains many process-related information like image name, loaded modules(dlls), image file path, command line parameters passed with the process etc.
One of the fields in EPROCESS data structure is ActiveProcessLinks which is a pointer to a CIRCULAR DOUBLY LINK LIST that tracks all active processes. The modules like pslist picks up this point and traverse through this series of pointers to get the list of the active processes. also  this is used by tools such as Windows Task Manager and tasklist to display the running processes to the system. 

Process Environment Block(PEB)
Process Environment Block (PEB) is one of the structures that EPROCESS points to. PEB contains many process-related information like image name, loaded modules(dlls), image file path, command line parameters passed with the process etc.

ActiveProcessLinks
Kernel uses doubly link list to track the processes. Each Process has this doubly link list which is pointed by ActiveProcessLinks field of the previous process. All EPROCESS blocks are connected in a circular way by DoublyLinkList. Hence, by traversing this list we can get all the active processes on the system.
ActiveProcessLinks is a LIST_ENTRY structure and it is a circular doubly link list pointing to the node in the next EPROCESS for a different process.
 A forward pointer from one process' EPROCESS structure points to the next process' EPROCESS structure; a backward pointer specifies the address of the previous process' EPROCESS structure. And, this doubly linked list of EPROCESS structure is pointed by PsActiveProcessHead
 
Unlinked processes
malicious process can remove EPROCESS block from this list,while continuing to run. This list is not used by the kernel scheduler to actually change context and execute the process.Therefore, one method used by rootkits to hide processes is simply to unlink the process from the active process list. Once unlinked , rootkit nicely hides the process from most standard process enumeration tools.
Unlinked process continues to run normally even after the modification to the list, because scheduling in the Windows kernel is based on threads, not processes.Manipulating kernel structures in memory to hide the process is called as Direct Kernel Object Manipulation (DKOM). This can be done by loading a malicious driver which will full access to kernel objects or with API function called ZWSystemDebugControl.

Pslist
Get all the active process by traversing through the doubly link lists.
Method 1:!PsActiveProcessHead is the pointer to the doubly linked list (ActiveProcessLinks) of the EPROCESS of the Process “System”, the first process. By getting a pointer to one of the nodes in the doubly linked list, we can traverse through all the active processes connected via doubly linked list.
Method 2: Another way to traverse through the process list is to pick one process and identify its pointer to the circular doubly linked list and traverse through the list.

vol.py --profile=testProfile -f memdump.mem pslist

Psscan
The psscan module doesn't trust the linked list of the processes, and, instead, searches memory by heuristically looking for EPROCESS structure that represent processes.Hence, it lists all processes that are even hidden by rootkit and not shown by pslist command of volatility or tasklist command of windows. Any discrepancy between process list shown by pslist and psscan suggests that rootkit is installed. also this command shows processes that have been terminated.
vol.py --profile=memdumpProfile -f memdump.mem psscan

psxview
This plugin is used to give an overall picture of the process so that cross reference can be done for various aspects to discover malicious processes. The psxview plugin provides a detailed listing of which processes were running in the memory image and by which method they were found. psxview plugin supports these methods: pslist, psscan, thrdproc, pspcdid, csrss, session and deskthrd. 
thrdproc: It’s good to map with the threads for the process. Threads can be enumerated individually for _ETHREAD structure and can be mapped to processes from there.
PspCid: This is a special table in memory that stores reference for all active and threads objects. This table can be manipulated to remove any process, thread reference.
Csrss: Client-server Runtime subsystem plays a critical role in the creation of processes and threads. Note that this holds true only for a process created by itself.(system, smss.exe,csrss.exe)
Session and Desktop: Session will attach all the process to a particular user session, and desktop will find each thread attached to the desktop which can be mapped to its owning process.
In logical point of view process's activity Disturb if process has no effect in csrss, session and desktop tables. A hidden process, for example, would be a process that was invisible to not only the pslist plugin, but to most of the other aforementioned plugins, but which would have to be visible to at least one, in order to be detected. It's unlikely that a rootkit can sucsessfully hide from psxview. Realistically it's far easier to just inject code into a process that's not hidden than to hide a process seven different ways in a reliable(with no bug) andportable manner (works across all windows versions). 
Important note: if you supply the --apply-rules option, you might also see Okay in the columns witch indicates that although the process was not found, it meets one of the valid exceptions described in the following list: 
	• Processes that start before csrss.exe (including System, smss.exe and csrss.exe itself) are not in the CSRSS handle table.
  •	Processes that start before smss.exe (including   - System and smss.exe) are not in the session process or desktop thread lists.
  •	Processes that have exited will not be found by any of the methods except process object scanning and thread scanning (if an _EPROCESS or _ETHREAD still happens to be memory resident).
  Warning: After attackers gain access to kernel memory, they can manipulate anything they want. In this case, they could overwrite the _EPROCESS.ExitTime member to make it appear as if the process exited; thus the --apply-rules option would improperly report it as Okay. However, processes that have truly exited have zero threads and an invalid handle table—so you can always double-check what those fields contain
  






