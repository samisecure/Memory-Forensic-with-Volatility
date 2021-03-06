# Memory-Forensic-with-Volatility

## Accurated list of Volatility commands for memory forensic

## Image Identification
For a high level summary of the memory sample you’re analyzing, use the imageinfo command. Most often this command is used to identify the operating system, service pack, and hardware architecture (32 or 64 bit), but it also contains other useful information such as the DTB address and time the sample was collected.The imageinfo output tells you the suggested profile that you should pass as the parameter to --profile=PROFILE when using other plugins.

`vol.py -f memdump.vmem imageinfo`

## KDBGSCAN
The KDBG is a structure maintained by the Windows kernel for debugging purposes. It contains a list of the running processes and loaded kernel modules. It also contains some version information that allows you to determine if a memory dump came from a Windows XP system versus Windows 7, what Service Pack was installed, and the memory model (32-bit vs 64-bit).
Sometimes in process analysis by volatility pslist command doesn't show any output. The pslist plugin relies on finding the process list head which is pointed to by KDBG. However, the plugin takes the first KDBG found in the memory sample, which is not always the best one.You may run into this problem if a KDBG with an invalid PsActiveProcessHead pointer is found earlier in a sample (i.e. at a lower physical offset) than the valid KDBG. In order to "fix" pslist in these cases, you would simply need to supply the (--kdbg=address of Offset (V) in kdbgscan command output) to the plist plugin.

`vol.py -f memdump.vmem kdbgscan`

## KPCRSCAN
This plug-in is used to scan for KPCR (Kernel Processor Control Region) structures. A KPCR is a data structure used by the kernel to store the processor-specific data. Kpcrscan searches for and dumps potential KPCR values. Each processor on a multi-core system has its own KPCR. 
`vol.py -f test.vmem kpcrscan`


## VAD (Virtual Access Discriptor)
For each process, memory manager maintains a set of Virtual Address Descriptors (VADs) that describes the ranges of virtual memory address space reserved for that specific process. If any file is mapped in any of these memory regions, VAD node contains the full-path information for that file. This is really important information from the memory forensics perspective. If any dll or exe is mapped in one of these memory ranges then the VAD node (which is a Kernel structure) contains the full path on disk for that dll/exe. This information helps us in identifying any malicious activities like unlinking dll in the standard _PEB ldrmodules. The information is still available even if dll is unlinked from all 3 ldrmodules in _PEB (which is a user mode structure). VAD information can be used in revealing many attacks like dll injection, reflective code injection etc.

### Volatility VAD Plugins 

•	vadinfo: Displays the most verbose output, including the starting and ending addresses, the protection level, flags, and full paths to mapped files or DLLs.
•	vadtree: In text mode, this plugin prints a tree-view of the nodes, so you can see the parent and child relationships on your console. It also supports generating the color-coded graphs shown in 
![image](https://user-images.githubusercontent.com/41668480/151697883-0ab42c1c-97fb-4afc-a6fc-849f6c693e1d.png)
• vaddump: Extracts the range of process memory each VAD node describes to a separate file on disk. Unlike memmap (discussed earlier), the output from this plugin is padded with zeros if any pages in the range are swapped to disk to maintain spatial integrity (offsets).

###  Malfind
The malfind command helps find hidden or injected code/DLLs in user mode memory, based on characteristics such as VAD tag and page permissions.
Note: malfind does not detect DLLs injected into a process using CreateRemoteThread->LoadLibrary. DLLs injected with this technique are not hidden and thus you can view them with dlllist. The purpose of malfind is to locate DLLs that standard methods/tools do not see.
` vol.py -f memdump.vmem  malfind -p <PID> `
If you want to save extracted copies of the memory segments identified by malfind, just supply an output directory with -D or --dump-dir=DIR. 
https://imphash.medium.com/windows-process-internals-a-few-concepts-to-know-before-jumping-on-memory-forensics-part-4-16c47b89e826

___
## _EPROCESS, Process Environment Block,ActiveProcessLinks
### _EPROCESS
Each Windows process is represented by an executive process structure called ***_EPROCESS***. EPROCESS contains many attributes related to process and it also points to a number of other related data structures.***Process Environment Block (PEB)*** is one of the structures that EPROCESS points to. PEB contains many process-related information like image name, loaded modules(dlls), image file path, command line parameters passed with the process etc.
One of the fields in EPROCESS data structure is ***ActiveProcessLinks*** which is a pointer to a CIRCULAR DOUBLY LINK LIST that tracks all active processes. The modules like pslist picks up this point and traverse through this series of pointers to get the list of the active processes. also  this is used by tools such as Windows Task Manager and tasklist to display the running processes to the system. 

### EPROCESS and SID
 each _EPROCESS points to a list of security identifiers (SIDs) and privilege data. This is one of the primary ways the kernel enforces security and access control. 

### Process Environment Block(PEB)
Process Environment Block (PEB) is one of the structures that EPROCESS points to. PEB contains many process-related information like image name, loaded modules(dlls), image file path, command line parameters passed with the process etc.

### ActiveProcessLinks
Kernel uses doubly link list to track the processes. Each Process has this doubly link list which is pointed by ActiveProcessLinks field of the previous process. All EPROCESS blocks are connected in a circular way by DoublyLinkList. Hence, by traversing this list we can get all the active processes on the system.
ActiveProcessLinks is a LIST_ENTRY structure and it is a circular doubly link list pointing to the node in the next EPROCESS for a different process.
 A forward pointer from one process' EPROCESS structure points to the next process' EPROCESS structure; a backward pointer specifies the address of the previous process' EPROCESS structure. And, this doubly linked list of EPROCESS structure is pointed by PsActiveProcessHead
 
### Unlinked processes
malicious process can remove EPROCESS block from this list,while continuing to run. This list is not used by the kernel scheduler to actually change context and execute the process.Therefore, one method used by rootkits to hide processes is simply to unlink the process from the active process list. Once unlinked , rootkit nicely hides the process from most standard process enumeration tools.
Unlinked process continues to run normally even after the modification to the list, because scheduling in the Windows kernel is based on threads, not processes.Manipulating kernel structures in memory to hide the process is called as Direct Kernel Object Manipulation (DKOM). This can be done by loading a malicious driver which will full access to kernel objects or with API function called ZWSystemDebugControl.

___
## Pslist
Get all the active process by traversing through the doubly link lists.
Method 1:!PsActiveProcessHead is the pointer to the doubly linked list (ActiveProcessLinks) of the EPROCESS of the Process “System”, the first process. By getting a pointer to one of the nodes in the doubly linked list, we can traverse through all the active processes connected via doubly linked list.
Method 2: Another way to traverse through the process list is to pick one process and identify its pointer to the circular doubly linked list and traverse through the list.

![image](https://user-images.githubusercontent.com/41668480/151692590-35260ecf-a3bf-471c-8c85-8a304f302419.png)

`vol.py --profile=<profile> -f memdump.mem pslist`

By default, pslist shows virtual offsets for the _EPROCESS but the physical offset can be obtained with the -P switch:

` vol.py -f memdump.vmem --profile=<profile> pslist -P ` 

## Psscan
The psscan module doesn't trust the linked list of the processes, and, instead, searches memory by heuristically looking for EPROCESS structure that represent processes.Hence, it lists all processes that are even hidden by rootkit and not shown by pslist command of volatility or tasklist command of windows. Any discrepancy between process list shown by pslist and psscan suggests that rootkit is installed. also this command shows processes that have been terminated.
If you want to investigate a hidden process (such as displaying its DLLs), then you’ll need physical offset of the _EPROCESSobject, which is shown in the far left column. Almost all process-related plugins take a --OFFSET parameter so that you can work with hidden processes.

`vol.py --profile=<profile> -f memdump.mem psscan`

## psxview
This plugin is used to give an overall picture of the process so that cross reference can be done for various aspects to discover malicious processes. The psxview plugin provides a detailed listing of which processes were running in the memory image and by which method they were found. psxview plugin supports these methods: pslist, psscan, thrdproc, pspcdid, csrss, session and deskthrd. 
- thrdproc: It’s good to map with the threads for the process. Threads can be enumerated individually for _ETHREAD structure and can be mapped to processes from there.
- PspCid: This is a special table in memory that stores reference for all active and threads objects. This table can be manipulated to remove any process, thread reference.
- Csrss: Client-server Runtime subsystem plays a critical role in the creation of processes and threads. Note that this holds true only for a process created by itself.(system, smss.exe,csrss.exe)
- Session and Desktop: Session will attach all the process to a particular user session, and desktop will find each thread attached to the desktop which can be mapped to its owning process.


___
>  In logical point of view process's activity Disturb if process has no effect in csrss, session and desktop tables.
A hidden process, for example, would be a process that was invisible to not only the pslist plugin, but to most of the other aforementioned plugins, but which would have to be visible to at least one, in order to be detected. It's unlikely that a rootkit can sucsessfully hide from psxview. Realistically it's far easier to just inject code into a process that's not hidden than to hide a process seven different ways in a reliable(with no bug) andportable manner (works across all windows versions). 

___
> Important note: if you supply the --apply-rules option, you might also see Okay in the columns witch indicates that although the process was not found, it meets one of the valid exceptions described in the following list: 
  •     Processes that start before csrss.exe (including System, smss.exe and csrss.exe itself) are not in the CSRSS handle table.
  •	Processes that start before smss.exe (including   - System and smss.exe) are not in the session process or desktop thread lists.
  •	Processes that have exited will not be found by any of the methods except process object scanning and thread scanning (if an _EPROCESS or _ETHREAD still happens to be memory resident). 
 
 ___
> Warning: After attackers gain access to kernel memory, they can manipulate anything they want. In this case, they could overwrite the _EPROCESS.ExitTime member to make it appear as if the process exited; thus the --apply-rules option would improperly report it as Okay. However, processes that have truly exited have zero threads and an invalid handle table—so you can always double-check what those fields contain 

  
___
 > Differentiating the output between the pslist and psscan plugins
Highlighting the differences between the output from the pslist and psscan plugins, may not always be obvious. For this task, shell-based text processing is of significant use. By using the following commands, it will be possible to determine which
differences were found:

` $ cat psscan.txt | awk '{print $2"\t"$3"\t"$4"\t"$6"\t"$7}' | grep -v "\-\-\-\-\-\-\-\-\-\-" | grep -v PPID | sort > psscan.txt `
` $ cat pslist.txt | awk '{print $2"\t"$3"\t"$4"\t"$9"\t"$10}' | grep -v "\-\-\-\-\-\-\-\-\-\-" | grep -v PPID | sort > pslist_sorted.txt `
` $ diff psscan_sorted.txt pslist_sorted.txt > pslist_psscan_diff.txt ` 

___
## pstree
This plugin takes the output of pslist and actually present them in child-parent relationship. Very useful plugin when the process listing is huge within the memory to see any suspicious relationship between child-parent.
` vol.py pstree -p <profile> -f memdump.vmem -p process_id `

___
## Malprocfind
This is such a cool plugin.  It checks to see if any system processes are masquerading as legitimate ones.  It has 13 checks. It provide you a true or false for each check.  If the check is false it means it failed the check and you might need to look into this a bit further.  Again, there can still be false positives. In addition, it will show a count of unusual processes as well as processes with no parent process.  No process should ever grow up without a parent except in some cases such as the system service which does not have a parent process or processes that are spawned from an instance of the smss service or userinit that may have existed and it no longer present.  Wininit, csrss, winlogon and explorer are good examples of that.

The plugin will check for the following: 
- PID = The right parent process ID  
- Name = Process name is correct (not misspelled)  
- Path = Process path is correct 
- Priority = Right priority  
- Cmdline = Command line parameters are correct  
- User = Right user (SID)  
- Session/Time = Correct Session and time started (Most system processes run in session 0)  
- CMD = Was process spawned from the command line?  
- Phollow = Does the process show signs of process hollowing?  (Will discuss more later)  
- SPath = Looks for suspicious paths like temp directory 

` vol.py malprocfind -f memdump.vmem --profile=<profile> `
` vol.py malprocfind -x -f memdump.vmem --profile=<profile>  "-x includes closed processes" ` 
___
## malsysprocfind 
To check Legitimacy for LSASS and SVCHOST processes.  This plugin will also look for processes named similarly to svchost and lsass such as lssas or scvhost. List of items that this plugin checks:
- If  name of the process is actually what is expected.
- The process is running from the expected path. This check that the path matches the path of the native Windows process (C:\windows\system32\ for both lsass.exe and svchost.exe).
- It checks parent-child relationship. svchost.exe should always be a child of services.exe and lsass.exe should be the child of wininit.exe for systems running Vista or better, or winlogon.exe for systems running XP or older.
- It compares each system process' creation time to that of its parent, and if the system process was created more than 10 seconds after its parent it is flagged. 
- It compares the command line arguments of each system process to a list of expect arguments. 
` vol.py malsysproc -f memdump.vmem --profile=<profile> `

___
## Malconfscan
MalConfScan is a Volatility plugin extracts configuration data of known malware. This tool searches for malware in memory images and dumps configuration data. In addition, this tool has a function to list strings to which malicious code refers. MalConfScan has a function to list strings to which malicious code refers. Configuration data is usually encoded by malware. Malware writes decoded configuration data to memory, it may be in memory. This feature may list decoded configuration data.

Export known malware configuration
` python vol.py malconfscan -f images.mem --profile=Win7SP1x64 `

Export known malware configuration for Linux
` python vol.py linux_malconfscan -f images.mem --profile=LinuxDebianx64 `

List the referenced strings
` python vol.py malstrscan -f images.mem --profile=Win7SP1x64 `
Refrence: https://github.com/JPCERTCC/MalConfScan
___
## Thread
The threads plugin is useful as it has the ability to provide detailed information about processes and threads that have since terminated or that may be hidden.

` vol.py threads -f memdump.vmem -p process_id `

you can check if process is terminated by checking it's thread exit time.To find ETHREAD objects in physical memory with pool tag scanning, use the thrdscan command. Since an ETHREAD contains fields that identify its parent process, you can use this technique to find hidden processes. One such use case is documented in the psxview command. Also, for verbose details, try the threads plugin

`vol.py thrdscan -f memdump.vmem -p process_id `

### Threads in Kernel Mode
When kernel modules create new threads with PsCreateSystemThread, the System process (PID 4 on XP and later) becomes the owner of the thread. In other words, the System process is the default home for threads that start in kernel mode. When parsing through a memory dump, you can distinguish these system threads from others based on the following factors:

- The _ETHREAD.SystemThread value is 1.
- The _ETHREAD.CrossThreadFlags member has the PS_CROSS_THREAD_FLAGS_SYSTEM flag set.
- The owning process is PID 4.
This information can help you find malware families that attempt to hide their presence in the kernel. When the rootkit modules initially load, they allocate a pool of kernel memory, copy executable code to the pool, and call PsCreateSystemThread to begin executing the new code block. After the thread is created, the module can unload. These actions help the rootkit remain stealthy because it survives based on threads running from untagged pools of memory. 
### Detecting Orphan Threads 
The threads plugin can help you identify attempts to hide in the described manner. It enumerates loaded modules by walking the doubly linked list and records their base addresses and sizes. Then it scans for system threads and checks whether the _ETHREAD .StartAddress value is within the range of one of the modules. If the plugin cannot pair a thread with its owning driver, it assumes that the thread is detached or hidden. For this reason, the threads have also become known as orphan threads. You’ll see the OrphanThread tag displayed as well as an UNKNOWN to the right of the starting address.  keep in mind that the thread’s starting address will point at a function inside the malicious PE file, rather than at the PE file’s base address. Thus, you may need to do some calculation to find the MZ signature. 
`  python vol.py -f memdump.vmem threads -F OrphanThread     --profile=memdump_profile  ` 
> ### warning: ### 
> Rootkits can easily bypass the orphan thread detection technique by patching the _ETHREAD.StartAddress values to point at a known driver. In (http://www.virusbtn.com/pdf/conference_slides/2008/Kasslin-Florio-VB2008.pdf),  Kimmo Kasslin and Elia Floria noted that the third generation of Mebroot started applying these patches to increase its stealth.
___

## TokenImp
**Token and Token Impersonation** : An access token is an object that describes the security context of a process or a thread. The information inside a token includes the identity and privileges of the user account associated with the process or thread. Every process has a primary token that describes the security context of the user account associated with the process. Moreover, a thread can impersonate a client account. Impersonation allows the thread to interact with securable objects using the client's security context. A thread that is impersonating a client has both a primary token and an impersonation token. 
The most common tool that allows the impersonation of another user is a built-in tool called RunAs and allows you to run an application as other users if you know theirs credentials. Token impersonation is a technique used often by red teams and attackers in order to impersonate another user logged on in order to commit some tasks as a legitimate user, or to perform privilege escalation into SYSTEM account.An example for usage in the wild can be found in APT28, Azorult, Lazarus Group, Duqo and more

**User Account Control (UAC)**: Since Windows Vista, UAC became a part of Windows security features. It basically means that even
though an account is administrative, every application won’t run in administrative context until it will be
approved by the user itself or inherit the high context from the parent process. There are many techniques to bypass the UAC in the wild, examples can be found [here](https://attack.mitre.org/techniques/T1088/). 
A method worth mentioning is utilizing the fact that Microsoft's signed executables can run in high privileged context without the user’s permission and interaction when they use operations such as IFileOperation COM object. (Presented in [Cobalt Strike’s](https://www.cobaltstrike.com/) bypassuac command).

**TokenImp**: The plugin’s goal is to detect token impersonation attacks, and perhaps detect suspicious behavior that can lead to zero day attacks. TokenImp plugin comes in handy when you want to map administrative user’s UAC status or every other user’s session, detect token impersonation inside existing processes (i.e. ImpersonateLoggedOnUser,
SetThreadToken API) and new processes related to impersonation without explorer (i.e.CreateProcessWithTokenW API). The plugin supports all windows platforms from Windows vista and higher and tested on Windows 7,Windows 2012 and Windows 10.

**Detects only impersonation for active threads:**
` vol.py -f memdump.vmem --profile=<profile> tokenimp `

**Detects all malicious processes that created with impersonated token:**
` vol.py -f memdump.vmem --profile=<profile> tokenimp -c `

Refrence: https://github.com/kslgroup/TokenImp-Token_Impersonation_Detection

 ___
 
 ## SID
 You can map the SID string to a username by querying the registry. The following command shows an example of how to do this:
vol.py -f memory.img --profile=<profile> printkey -K "Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-4010035002-774237572-2085959976-1000" 
 
 ## Detecting Lateral Movement
 If you need to associate a process with a user account or investigate potential lateral movement attempts, use the getsids plugin. 
 
 `  vol.py –f memory.img --profile=<profile> getsids –p <PID>  `
 
 Maybe one SID doesn’t display an account name. On systems that don’t authenticate to a domain, you’ll see the local user’s name next to the SID. In this case, however, because Volatility doesn’t have access to the remote machine’s registry (that is, the domain controller or Active Directory server), it cannot perform the resolution. 

 ## Privilege
Privileges are another critical component involved in security and access control. A privilege is the permission to perform a specific task, such as debugging a process, shutting down the computer, changing the time zone, or loading a kernel driver. Before a process can enable a privilege, the privilege must be present in the process’ token. 
few ways to enable privileges: 
 - Enabled by default: The LSP can specify that privileges be enabled by default when a process starts.
 - 	Inheritance: Unless otherwise specified, child processes inherit the security context of their creator (parent).
 - 	Explicit enabling: A process can explicitly enable a privilege using the AdjustTokenPrivileges API
 
 ![image](https://user-images.githubusercontent.com/41668480/151694808-875af902-a374-4fd1-9410-b406a7877cdc.png)

 What	can	you	do	with	elevated	privileges:	
– Debug	programs	
– Take	ownership	of	objects	
– Modify	files	and	directories	
– Impersonate	a	client	aJer	authen2ca2on	
– Load	and	unload	device	drivers	
– Create	a	token	object	
– Act	as	part	of	the	opera2ng	system,	etc.
 https://downloads.volatilityfoundation.org//omfw/2012/OMFW2012_Gurkok.pdf
 
From a forensic perspective, you should be most concerned with the following privileges when they’ve been explicitly enabled:
 	- SeBackupPrivilege: This grants read access to any file on the file system, regardless of its specified access control list (ACL). Attackers can leverage this privilege to copy locked files.
 - 	SeDebugPrivilege: This grants the ability to read from or write to another process’ private memory space. It allows malware to bypass the security boundaries that typically isolate processes. Practically all malware that performs code injection from user mode relies on enabling this privilege.
 - 	SeLoadDriverPrivilege: This grants the ability to load or unload kernel drivers.
 - 	SeChangeNotifyPrivilege: This allows the caller to register a callback function that gets executed when specific files and directories change. Attackers can use this to determine immediately when one of their configuration or executable files are removed by antivirus or administrators.
 - 	SeShutdownPrivilege: This allows the caller to reboot or shut down the system. Some infections, such as those that modify the Master Boot Record (MBR) don’t activate until the next time the system boots. Thus, you’ll often see malware trying to manually speed up the procedure by invoking a reboot. 
 
 You can see a process privileges with its attributes (present, enabled, and/or enabled by default). and check if the process need to enable that privileges or not to detect malicious behavior.
 
 ` vol.py -f memdump.vmem.img privs -p <PID> `
 ___

## DLL
### Dlllis
To display a process’s loaded DLLs, use the dlllist command. It walks the doubly-linked list of _LDR_DATA_TABLE_ENTRY structures which is pointed to by the PEB's InLoadOrderModuleList. DLLs are automatically added to this list when a process calls LoadLibrary (or some derivative such as LdrLoadDll) and they aren't removed until FreeLibrary is called and the reference count reaches zero. The load count column tells you if a DLL was statically loaded (i.e. as a result of being in the exe or another DLL's import table) or dynamically loaded.

` vol.py -f memdump.vmem --profile=<profile> dlllist -p 1892 `

To display the DLLs for a process that is hidden or unlinked by a rootkit, first use the psscan to get the physical offset of the EPROCESS object and supply it with — offset=OFFSET. The plugin will “bounce back” and determine the virtual address of the EPROCESS and then acquire an address space in order to access the PEB.

` vol.py -f memdump.vmem --profile=<profile> dlllist --offset=<pysical offeset of process> ` 

 ***Notice when you  analyze a Wow64 process***: Wow64 processes have a limited list of DLLs in the PEB lists, but that doesn't mean they're the only DLLs loaded in the process address space. Thus Volatility will remind you to use the ***ldrmodules*** instead for these processes.
 
 
### LDRModule
detect unlinked DLL and non memory maped files.There are many ways to hide a DLL. One of the ways involves unlinking the DLL from one (or all) of the linked lists in the PEB. However, when this is done, there is still information contained within the VAD (Virtual Address Descriptor) which identifies the base address of the DLL and its full path on disk. To cross-reference this information (known as memory mapped files) with the 3 PEB lists, use the ldrmodules command.For each memory mapped PE file, the ldrmodules command prints True or False if the PE exists in the PEB lists. if you dont see information in mapped path column, this indicate DLL was not loaded using windows API. and this is sign of dll injection. also Since the PEB and the DLL lists that it contains all exist in user mode, its also possible for malware to hide (or obscure) a DLL by simply overwriting the path. Tools that only look for unlinked entries may miss the fact that malware could overwrite C:\bad.dll to show C:\windows\system32\kernel32.dll. So you can also pass -v or --verbose to ldrmodules to see the full path of all entries.
 python vol.py -f memdump.vmem --profile=<profile> ldrmodules -v
 
 For concrete examples, see QuickPost: Flame & Volatility.

### DLLDump
To extract a DLL from a process’s memory space and dump it to disk for analysis, use the dlldump command. The syntax is nearly the same as what we’ve shown for dlllist above. You can:
- Dump all DLLs from all processes
- Dump all DLLs from a specific process `(with --pid=PID)`
- Dump all DLLs from a hidden/unlinked process `(with --offset=OFFSET)`
- Dump a PE from anywhere in process memory `(with --base=BASEADDR)`, this option is useful for extracting hidden DLLs
- Dump one or more DLLs that match a regular expression `(--regex=REGEX)`, case sensitive or not `(--ignore-case)`
To specify an output directory, use `--dump-dir=DIR or -d DIR`.

` vol.py -f memdump.vmem --profile=<profile> dlldump -D dlls/ `

If the extraction fails, as it did for a few DLLs above, it probably means that some of the memory pages in that DLL were not memory resident (due to paging). In particular, this is a problem if the first page containing the PE header and thus the PE section mappings is not available. In these cases you can still extract the memory segment using the vaddump command, but you’ll need to manually rebuild the PE header and fixup the sections (if you plan on analyzing in IDA Pro) as described in [Recovering CoreFlood Binaries with Volatility](https://mnin.blogspot.com/2008/11/recovering-coreflood-binaries-with.html).

To dump a PE file that doesn’t exist in the DLLs list (for example, due to code injection or malicious unlinking), just specify the base address of the PE in process memory:
` vol.py --profile=<profile> -f windump.vmem dlldump --pid=<PID> -D out --base=<Base Address of the PE>
` vol.py --profile=<profile> -f windump.vmem dlldump -o <Physical offset of Process>  -D out --base=<Base address of the PE> `

___
 ## YARASCAN
 Volatility has several built-in scanning engines to help you find simple patterns like pool tags in physical or virtual address spaces. However, if you need to scan for more complex things like regular expressions or compound rules, you can use the yarascan command. You can create a YARA rules file and specify it as --yara-file=RULESFILE. Or, if you're just looking for something simple, and only plan to do the search a few times, then you can specify the criteria like --yara-rules=RULESTEXT.
To search for signatures defined in the file rules.yar, in any process, and simply display the results on screen: 
 
` python vol.py -f zeus.vmem yarascan --yara-file=/path/to/rules.yar `
 
To search for a simple string in any process and dump the memory segments containing a match:
 
` python vol.py -f zeus.vmem yarascan -D dump_files --yara-rules="simpleStringToFind" ` 
 
To Search for a given byte pattern in a particular process:
 
` python vol.py -f zeus.vmem yarascan --yara-rules="{eb 90 ff e4 88 32 0d}" --pid=624 `
___
 ## SVCSCAN
Volatility is the only memory forensics framework with the ability to list services without using the Windows API on a live machine. To see which services are registered on your memory image, use the svcscan command. The output shows the process ID of each service (if its active and pertains to a usermode process), the service name, service display name, service type, and current status. It also shows the binary path for the registered service - which will be an EXE for usermode services and a driver name for services that run from kernel mode.
 ` python vol.py -f memdump.vmem --profile=<profile> svcscan `
 A new option (--verbose) is available starting with Volatility 2.3. This option checks the ServiceDll registry key and reports which DLL is hosting the service. This is a critical capability since malware very commonly installs services using svchost.exe (the shared host service process) and implements the actual malicious code in a DLL.
 ` python vol.py -f memdump.vmem svcscan --verbose --profile=<profile> `


 ____
 ## Kernel Memory and Objects
 ## modules
 To view the list of kernel drivers loaded on the system, use the modules command. This walks the doubly-linked list of LDR_DATA_TABLE_ENTRY structures pointed to by PsLoadedModuleList. Similar to the pslist command, this relies on finding the KDBG structure. In rare cases, you may need to use kdbgscan to find the most appropriate KDBG structure address and then supply it to this plugin like --kdbg=ADDRESS.
It cannot find hidden/unlinked kernel drivers, however modscan serves that purpose. Also, since this plugin uses list walking techniques, you typically can assume that the order the modules are displayed in the output is the order they were loaded on the system. 
 
 ` python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 modules `
 
 ## modscan
 The modscan command finds LDR_DATA_TABLE_ENTRY structures by scanning physical memory for pool tags. This can pick up previously unloaded drivers and drivers that have been hidden/unlinked by rootkits. Unlike modules the order of results has no relationship with the order in which the drivers loaded. As you can see below, DumpIt.sys was found at the lowest physical offset, but it was probably one of the last drivers to load (since it was used to acquire memory).
 
 ` python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 modscan `
 
 
 ## Moddump
 To extract a kernel driver to a file, use the moddump command. Supply the output directory with -D or --dump-dir=DIR. Without any additional parameters, all drivers identified by modlist will be dumped. If you want a specific driver, supply a regular expression of the driver's name with --regex=REGEX or the module's base address with --base=BASE.
 
 ` python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 moddump -D drivers/ `
 
 ## SSDT (System Service Descriptor Table)
 The SSDT maps syscalls to kernel function addresses. When a syscall is issued by a user space application, it contains the service index as parameter to indicate which syscall is called. The SSDT is then used to resolve the address of the corresponding function within ntoskrnl.exe. In modern Windows kernels, two SSDTs are used: One for generic routines (KeServiceDescriptorTable) and a second (KeServiceDescriptorTableShadow) for graphical routines. A parameter passed by the calling userspace application determines which SSDT shall be used.
  This table is a link between Ring3's Win32 API and Ring0's kernel API. SSDT not only contains a huge address index table, but also contains some other useful information, such as the base address of the address index, the number of service functions and so on. By modifying the function address of this table, the common Windows functions and APIs can be Hook, so as to achieve the purpose of filtering and monitoring some concerned system actions. Some HIPS, anti-virus software, system monitoring, registry monitoring software often use this interface to achieve their own monitoring module.
Windows over NT 4.0 operating system By default, there are two system service description tables, which correspond to two different types of system services: KeService Descriptor Table and KeService Descriptor Table Shadow. KeService Descriptor Table mainly deals with system calls from Ring 3-tier Kernel 32.dll, while KeService Descriptor Table Shadow mainly deals with system calls from Ring 3-tier Kernel 32.dll. System calls from User32.dll and GDI32.dll, and KeService Descriptor Table is exported in ntoskrnl.exe(Windows operating system kernel files, including kernel and execution layer), while KeService Descriptor Table Shadow is not exported by Windows operating system, and all content about SSDT is done through KeService Descriptor Table.
 
 ## SSDT Hooking
 To filter all functions which point to ntoskrnl.exe and win32k.sys, you can use egrep on command-line. This will only show hooked SSDT functions.
 `  python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 ssdt | egrep -v '(ntos|win32k)' `
 Note that the NT module on your system may be ntkrnlpa.exe or ntkrnlmp.exe - so check that before using egrep of you'll be filtering the wrong module name. Also be aware that this isn't a hardened technique for finding hooks, as malware can load a driver named win32ktesting.sys and bypass your filter.
 
 ## driverscan
 To find DRIVER_OBJECTs in physical memory using pool tag scanning, use the driverscan command. This is another way to locate kernel modules, although not all kernel modules have an associated DRIVER_OBJECT. The DRIVER_OBJECT is what contains the 28 IRP (Major Function) tables, thus the driverirp command is based on the methodology used by driverscan.
 
 ` python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 driverscan `
 
 
 ## filescan
 To find FILE_OBJECTs in physical memory using pool tag scanning, use the filescan command. This will find open files even if a rootkit is hiding the files on disk and if the rootkit hooks some API functions to hide the open handles on a live system. The output shows the physical offset of the FILE_OBJECT, file name, number of pointers to the object, number of handles to the object, and the effective permissions granted to the object.
 
 ` python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 filescan` 
 ## mutantscan
 Malicious software often uses mutex objects for the same purpose as legitimate software. Furthermore, malware might use a mutex to avoid reinfecting the host. 
 To scan physical memory for KMUTANT objects with pool tag scanning, use the mutantscan command. By default, it displays all objects, but you can pass -s or --silent to only show named mutexes. The CID column contains the process ID and thread ID of the mutex owner if one exists.
 
 ` python -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 mutantscan --silent `
 
 
 https://www.sans.org/blog/looking-at-mutex-objects-for-malware-discovery-indicators-of-compromise/
