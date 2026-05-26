# Module Stomping (Module Overwriting)

## Summary
Module Stomping is a process injection technique where a legitimate, image-backed DLL is loaded into a process, and its memory (typically the `.text` section) is overwritten with a payload. This ensures the payload resides within a memory region associated with a file on disk, rather than "Private" memory.

| Component | Description |
| :--- | :--- |
| **Technique** | Overwriting legitimate module code with a payload. |
| **Tactical Goal** | **Evade Memory Scanners:** Bypasses detections that flag `RX` memory regions not backed by a file on disk (`MEM_PRIVATE`). |
| **Stealth** | **Moderate.** While it solves the "unbacked memory" problem, it introduces another IoC "Module Mismatch" (the memory content no longer matches the file on disk). |

## DLL Discovery
Identify a target process and the process ID.
```
c:\Users\Administrator\Desktop\module-stomping>tasklist /fi "imageName eq rufus.exe"

Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
rufus.exe                     1988 RDP-Tcp#0                  2     27,636 K

c:\Users\Administrator\Desktop\module-stomping>
```
Output the list of modules loaded by the target process
```
c:\Users\Administrator\Desktop\module-stomping>.\list-process-dlls.exe -p 1988
[+] Successfully obtained handle for PID 1988
[+] Enumerating loaded modules:
--------------------------------------------------
[0x00007FF7F8A30000] rufus.exe
[0x00007FFFFC060000] ntdll.dll
[0x00007FFFFA990000] KERNEL32.DLL
[0x00007FFFF97E0000] KERNELBASE.dll
[0x00007FFFF6CA0000] apphelp.dll
[0x00007FFFFAB60000] USER32.dll
[0x00007FFFF96F0000] win32u.dll
[0x00007FFFFB5C0000] GDI32.dll
[0x00007FFFF9300000] gdi32full.dll
[0x00007FFFF9430000] msvcp_win.dll
[0x00007FFFF91B0000] ucrtbase.dll
[0x00007FFFF9E10000] IMM32.DLL
[0x00007FFFFB3A0000] ADVAPI32.dll
[0x00007FFFFA2E0000] msvcrt.dll
[0x00007FFFFAF60000] sechost.dll
[0x00007FFFFA7E0000] RPCRT4.dll
[0x00007FFFF8200000] SspiCli.dll
[0x00007FFFFB6F0000] SHELL32.dll
[0x00007FFFF9BE0000] wintypes.dll
[0x00007FFFFB010000] combase.dll
[0x00007FFFF07D0000] windows.storage.dll
[0x00007FFFFB4B0000] SHCORE.dll
[0x00007FFFFAD30000] shlwapi.dll
[0x00007FFFF90D0000] profapi.dll
[0x00007FFFF9570000] CRYPT32.dll
[0x00007FFFF94E0000] WINTRUST.DLL
[0x00007FFFF8800000] MSASN1.dll
[0x00007FFFFA7A0000] imagehlp.dll
[0x00007FFFFA410000] ole32.dll
[0x00007FFFF75D0000] kernel.appcore.dll
[0x00007FFFF9D50000] bcryptPrimitives.dll
[0x00007FFFF6EA0000] uxtheme.dll
[0x00007FFFFADA0000] clbcatq.dll
[0x00007FFFE1890000] vds_ps.dll
[0x00007FFFF8870000] Wldp.DLL
[0x00007FFFD7D10000] Riched20.DLL
[0x00007FFFE5080000] USP10.dll
[0x00007FFFD9880000] msls31.dll
[0x00007FFFEB580000] VERSION.dll
[0x00007FFFFBEB0000] MSCTF.dll
[0x00007FFFEB020000] comctl32.dll
[0x00007FFFF7130000] dwmapi.dll
[0x00007FFFFAE60000] OLEAUT32.dll
[0x00007FFFEEAB0000] textinputframework.dll
[0x00007FFFF53E0000] WindowsCodecs.dll
[0x00007FFFEE460000] IconCodecService.dll
[0x00007FFFD93E0000] oleacc.dll
[0x00007FFFEF500000] TextShaping.dll
[0x00007FFFD9120000] explorerframe.dll
[0x00007FFFFAA60000] ComDlg32.DLL
[0x00007FFFF68A0000] CoreMessaging.dll
[0x00007FFFF3DD0000] CoreUIComponents.dll
[0x00007FFFF8790000] CRYPTBASE.DLL
[0x00007FFFF9E50000] SETUPAPI.dll
[0x00007FFFF8D50000] DEVOBJ.dll
[0x00007FFFF8CF0000] cfgmgr32.dll

c:\Users\Administrator\Desktop\module-stomping>
```
Save the list of module names to a file named `rufus-modules-loaded.txt`
```
c:\Users\Administrator\Desktop\module-stomping>.\list-process-dlls.exe -p 1988 -n -o rufus-modules-loaded.txt
[+] Successfully obtained handle for PID 1988
[+] Output will also be dumped to: rufus-modules-loaded.txt
[+] Enumerating loaded modules:
--------------------------------------------------
rufus.exe
ntdll.dll
KERNEL32.DLL
KERNELBASE.dll
apphelp.dll
USER32.dll
win32u.dll
GDI32.dll
gdi32full.dll
msvcp_win.dll
ucrtbase.dll
IMM32.DLL
ADVAPI32.dll
msvcrt.dll
sechost.dll
RPCRT4.dll
SspiCli.dll
SHELL32.dll
wintypes.dll
combase.dll
windows.storage.dll
SHCORE.dll
shlwapi.dll
profapi.dll
CRYPT32.dll
WINTRUST.DLL
MSASN1.dll
imagehlp.dll
ole32.dll
kernel.appcore.dll
bcryptPrimitives.dll
uxtheme.dll
clbcatq.dll
vds_ps.dll
Wldp.DLL
Riched20.DLL
USP10.dll
msls31.dll
VERSION.dll
MSCTF.dll
comctl32.dll
dwmapi.dll
OLEAUT32.dll
textinputframework.dll
WindowsCodecs.dll
IconCodecService.dll
oleacc.dll
TextShaping.dll
explorerframe.dll
ComDlg32.DLL
CoreMessaging.dll
CoreUIComponents.dll
CRYPTBASE.DLL
SETUPAPI.dll
DEVOBJ.dll
cfgmgr32.dll

c:\Users\Administrator\Desktop\module-stomping>
```

[find-stompable-dlls.py](find-stompable-dlls.py)

Locate qualifying modules that are already loaded using the `includes` list
```
c:\Users\Administrator\Desktop\module-stomping>python find-stompable-dlls.py 0x80000 -i rufus-modules-loaded.txt
[*] Loading INCLUDE_MODULES from: 'rufus-modules-loaded.txt'
[+] Loaded 56 modules into INCLUDE_MODULES filter.
[*] Scanning Target Directory: 'C:\Windows\System32'
[*] Filtering for Files      : > 1.0MB
[*] Required .text Space     : 0x80000 bytes
[*] Targeted Include Filter  : Active (56 specific targets allowed)
--------------------------------------------------------------------------------------------------------------------------------------------
Full File Path                                                                        | File Size (MB)  | Size of .text   | Virtual Address
--------------------------------------------------------------------------------------------------------------------------------------------
C:\Windows\System32\combase.dll                                                       | 3.54            | 0x269ca2        | 0x1000
C:\Windows\System32\CoreMessaging.dll                                                 | 1.17            | 0xd1175         | 0x1000
C:\Windows\System32\CoreUIComponents.dll                                              | 2.89            | 0x19bf50        | 0x1000
C:\Windows\System32\crypt32.dll                                                       | 1.46            | 0x124e7b        | 0x1000
C:\Windows\System32\ExplorerFrame.dll                                                 | 2.73            | 0x21677c        | 0x1000
C:\Windows\System32\gdi32full.dll                                                     | 1.18            | 0xb32bc         | 0x1000
C:\Windows\System32\KernelBase.dll                                                    | 3.94            | 0x1a392f        | 0x1000
C:\Windows\System32\msctf.dll                                                         | 1.38            | 0x114f70        | 0x1000
C:\Windows\System32\ntdll.dll                                                         | 2.41            | 0x16ae9c        | 0x1000
C:\Windows\System32\ole32.dll                                                         | 1.61            | 0xd5c4c         | 0x1000
C:\Windows\System32\rpcrt4.dll                                                        | 1.11            | 0xd3e99         | 0x1000
C:\Windows\System32\setupapi.dll                                                      | 4.58            | 0xebc1e         | 0x1000
C:\Windows\System32\shell32.dll                                                       | 7.37            | 0x5aa034        | 0x1000
C:\Windows\System32\TextInputFramework.dll                                            | 1.30            | 0xf8d0c         | 0x1000
C:\Windows\System32\ucrtbase.dll                                                      | 1.31            | 0xf5f61         | 0x1000
C:\Windows\System32\user32.dll                                                        | 1.79            | 0xa7fee         | 0x1000
C:\Windows\System32\windows.storage.dll                                               | 8.43            | 0x64cc4e        | 0x1000
C:\Windows\System32\WindowsCodecs.dll                                                 | 2.21            | 0x1a226c        | 0x1000
C:\Windows\System32\WinTypes.dll                                                      | 1.43            | 0xa1318         | 0x1000
C:\Windows\System32\downlevel\ucrtbase.dll                                            | 1.31            | 0xf559c         | 0x1000
--------------------------------------------------------------------------------------------------------------------------------------------
[*] Found 20 potential candidates matching the criteria.

c:\Users\Administrator\Desktop\module-stomping>
```
Locate qualifying modules that are NOT already loaded using the `excludes` list
```
c:\Users\Administrator\Desktop\module-stomping>python find-stompable-dlls.py 0x80000 -x rufus-modules-loaded.txt
[*] Loading EXCLUDE_MODULES from: 'rufus-modules-loaded.txt'
[+] Loaded 56 modules into EXCLUDE_MODULES filter.
[*] Scanning Target Directory: 'C:\Windows\System32'
[*] Filtering for Files      : > 1.0MB
[*] Required .text Space     : 0x80000 bytes
[*] Exclusion Filter         : Active (56 modules blacklisted)
--------------------------------------------------------------------------------------------------------------------------------------------
Full File Path                                                                        | File Size (MB)  | Size of .text   | Virtual Address
--------------------------------------------------------------------------------------------------------------------------------------------
C:\Windows\System32\aadtb.dll                                                         | 1.48            | 0xff60c         | 0x1000
C:\Windows\System32\ActiveSyncProvider.dll                                            | 1.73            | 0x14abe2        | 0x1000
C:\Windows\System32\aeinv.dll                                                         | 1.60            | 0x13495a        | 0x1000
C:\Windows\System32\aemarebackup.dll                                                  | 1.23            | 0xf8a64         | 0x1000
C:\Windows\System32\aepic.dll                                                         | 1.25            | 0xf2afa         | 0x1000
C:\Windows\System32\APMon.dll                                                         | 1.57            | 0xe395c         | 0x1000
C:\Windows\System32\appraiser.dll                                                     | 3.18            | 0x26b133        | 0x1000
C:\Windows\System32\AppVEntSubsystemController.dll                                    | 1.22            | 0xc941c         | 0x1000
...
C:\Windows\System32\ru\Microsoft.Windows.ServerManager.Plugins.Ipam.resources.dll     | 2.84            | 0x2d6354        | 0x2000
C:\Windows\System32\SecurityHealth\10.0.29429.1000-0\SecurityHealthAgent.dll          | 1.36            | 0xb748c         | 0x1000
C:\Windows\System32\SecurityHealth\10.0.29429.1000-0\SecurityHealthCore.dll           | 1.31            | 0xeb64c         | 0x1000
C:\Windows\System32\ShellExperiences\WindowsInternal.Xaml.Controls.Tabs.dll           | 1.68            | 0x14766c        | 0x1000
C:\Windows\System32\Speech\Common\sapi.dll                                            | 1.45            | 0xdcaab         | 0x1000
C:\Windows\System32\Speech\SpeechUX\SpeechUX.dll                                      | 1.46            | 0x8f343         | 0x1000
C:\Windows\System32\Speech_OneCore\Common\sapi_onecore.dll                            | 4.26            | 0x2aad27        | 0x1000
C:\Windows\System32\Speech_OneCore\Common\Windows.Speech.Shell.dll                    | 1.03            | 0xc2818         | 0x1000
C:\Windows\System32\Speech_OneCore\Engines\SR\spsreng_onecore.dll                     | 1.41            | 0x10ae0b        | 0x1000
C:\Windows\System32\Speech_OneCore\Engines\TTS\MSTTSEngine_OneCore.dll                | 1.87            | 0x16bb0c        | 0x1000
C:\Windows\System32\spool\drivers\W32X86\3\mxdwdrv.dll                                | 1.12            | 0x10e418        | 0x1000
C:\Windows\System32\spool\drivers\W32X86\3\PrintConfig.dll                            | 3.12            | 0x1da306        | 0x1000
C:\Windows\System32\spool\drivers\x64\3\PrintConfig.dll                               | 3.66            | 0x1c497c        | 0x1000
C:\Windows\System32\spool\drivers\x64\3\PS5UI.DLL                                     | 1.19            | 0xa993c         | 0x1000
C:\Windows\System32\spool\drivers\x64\3\UNIDRVUI.DLL                                  | 1.27            | 0xb840c         | 0x1000
C:\Windows\System32\wbem\cimwin32.dll                                                 | 1.75            | 0x12f3dc        | 0x1000
C:\Windows\System32\wbem\DMWmiBridgeProv.dll                                          | 3.75            | 0x244a1c        | 0x1000
C:\Windows\System32\wbem\Microsoft.Uev.AgentWmi.dll                                   | 1.09            | 0xc3d6c         | 0x1000
C:\Windows\System32\wbem\NetPeerDistCim.dll                                           | 1.39            | 0xffe3a         | 0x1000
C:\Windows\System32\wbem\wbemcore.dll                                                 | 1.77            | 0xee98c         | 0x1000
C:\Windows\System32\WindowsPowerShell\v1.0\Modules\Appx\Microsoft.Windows.Appx.PackageManager.Commands.Core.dll | 2.68            | 0x2acd98        | 0x2000
C:\Windows\System32\zh-HANS\AuthFWSnapIn.Resources.dll                                | 2.98            | 0x2f9674        | 0x2000
C:\Windows\System32\zh-HANS\Microsoft.Windows.ServerManager.Plugins.Ipam.resources.dll | 2.72            | 0x2b6d04        | 0x2000
--------------------------------------------------------------------------------------------------------------------------------------------
[*] Found 411 potential candidates matching the criteria.

c:\Users\Administrator\Desktop\module-stomping>
```

## Execution Steps
### Stomping in the Current Process
The `local-stomp.cpp` example follows this execution logic:

1. **Load Target DLL:** Use `LoadLibraryExA` with the `DONT_RESOLVE_DLL_REFERENCES` flag to map a "sacrificial" DLL into the process without executing its entry point.
2. **Identify Section:** Lazy locate the `.text` section of the loaded module to ensure the payload is placed in an executable region.
3. **Reprotect (Write):** Call `VirtualProtect` to change the memory permissions from Read-Execute (`RX`) to Read-Write (`RW`).
4. **Write Payload:** Use `WriteProcessMemory` or `RtlCopyMemory` to stomp the payload over the legitimate instructions.
5. **Reprotect (Execute):** Revert the memory permissions back to Read-Execute (`RX`).
6. **Execution:** Trigger the shellcode using a thread execution API (e.g., `CreateThread` or `CreateRemoteThread`).
### Stomping in a Remote Process
The `remote-stomp.cpp` example follows this execution logic:  

1. **Acquire Process Handle:** Open a handle to the target remote process via OpenProcess using the supplied Process ID (PID) with the required access rights.
2. **Locate Remote PEB:** Query the target process to find its remote Process Environment Block (PEB) address using internal utility routines.
3. **Parse Remote Modules:** Walk the remote process's InMemoryOrderModuleList to dynamically locate the base address of a loaded target module (e.g., KERNEL32.dll).
4. **Identify Section / Export Target:** Verify the boundaries of the executable .text section, and locate a specific target function address (e.g., FileTimeToSystemTime) within that module via manual Export Address Table (EAT) parsing.
5. **Reprotect (Write):** Call VirtualProtectEx to change the target function's memory permissions in the remote process from Read-Execute (RX) to Read-Write (RW).
6. **Write Payload:** Use WriteProcessMemory to stomp the shellcode payload directly over the legitimate instructions of the identified remote export.
7. **Reprotect (Execute):** Revert the remote memory permissions back to Read-Execute (RX) via VirtualProtectEx.
8. **Execution:** Trigger the payload within the target process context using a remote execution API (e.g., CreateRemoteThread) pointing directly to the stomped function address.

## OPSEC Considerations

### 1. Image Divergence
Modern EDRs perform "Module Integrity Checks" by comparing the code in memory against the original file on disk. 
* **The Risk:** If `Memory_Hash(DLL) != Disk_Hash(DLL)`, an alert is triggered.
* **Mitigation:** Choose large DLLs and only stomp the specific bytes needed. Consider using "Nops" to mask the payload entry.

### 2. API Monitoring
The use of `VirtualProtect` on an image-backed region is a high-confidence heuristic for many security products.
* **Red Team Tip:** Instead of `VirtualProtect`, advanced implementations use `NtMapViewOfSection` to map a modified view of the DLL directly into memory, avoiding the "Modify" event entirely.

### 3. Target Selection
* **Size Matters:** The sacrificial DLL must have a `.text` section larger than your payload.
* **Frequency:** Use common system DLLs that are normally present but rarely undergo deep integrity checks during routine operation.

## Indicators of Compromise (IoC)
* **Memory/Disk Mismatch:** Significant byte differences between the loaded module and its corresponding `C:\Windows\System32\` file.
* **Suspicious Call Trace:** Thread execution starting from the middle of a DLL's code section rather than a legitimate exported function.
* **API Pattern:** The sequence of `LoadLibrary` -> `VirtualProtect(RW)` -> `VirtualProtect(RX)` is a classic signature of memory manipulation.
