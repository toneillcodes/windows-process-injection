# Module Stomping (Module Overwriting)

## Summary
Module Stomping is a process injection technique where a legitimate, image-backed DLL is loaded into a process, and its memory (typically the `.text` section) is overwritten with a payload. This ensures the payload resides within a memory region associated with a file on disk, rather than "Private" memory.

| Component | Description |
| :--- | :--- |
| **Technique** | Overwriting legitimate module code with a payload. |
| **Tactical Goal** | **Evade Memory Scanners:** Bypasses detections that flag `RX` memory regions not backed by a file on disk (`MEM_PRIVATE`). |
| **Stealth** | **Moderate.** While it solves the "unbacked memory" problem, it introduces another IoC "Module Mismatch" (the memory content no longer matches the file on disk). |

## DLL Scanner
[find-stompable-dlls.py](find-stompable-dlls.py)
```
PS C:\Users\Administrator\Desktop\Tools > python .\find-stompable-dlls.py 0x80000
[*] Scanning Target Directory: 'C:\Windows\System32'
[*] Filtering for Files      : > 1.0MB
[*] Required .text Space     : 0x80000 bytes
------------------------------------------------------------------------------------------
DLL Name                                 | File Size (MB)  | Size of .text   | Virtual Address
------------------------------------------------------------------------------------------
aadtb.dll                                | 1.48            | 0xff60c         | 0x1000
ActiveSyncProvider.dll                   | 1.73            | 0x14abe2        | 0x1000
aeinv.dll                                | 1.60            | 0x13495a        | 0x1000
aemarebackup.dll                         | 1.23            | 0xf8a64         | 0x1000
aepic.dll                                | 1.25            | 0xf2afa         | 0x1000
APMon.dll                                | 1.57            | 0xe395c         | 0x1000
appraiser.dll                            | 3.18            | 0x26b133        | 0x1000
AppVEntSubsystemController.dll           | 1.22            | 0xc941c         | 0x1000
AppVEntSubsystems64.dll                  | 1.63            | 0x10565c        | 0x1000
AppVEntVirtualization.dll                | 1.56            | 0x108d1c        | 0x1000
AppVIntegration.dll                      | 1.37            | 0xd648c         | 0x1000
AppXDeploymentClient.dll                 | 1.45            | 0xe89d0         | 0x1000
AppXDeploymentExtensions.desktop.dll     | 2.68            | 0x1ab07c        | 0x1000
AppXDeploymentExtensions.onecore.dll     | 3.44            | 0x23493c        | 0x1000
...
PrintConfig.dll                          | 3.66            | 0x1c497c        | 0x1000
PS5UI.DLL                                | 1.19            | 0xa993c         | 0x1000
UNIDRVUI.DLL                             | 1.27            | 0xb840c         | 0x1000
cimwin32.dll                             | 1.75            | 0x12f3dc        | 0x1000
DMWmiBridgeProv.dll                      | 3.75            | 0x244a1c        | 0x1000
Microsoft.Uev.AgentWmi.dll               | 1.09            | 0xc3d6c         | 0x1000
NetPeerDistCim.dll                       | 1.39            | 0xffe3a         | 0x1000
wbemcore.dll                             | 1.77            | 0xee98c         | 0x1000
Microsoft.Windows.Appx.PackageManager.Commands.Core.dll | 2.68            | 0x2acd98        | 0x2000
AuthFWSnapIn.Resources.dll               | 2.98            | 0x2f9674        | 0x2000
Microsoft.Windows.ServerManager.Plugins.Ipam.resources.dll | 2.72            | 0x2b6d04        | 0x2000
------------------------------------------------------------------------------------------
[*] Found 433 potential candidates.
PS C:\Users\Administrator\Desktop\Tools >
```

## Execution Steps
The `local-stomp.cpp` example follows this execution logic:

1. **Load Target DLL:** Use `LoadLibraryExA` with the `DONT_RESOLVE_DLL_REFERENCES` flag to map a "sacrificial" DLL into the process without executing its entry point.
2. **Identify Section:** Lazy locate the `.text` section of the loaded module to ensure the payload is placed in an executable region.
3. **Reprotect (Write):** Call `VirtualProtect` to change the memory permissions from Read-Execute (`RX`) to Read-Write (`RW`).
4. **Write Payload:** Use `WriteProcessMemory` or `RtlCopyMemory` to stomp the payload over the legitimate instructions.
5. **Reprotect (Execute):** Revert the memory permissions back to Read-Execute (`RX`).
6. **Execution:** Trigger the shellcode using a thread execution API (e.g., `CreateThread` or `CreateRemoteThread`).

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
