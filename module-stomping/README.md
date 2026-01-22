# Module Stomping (Module Overwriting)

## Summary
Module Stomping is a process injection technique where a legitimate, image-backed DLL is loaded into a process, and its memory (typically the `.text` section) is overwritten with a payload. This ensures the payload resides within a memory region associated with a file on disk, rather than "Private" memory.

| Component | Description |
| :--- | :--- |
| **Technique** | Overwriting legitimate module code with a payload. |
| **Tactical Goal** | **Evade Memory Scanners:** Bypasses detections that flag `RX` memory regions not backed by a file on disk (`MEM_PRIVATE`). |
| **Stealth** | **Moderate.** While it solves the "unbacked memory" problem, it introduces another IoC "Module Mismatch" (the memory content no longer matches the file on disk). |

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