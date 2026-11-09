# Indirect System Calls

## Summary
Indirect System Calls is an evasion technique where user-mode code extracts clean System Service Numbers (SSNs) and transitions into kernel mode by jumping to a legitimate `syscall; ret` gadget located inside `ntdll.dll`, rather than issuing the `syscall` instruction from local private memory.

| Component | Description |
| --- | --- |
| **Technique** | Resolving clean SSNs dynamically and redirecting execution via `jmp` to a `syscall; ret` instruction located within legitimate `ntdll.dll` memory. |
| **Tactical Goal** | **Bypass Inline Hooks & RIP Telemetry:** Evades inline API hooks placed in userland stubs while ensuring the kernel-mode transition origin points to legitimate image-backed memory (`ntdll.dll`) rather than private assembly memory. |
| **Stealth** | **High.** Eliminates unbacked execution origins detected by kernel telemetry (e.g., ETW-Ti) and basic return-address checks. |

---

## Execution Steps
1. **Clean SSN Extraction:** Uses PEB and EAT parsing (`GetSSNByName`) to obtain the original syscall numbers directly from an unhooked copy of `ntdll.dll` on disk, bypassing any memory-resident inline hooks.
2. **Gadget Resolution:** Queries the base address of each target NT API in the loaded `ntdll.dll` and offsets into the stub (`+ 0x12`) to locate the native `syscall; ret` instructions.
3. **Assembly Proxying:** Calls wrapper routines in `indirect-syscalls.asm` that populate `r10` and `eax` with the extracted parameters and SSN, then perform an indirect jump (`jmp QWORD PTR [sysAddr...]`) into `ntdll.dll` to execute the transition.
4. **Execution & Injection:**
* **Target Acquisition:** Resolves the process ID of the target process (`notepad.exe`) and opens a handle.
* **Allocate Space:** `IndirectSysNtAllocateVirtualMemory` (Allocates memory with `PAGE_EXECUTE_READWRITE`)
* **Write Payload:** `IndirectSysNtWriteVirtualMemory` (Copies the payload buffer into target space)
* **Thread Creation & Blocking:** `IndirectSysNtCreateThreadEx` (Spawns a remote execution thread) & `IndirectSysNtWaitForSingleObject` (Blocks until thread completion)

---

## Compilation
Compile the assembly routines using MASM (`ml64.exe`) and link them with the C driver using MSVC (`cl.exe`):

1. Assemble the 64-bit indirect syscall stubs
```
ml64.exe /c indirect-syscalls.asm
```

2. Compile and link the sample with dependencies
```
cl.exe indirect-syscalls-ex.c ..\includes\peb-eat-utils.c ..\includes\syscall-utils.c ..\includes\ps-utils.c indirect-syscalls.obj /Fe:indirect-syscalls.exe
```