# Direct Syscalls

## Summary
The use of direct syscalls is an EDR evasion technique where an executable manually sets up the EAX CPU register to a specific System Service Number (SSN) and executes the `syscall` instruction directly from user-mode assembly, bypassing userland API hooks placed by security products inside the target DLL (ex: `ntdll.dll`).

| Component | Description |
| --- | --- |
| **Technique** | Invoking kernel transitions directly via assembly (`syscall`) rather than routing through user-mode export stubs. |
| **Tactical Goal** | **Bypass Userland Hooking:** Circumvents inline hooks (such as `jmp` patches) placed by EDR/AV solutions inside Win32 APIs or Native APIs (ex: `ntdll.dll`). |
| **Stealth** | **Moderate.** While it completely avoids executing hooked user-mode code, direct transitions from an unbacked module or private memory generate abnormal call stacks and trigger telemetry events that flag rip execution outside `ntdll.dll`. |

---

## Execution Steps

1. **System Service Number (SSN) Identification:** The System Service Numbers corresponding to target native APIs (`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`, etc.) are pre-identified for the specific target OS architecture/build (such as Windows Server 2025) and defined as constants within the assembly implementation.
2. **Register Preparation:** When invoking a wrapper routine, user-mode execution enters the custom assembly procedure in `direct-syscalls.asm`. The routine moves the first argument from `RCX` into `R10` (since the `syscall` instruction in x64 architecture overwrites `RCX` with the return `RIP`) and loads the designated SSN into `EAX`.
3. **Direct Kernel Transition:** The routine issues the `syscall` instruction directly from the user-mode application's memory space, switching the CPU privilege level to Ring 0 and handing execution to the kernel dispatch table without passing through `ntdll.dll` stubs.
4. **Execution & Injection:**
* **Target Acquisition:** Resolves the process ID of the target process (`notepad.exe`) and opens a handle.
* **Allocate Space:** Invokes `SysNtAllocateVirtualMemory` via direct syscall to allocate memory within the target process space.
* **Write Payload:** Invokes `SysNtWriteVirtualMemory` via direct syscall to copy the buffer into the allocated target region.
* **Thread Creation & Blocking:** Invokes `SysNtCreateThreadEx` to spawn execution inside the remote process, then invokes `SysNtWaitForSingleObject` to await completion.

---

## Compilation
Compile the assembly routines using MASM (`ml64.exe`) and link them with the C driver using MSVC (`cl.exe`):

1. Assemble the 64-bit indirect syscall stubs
```
ml64.exe /c direct-syscalls.asm
```

2. Compile and link the sample with dependencies
```
cl.exe direct-syscalls-ex.c ..\includes\peb-eat-utils.c ..\includes\syscall-utils.c ..\includes\ps-utils.c direct-syscalls.obj /Fe:direct-syscalls.exe
```