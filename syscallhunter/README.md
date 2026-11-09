# SyscallHunter

## Summary
SyscallHunter is a utility designed to inspect native Windows export stubs in loaded dynamic-link libraries (such as `ntdll.dll`) and dynamically extract their System Service Number (SSN) along with the memory address of the transition instruction. It parses the in-memory function bytes for signature opcodes rather than relying on static syscall tables.

| Component | Description |
| --- | --- |
| **Technique** | Runtime byte-scanning of exported function stubs to locate the `mov eax, <imm32>` opcode (`0xB8`) and retrieve the immediate 32-bit SSN value. |
| **Tactical Goal** | **Dynamic Syscall Resolution:** Eliminates hardcoded SSNs across varying Windows builds and service packs, providing accurate syscall IDs and transition addresses for direct or indirect invocation. |
| **Stealth / Utility** | **Informational / Prerequisite Tool.** Analyzes local process memory space to resolve system call artifacts required by low-level invocation routines. |

---

## Execution Steps
1. **Module & Export Resolution:**
* Receives target module name (e.g., `ntdll.dll`) and export name (e.g., `NtCreateThreadEx`) via command-line arguments.
* Acquires the base handle of the loaded module using `GetModuleHandleA` and resolves the initial virtual address of the exported stub using `GetProcAddress`.

2. **Opcode Pattern Scanning (`GetSSNFromAddress`):**
* Sets up a bounded inspection loop starting at the function entry point (`funcAddr` in `RCX`).
* Evaluates each byte sequentially against the opcode `0xB8` (`mov eax, <imm32>`), which represents the standard x64 prologue assignment of the SSN into the `EAX` register.
* Enforces a 28-byte search ceiling to prevent reading beyond a safe 32-byte boundary when reading the 4-byte immediate value.

3. **Data Extraction:**
* Once `0xB8` is encountered, reads the subsequent 4 bytes (`[r8 + r9 + 1]`) to capture the full 32-bit SSN value into `EAX`.
* Locates the corresponding `syscall; ret` instruction gadget address within the export block.
* Formats and prints the extracted module name, target function, hex SSN, and gadget pointer to `stdout`.

---

## Compilation
Assemble the MASM routine and link it with the C driver using the Microsoft Visual C++ toolchain:

1. Assemble the scanning routine
```
ml64.exe /c syscalls.asm
```

2. Compile and link the driver executable
```
cl.exe syscallhunter.c syscalls.obj ..\includes\syscall-utils.c ..\includes\peb-eat-utils.c /Fe:syscallhunter.exe
```

## Usage

```
syscallhunter.exe <module_name> <function_name>
```

### Example

```
syscallhunter.exe ntdll.dll NtCreateThreadEx
```

**Output:**

```text
Module:   ntdll.dll
Function: NtCreateThreadEx
SSN:      0x00C9
Syscall:  0x00007FFB12345678
```