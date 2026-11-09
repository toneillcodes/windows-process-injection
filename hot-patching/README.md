# Hot Patching (Inline Function Hooking)

## Summary

Hot Patching or 'Inline Function Hooking' is a runtime modification technique where the entry point of a loaded function in memory is overwritten with an unconditional jump (`JMP`) instruction. This redirects control flow to an alternate routine without needing modify the binary.

| Component | Description |
| --- | --- |
| **Technique** | Modifying function prologues in memory using a 5-byte relative near jump (`0xE9`). |
| **Tactical Goal** | **Runtime Control Flow Redirection:** Enables live bug fixes, function detouring, instrumentation, or API monitoring without altering binaries on disk. |
| **Stealth / Impact** | **Low to Moderate.** While functional in local memory, overwriting execution memory alters the `.text` section hash and creates an in-memory modification that integrity checkers and memory scanners easily detect. |

---

## Technical Workflow

1. **Relative Offset Calculation:**
* Computes the distance between the replacement routine (`FixedFunction`) and the original routine (`targetFunction`).
* Uses the x86/x64 relative jump displacement formula:
$$\text{Relative Offset} = \text{Destination Address} - \text{Current Address} - 5$$

* The subtractor of $5$ accounts for the length of the `JMP rel32` instruction itself, since the CPU advances the instruction pointer (`EIP`/`RIP`) before taking the jump.
2. **Payload Construction:**
* Prepares a 5-byte sequence: the `0xE9` opcode followed by the 4-byte (32-bit) signed relative offset.
3. **Memory Unprotection:**
* Calls `VirtualProtect` to transition the target memory region from its default protection (typically `PAGE_EXECUTE_READ`) to `PAGE_EXECUTE_READWRITE`, allowing write access to executable code.
4. **Instruction Overwrite & Restoration:**
* Uses `memcpy` to write the 5-byte patch over the first instructions of `targetFunction`.
* Invokes `VirtualProtect` once more to restore the original memory protection attributes, leaving the hook active.

---

## Build Instructions

Compile using the Microsoft Visual C++ compiler (`cl.exe`):

```
cl.exe hot-patch.cpp /Fe:hot-patch.exe
```

---

## Considerations & Limitations

* **32-Bit Displacement Limitation in x64:** The `0xE9` jump instruction uses a signed 32-bit relative offset, restricting jump targets to within $\pm 2\text{ GB}$ of the source function. In 64-bit processes where memory allocations can exceed 2 GB, a 14-byte absolute jump (e.g., `jmp [rip+0]`) or a trampoline/trampoline-relay is typically required.
* **Instruction Boundary Integrity:** Overwriting 5 bytes assumes the original function entry point contains at least 5 bytes of complete instructions. In variable-length instruction architectures (x86/x64), overwriting mid-instruction without disassembling the prologue can corrupt neighboring instructions if the function is ever called at sub-entry offsets.
* **Instruction Cache Consistency:** For high-reliability environments, issuing `FlushInstructionCache` immediately after modifying code pages ensures other CPU cores do not execute stale instructions from their L1 instruction cache.