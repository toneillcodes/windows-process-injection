# Windows Process Injection
A collection of techniques for process injection on Windows
> [!CAUTION]
> Disclaimer: Intended only for use on systems that you are legally authorized to access.
## Fundamentals
A collection of examples intended to demonstrate the fundamentals and provide a base for more advanced techniques.  
* [injection-example-1.c](/fundamentals/injection-example-1.c): injecting calc.exe msfvenom shellcode into the current process 
* [injection-example-2.c](/fundamentals/injection-example-2.c): injecting calc.exe msfvenom shellcode into the current process, toggling the memory protection between RW and RWX
* [injection-example-3.c](/fundamentals/injection-example-3.c): injecting calc.exe msfvenom shellcode into a remote process, with memory protection toggling
* [injection-example-4.c](/fundamentals/injection-example-4.c): injecting calc.exe msfvenom shellcode into a remote process, with memory protection toggling and using dynamic function resolution

## Techniques
* [Dynamic Function Resolution](dynamic-function-resolution/README.md)
* [Module Stomping](module-stomping/README.md)
* [Walking the PEB and EAT](walking-peb-eat/README.md)
* [Direct Syscalls](direct-syscalls/README.md)
* [Indirect Syscalls](indirect-syscalls/README.md)
* [Thread Pool Injection](thread-pool-injection/README.md)

## Blog Posts
* [Process Injection Fundamentals](https://medium.com/@toneillcodes/windows-process-injection-fundamentals-00d43ee9ecad)
* [The Ministry of Silly Walks Presents: Walking the PEB](https://infosecwriteups.com/the-ministry-of-silly-walks-presents-walking-the-peb-e3c159eb3d30)
* [An Introduction To Module Stomping](https://medium.com/@toneillcodes/an-introduction-to-module-stomping-26238af76d43)
* [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
* [Hunting for Module Stomping Targets](https://medium.com/@toneillcodes/hunting-for-module-stomping-targets-1e9b8bb09766)
* [The Single-Primitive Write: WriteProcessMemory’s Hidden Page Flip](https://medium.com/@toneillcodes/the-single-primitive-write-writeprocessmemorys-hidden-page-flip-e5cb952bbfb2)
* [Don’t Be So Primitive: Evolving the Module Stomping Staging Chain](https://medium.com/@toneillcodes/dont-be-so-primitive-evolving-the-module-stomping-staging-chain-59fb96db50ac)