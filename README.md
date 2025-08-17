# Windows Process Injection
A collection of techniques for process injection on Windows
> [!CAUTION]
> Disclaimer: Intended only for use on systems that you are legally authorized to access.
## Fundamentals
A collection of examples intended to demonstrate the fundamentals and provide a base for more advanced techniques.  
* [injection-example-1.cpp](https://github.com/toneillcodes/windows-process-injection/blob/main/fundamentals/injection-example-1.cpp): injecting calc.exe msfvenom shellcode into the current process 
* [injection-example-2.cpp](https://github.com/toneillcodes/windows-process-injection/blob/main/fundamentals/injection-example-2.cpp): injecting calc.exe msfvenom shellcode into the current process, toggling the memory protection between RW and RWX
* [injection-example-3.cpp](https://github.com/toneillcodes/windows-process-injection/blob/main/fundamentals/injection-example-3.cpp): injecting calc.exe msfvenom shellcode into a remote process, with memory protection toggling
* [injection-example-4.cpp](https://github.com/toneillcodes/windows-process-injection/blob/main/fundamentals/injection-example-4.cpp): injecting calc.exe msfvenom shellcode into a remote process, with memory protection toggling and using dynamic function resolution
