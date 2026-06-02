# Snippets

## Index
* [bintoc.rb](bintoc.rb): Ruby to convert a raw binary file to C array style shellcode by 0xNinjaCyclone
* [bintoc.py](bintoc.py): Python to convert a raw binary file to C array style shellcode (ported from 0xNinjaCyclone's Ruby script)
* [bintocsharp.py](bintocsharp.py): Python to convert a raw binary file to C# array style shellcode
* [getpid.cpp](getpid.cpp): FindPidByName implementation and example
* [syscallhunter.cpp](syscallhunter.cpp)
* [syscalls.asm](syscalls.asm)

## Useful PowerShell
### Finding Microsoft Edge
```
Get-CimInstance Win32_Process -Filter "Name = 'msedge.exe' AND CommandLine LIKE '%msedge.exe%'" | 
    Where-Object { $_.CommandLine -notlike '*--type=*' } |
    Select-Object ProcessId, CommandLine | 
    Format-List
```

```
Get-CimInstance Win32_Process -Filter "Name = 'msedge.exe' AND CommandLine LIKE '%msedge.exe%'" | 
    Where-Object { $_.CommandLine -notlike '*--type=*' } |
    Select-Object ProcessId	
```