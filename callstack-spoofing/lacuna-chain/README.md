
```
ODPC-LAB-DEVBOX 07/07/2026 02:19:54
PS C:\dev\LACUNA-Chain > .\lacuna.exe
Lacuna-Chain Ghost Frames: Forging Plausible Call Stacks from .pdata Lacunae
Mohamed Alzhrani (0xmaz), 2026

usage:
  lacuna.exe scan
  lacuna.exe verify
  lacuna.exe inject <pid> <sc.bin>
ODPC-LAB-DEVBOX 07/07/2026 02:19:57
PS C:\dev\LACUNA-Chain >

ODPC-LAB-DEVBOX 07/07/2026 02:19:57
PS C:\dev\LACUNA-Chain > .\lacuna.exe scan
Lacuna-Chain Ghost Frames: Forging Plausible Call Stacks from .pdata Lacunae
Mohamed Alzhrani (0xmaz), 2026


ntdll.dll  —  512 ghost regions
  7ffd98023130–7ffd98023180    80B  LdrLoadDll                      dist=247600
  7ffd98023527–7ffd980235f8   209B  LdrLoadDll                      dist=246456
  7ffd9802715b–7ffd980271a0    69B  LdrLoadDll                      dist=231184
  7ffd98027242–7ffd980272a4    98B  LdrLoadDll                      dist=230924
  7ffd980278c5–7ffd98027900    59B  LdrLoadDll                      dist=229296
  7ffd98027ccd–7ffd98027d10    67B  LdrLoadDll                      dist=228256
  7ffd980294aa–7ffd98029500    86B  LdrLoadDll                      dist=222128
  7ffd98030ca4–7ffd98030cd0    44B  LdrLoadDll                      dist=191456
  7ffd98037fe8–7ffd98038010    40B  LdrLoadDll                      dist=161952
  7ffd98046748–7ffd98046780    56B  LdrLoadDll                      dist=102704
  7ffd9804c8a2–7ffd9804c8d0    46B  LdrLoadDll                      dist=77792
  7ffd98051d86–7ffd98051dd0    74B  LdrLoadDll                      dist=56032
  7ffd98052179–7ffd98052284   267B  LdrLoadDll                      dist=54828
  7ffd980523ea–7ffd98052480   150B  LdrLoadDll                      dist=54320
  7ffd98052acb–7ffd98052b50   133B  LdrLoadDll                      dist=52576
  7ffd9805398e–7ffd980539cc    62B  LdrLoadDll                      dist=48868
  7ffd98053dc5–7ffd98053de0    27B  LdrLoadDll                      dist=47824
  7ffd98053e42–7ffd98053f40   254B  LdrLoadDll                      dist=47472
  7ffd98054216–7ffd98054240    42B  LdrLoadDll                      dist=46704
  7ffd980554b0–7ffd98055500    80B  LdrLoadDll                      dist=41904
  7ffd980557ed–7ffd98055848    91B  LdrLoadDll                      dist=41064
  7ffd9805596e–7ffd980559b4    70B  LdrLoadDll                      dist=40700
  7ffd98055a54–7ffd98055b20   204B  LdrLoadDll                      dist=40336
  7ffd980562e1–7ffd98056330    79B  LdrLoadDll                      dist=38272
  7ffd98057f62–7ffd98057fe0   126B  LdrLoadDll                      dist=30928
  ... 487 more
  ghost gadgets (jmp [rbx]):
    7ffd980e5039  ntdll.dll ghost @7ffd980e502d

kernelbase.dll  —  512 ghost regions
  7ffd95373a65–7ffd95373b20   187B  WriteProcessMemory              dist=484096
  7ffd9537452d–7ffd95374560    51B  WriteProcessMemory              dist=481472
  7ffd9537681c–7ffd9537689c   128B  WriteProcessMemory              dist=472452
  7ffd95378e9d–7ffd95378eb8    27B  WriteProcessMemory              dist=462696
  7ffd9537aaaa–7ffd9537ab20   118B  WriteProcessMemory              dist=455424
  7ffd9537b8eb–7ffd9537b9a0   181B  WriteProcessMemory              dist=451712
  7ffd9537be43–7ffd9537be84    65B  WriteProcessMemory              dist=450460
  7ffd9537f0c0–7ffd9537f0e4    36B  WriteProcessMemory              dist=437564
  7ffd9537fa5a–7ffd9537fa84    42B  WriteProcessMemory              dist=435100
  7ffd9537fbc1–7ffd9537fbe8    39B  WriteProcessMemory              dist=434744
  7ffd9537fd3b–7ffd9537fdb8   125B  WriteProcessMemory              dist=434280
  7ffd95383085–7ffd953830b4    47B  WriteProcessMemory              dist=421228
  7ffd95386503–7ffd953865d0   205B  WriteProcessMemory              dist=407632
  7ffd9538cc52–7ffd9538cc88    54B  WriteProcessMemory              dist=381336
  7ffd9538e636–7ffd9538e664    46B  WriteProcessMemory              dist=374716
  7ffd95391827–7ffd9539185c    53B  WriteProcessMemory              dist=361924
  7ffd95394480–7ffd953944b0    48B  WriteProcessMemory              dist=350576
  7ffd9539c740–7ffd9539c770    48B  WriteProcessMemory              dist=317104
  7ffd953a108e–7ffd953a10c0    50B  WriteProcessMemory              dist=298336
  7ffd953a1468–7ffd953a14f0   136B  WriteProcessMemory              dist=297264
  7ffd953a1b0d–7ffd953a1b98   139B  WriteProcessMemory              dist=295560
  7ffd953a1dff–7ffd953a1f44   325B  WriteProcessMemory              dist=294620
  7ffd953a321c–7ffd953a3260    68B  WriteProcessMemory              dist=289728
  7ffd953a3c67–7ffd953a3ca0    57B  WriteProcessMemory              dist=287104
  7ffd953b55f3–7ffd953b56c0   205B  WriteProcessMemory              dist=214880
  ... 487 more
  ghost gadgets (jmp [rbx]):
    7ffd954a9882  kernelbase.dll ghost @7ffd954a9854
    7ffd954f196d  kernelbase.dll ghost @7ffd954eed28

  wow64.dll  not loaded

  win32u.dll  not loaded
ODPC-LAB-DEVBOX 07/07/2026 02:19:59
PS C:\dev\LACUNA-Chain >
```