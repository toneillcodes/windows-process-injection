# Editor Process Profiles

## Module Testing Table
| Process | Version Tested | Target Module | Target Function | Payload Size | Beacon Result | Notes |
|----|----|----|----|----|----|----|
| notepad++.exe | 8.9.3 | wininet.dll | InternetSetOptionW | 287930 | execution | Crashed on 'Open File' operation |
| notepad++.exe | 8.9.3 | wininet.dll | ShowCertificate | 287930 | success | Stable during normal browsing |
| sublime_text.exe | Build 4200 | wininet.dll | InternetSetOptionW | 287930 | success | Stable during typical usage |
| sublime_text.exe | Build 4200 | wininet.dll | ShowCertificate | 287930 | success | Stable during typical usage |
| sublime_text.exe | Build 4200 | wininet.dll | GopherCreateLocatorA | 287930 | success | Stable during typical usage |

## Modules to Avoid
* d3d10warp.dll

## Module Lists
### Notepad++ v8.9.3 64-bit
```
c:\Users\Administrator\Desktop\git\windows-process-injection\module-stomping>list-process-dlls.exe -p 9364
[+] Enumerating loaded modules:
--------------------------------------------------
[0x00007FF637270000] notepad++.exe
[0x00007FFAC6780000] ntdll.dll
[0x00007FFAC5AB0000] KERNEL32.DLL
[0x00007FFAC3B60000] KERNELBASE.dll
[0x00007FFAC1470000] apphelp.dll
[0x00007FFAB5AF0000] COMCTL32.dll
[0x00007FFAC4770000] msvcrt.dll
[0x00007FFAC6190000] SHLWAPI.dll
[0x00007FFAC5B80000] GDI32.dll
[0x00007FFAC4310000] win32u.dll
[0x00007FFAC3960000] ucrtbase.dll
[0x00007FFAC4340000] gdi32full.dll
[0x00007FFAC3AB0000] msvcp_win.dll
[0x00007FFAC45A0000] USER32.dll
[0x00007FFAC48D0000] SHELL32.dll
[0x00007FFAC3F60000] wintypes.dll
[0x00007FFAC54C0000] combase.dll
[0x00007FFAC6620000] RPCRT4.dll
[0x00007FFAA6FE0000] dbghelp.dll
[0x00007FFAC5BB0000] OLEAUT32.dll
[0x00007FFAB62E0000] VERSION.dll
[0x00007FFAC4190000] CRYPT32.dll
[0x00007FFAC38D0000] WINTRUST.dll
[0x00007FFAB4E50000] WININET.dll
[0x00007FFAC15C0000] UxTheme.dll
[0x00007FFAC1A50000] dwmapi.dll
[0x00007FFAAF240000] SensApi.dll
[0x00007FFAC6200000] COMDLG32.dll
[0x00007FFAC5C90000] shcore.dll
[0x00007FFAC58A0000] ADVAPI32.dll
[0x00007FFAC63D0000] sechost.dll
[0x00007FFAC6480000] ole32.dll
[0x00007FFAC5A70000] IMM32.dll
[0x00007FFAC2F20000] MSASN1.dll
[0x00007FFABA840000] windows.storage.dll
[0x00007FFAC60F0000] imagehlp.dll
[0x00007FFAC2EB0000] CRYPTSP.dll
[0x00007FFAC2700000] rsaenh.dll
[0x00007FFAC2ED0000] CRYPTBASE.dll
[0x00007FFAC4470000] bcryptPrimitives.dll
[0x00007FFAC37C0000] bcrypt.dll
[0x00007FFAC5D90000] MSCTF.dll
[0x00007FFAB9580000] TextShaping.dll
[0x00007FFAC1CF0000] kernel.appcore.dll
[0x00007FFAC6300000] clbcatq.dll
[0x00007FFAA25C0000] dataexchange.dll
[0x00007FFABBB30000] twinapi.appcore.dll
[0x00007FFAC02F0000] D2D1.DLL
[0x00007FFABFD50000] DWRITE.DLL
[0x00007FFABFFC0000] D3D11.DLL
[0x00007FFAC18F0000] dxgi.dll
[0x00007FFAC3750000] powrprof.dll
[0x00007FFAC3730000] UMPDC.dll
[0x00007FFAA80C0000] IconCodecService.dll
[0x00007FFABFB00000] WindowsCodecs.dll
[0x00007FFAB8960000] textinputframework.dll
[0x00007FFAA7840000] ComparePlugin.dll
[0x00007FFAABF60000] MSIMG32.dll
[0x00007FFAA6F70000] JSMinNPP.dll
[0x00007FFAA8A80000] mimeTools.dll
[0x00007FFAA6D20000] NppConverter.dll
[0x00007FFAA7380000] NppExport.dll
[0x00007FFA78D70000] XMLTools.dll
[0x00007FFA8CF80000] gdiplus.dll
[0x00007FFAA0420000] OLEACC.dll
[0x00007FFAB63C0000] WINMM.dll
[0x00007FFAADF70000] WINSPOOL.DRV
[0x00007FFAC3440000] cfgmgr32.dll
[0x00007FFAC1000000] CoreMessaging.dll
[0x00007FFABDE60000] CoreUIComponents.dll
[0x00007FFAC18A0000] dxcore.dll
[0x00007FFABEAE0000] directxdatabasehelper.dll
[0x00007FFABC140000] d3d10warp.dll
[0x00007FFABA1C0000] mscms.dll
[0x00007FFAB03B0000] icm32.dll
[0x00007FFABC710000] PROPSYS.dll
[0x00007FFAC37F0000] profapi.dll
[0x00007FFAB13C0000] edputil.dll
[0x00007FFABB480000] urlmon.dll
[0x00007FFABB1B0000] iertutil.dll
[0x00007FFABA810000] srvcli.dll
[0x00007FFAC21D0000] netutils.dll
[0x00007FFAB20F0000] Windows.StateRepositoryPS.dll
[0x00007FFAC2920000] SspiCli.dll
[0x00007FFAB7150000] virtdisk.dll
[0x00007FFAC2F90000] Wldp.dll

c:\Users\Administrator\Desktop\git\windows-process-injection\module-stomping>
```

### Sublime Text Build 4200 64-bit
```
c:\Users\Administrator\Desktop\git\windows-process-injection\module-stomping>list-process-dlls.exe -p 108
[+] Enumerating loaded modules:
--------------------------------------------------
[0x00007FF776250000] sublime_text.exe
[0x00007FFE35080000] ntdll.dll
[0x00007FFE32E20000] KERNEL32.DLL
[0x00007FFE32330000] KERNELBASE.dll
[0x00007FFE2FD30000] apphelp.dll
[0x00007FFE0F6E0000] AcGenral.dll
[0x00007FFE33EF0000] msvcrt.dll
[0x00007FFE33E40000] sechost.dll
[0x00007FFE344E0000] SHLWAPI.dll
[0x00007FFE32B10000] ucrtbase.dll
[0x00007FFE33540000] USER32.dll
[0x00007FFE32730000] win32u.dll
[0x00007FFE33510000] GDI32.dll
[0x00007FFE32CF0000] gdi32full.dll
[0x00007FFE32280000] msvcp_win.dll
[0x00007FFE34620000] ole32.dll
[0x00007FFE34150000] combase.dll
[0x00007FFE34F20000] RPCRT4.dll
[0x00007FFE34560000] advapi32.dll
[0x00007FFE34050000] shcore.dll
[0x00007FFE347C0000] SHELL32.dll
[0x00007FFE32820000] wintypes.dll
[0x00007FFE315A0000] USERENV.dll
[0x00007FFE22C10000] MPR.dll
[0x00007FFE31220000] SspiCli.dll
[0x00007FFE337F0000] IMM32.DLL
[0x00007FFE33410000] COMDLG32.dll
[0x00007FFE24080000] WININET.dll
[0x00007FFE243C0000] COMCTL32.dll
[0x00007FFE30250000] dwmapi.dll
[0x00007FFE013E0000] OPENGL32.dll
[0x00007FFE2FEF0000] UxTheme.dll
[0x00007FFE18A00000] GLU32.dll
[0x00007FFE2FFA0000] dxcore.dll
[0x00007FFE317D0000] CRYPTBASE.DLL
[0x00007FFE15240000] ninput.dll
[0x00007FFE33710000] OLEAUT32.dll
[0x00007FFE29560000] windows.storage.dll
[0x00007FFE33210000] MSCTF.dll
[0x00007FFE2E700000] dwrite.dll
[0x00007FFE321D0000] bcryptPrimitives.dll
[0x00007FFE305F0000] kernel.appcore.dll
[0x00007FFE33D30000] clbcatq.dll
[0x00007FFE175E0000] twinapi.dll
[0x00007FFE2AC60000] XmlLite.dll
[0x00007FFE310A0000] ntmarta.dll
[0x00007FFE285B0000] TextShaping.dll
[0x00007FFE141C0000] dataexchange.dll
[0x00007FFE2A5B0000] twinapi.appcore.dll
[0x00007FFE25800000] OneCoreUAPCommonProxyStub.dll
[0x00007FFE2F220000] dcomp.dll
[0x00007FFE2E3E0000] Microsoft.Internal.WarpPal.dll
[0x00007FFE27860000] textinputframework.dll
[0x00007FFE2F890000] CoreMessaging.dll
[0x00007FFE2CDF0000] CoreUIComponents.dll
[0x00007FFE29DD0000] iertutil.dll
[0x00007FFE29530000] srvcli.dll
[0x00007FFE30AD0000] netutils.dll
[0x00007FFE320F0000] profapi.dll
[0x00007FFE33390000] WS2_32.dll
[0x00007FFE20FB0000] ondemandconnroutehelper.dll
[0x00007FFE2A3F0000] WINHTTP.dll
[0x00007FFE314F0000] mswsock.dll
[0x00007FFE30B10000] IPHLPAPI.DLL
[0x00007FFE2FE30000] WINNSI.DLL
[0x00007FFE33200000] NSI.dll
[0x00007FFE2A0D0000] urlmon.dll
[0x00007FFE30B50000] DNSAPI.dll
[0x00007FFE27180000] rasadhlp.dll
[0x00007FFE28C60000] fwpuclnt.dll
[0x00007FFE30ED0000] schannel.DLL
[0x00007FFE32990000] CRYPT32.dll
[0x00007FFE31820000] MSASN1.dll
[0x00007FFE31DC0000] DPAPI.DLL
[0x00007FFE32C60000] WINTRUST.dll
[0x00007FFE317B0000] CRYPTSP.dll
[0x00007FFE31000000] rsaenh.dll
[0x00007FFE20B30000] cryptnet.dll
[0x00007FFE320C0000] bcrypt.dll
[0x00007FFE319D0000] ncrypt.dll
[0x00007FFE31980000] NTASN1.dll
[0x00007FFE20C70000] ncryptsslp.dll
[0x00007FFE2A2C0000] dhcpcsvc6.DLL
[0x00007FFE2A0A0000] dhcpcsvc.DLL
[0x00007FFE25460000] webio.dll
[0x00007FFE31560000] gpapi.dll
[0x00007FFE31D40000] CFGMGR32.dll
[0x00007FFE2A8E0000] propsys.dll
[0x00007FFDFDCE0000] DUI70.dll
[0x00007FFE0A130000] DUser.dll
[0x00007FFE119F0000] explorerframe.dll
[0x00007FFE11CB0000] oleacc.dll
[0x00007FFE2E400000] WindowsCodecs.dll
[0x00007FFE11240000] thumbcache.dll
[0x00007FFE28AC0000] Windows.Globalization.dll
[0x00007FFE26A40000] globinputhost.dll
[0x00007FFE2DA60000] Bcp47Langs.dll
[0x00007FFE1C440000] tiptsf.dll
[0x00007FFE208C0000] edputil.dll
[0x00007FFE1B540000] uiautomationcore.dll
[0x00007FFE31ED0000] sxs.dll
[0x00007FFE2A840000] atlthunk.dll
[0x00007FFE21E00000] StructuredQuery.dll
[0x00007FFE21B50000] icu.dll
[0x00007FFE0B450000] Windows.FileExplorer.Common.dll
[0x00007FFE2F9F0000] wtsapi32.dll
[0x00007FFE31F80000] WINSTA.dll
[0x00007FFE25320000] OneCoreCommonProxyStub.dll
[0x00007FFE1FE60000] Windows.System.Launcher.dll
[0x00007FFE246C0000] windows.staterepositorycore.dll
[0x00007FFE1FBC0000] Windows.Storage.Search.dll
[0x00007FFE1A720000] windowsudk.shellcommon.dll
[0x00007FFE2D440000] Windows.UI.dll
[0x00007FFE2AB00000] Windows.UI.Immersive.dll
[0x00007FFE33FA0000] coml2.dll
[0x00007FFE268E0000] LINKINFO.dll
[0x00007FFE09710000] p9np.dll
[0x00007FFE267D0000] drprov.dll
[0x00007FFE096E0000] ntlanman.dll
[0x00007FFE2A8A0000] wkscli.dll
[0x00007FFE1F730000] cscapi.dll
[0x00007FFE08F50000] NetworkExplorer.dll
[0x00007FFE128E0000] dlnashext.dll
[0x00007FFE09C40000] DevDispItemProvider.dll
[0x00007FFE10F20000] FileSyncShell64.dll
[0x00007FFE24340000] Secur32.dll
[0x00007FFE246A0000] VERSION.dll
[0x00007FFE13820000] EhStorShell.dll
[0x00007FFE33830000] SETUPAPI.dll
[0x00007FFE12800000] cscui.dll
[0x00007FFE27D20000] MMDevApi.dll
[0x00007FFE31D10000] DEVOBJ.dll
[0x00007FFE177D0000] rdpendp.dll
[0x00007FFE12070000] ntshrui.dll
[0x00007FFE2E640000] policymanager.dll
[0x00007FFE19E10000] WINMM.dll
[0x00007FFE23470000] SystemSettings.DataModel.dll
[0x00007FFE308B0000] slc.dll
[0x00007FFE1FB20000] Windows.Web.dll
[0x00007FFE10E90000] ActXPrxy.dll

c:\Users\Administrator\Desktop\git\windows-process-injection\module-stomping>
```

## AI Module Analysis
> [!CAUTION]
> The following section was generated by Gemini Pro and was not revised.

Here are the best candidates from your specific list to investigate next, categorized by their operational risk and stability profile:

### Tier 1: The Graphics & Rendering Infrastructure (Highest Stability)

These modules are responsible for drawing advanced layout interfaces, hardware acceleration, and imaging format parsing. If the user is simply typing raw text in Notepad++, the advanced export subsets of these modules are completely dark.

* **`c:\Windows\System32\d3d10warp.dll`** (`.text` size: `0x499e19` / ~4.6 MB)
* **High-Level Summary:** This is the Windows Advanced Rasterization Platform (WARP), a software-based implementation of Direct3D. It allows Windows to compute 3D graphics using the CPU when a dedicated GPU isn't available or fails.
* **Why it's a prime target:** Notepad++ is a flat 2D text editor; it does not intentionally call Direct3D software rasterization functions during standard operations. This gives you a massive, multi-megabyte executable code footprint that remains completely quiet, providing a huge runway for large arrays.

* **`c:\Windows\System32\d2d1.dll`** (`.text` size: `0x30eb70` / ~3.0 MB)
* **High-Level Summary:** The main engine for Microsoft Direct2D, a hardware-accelerated, immediate-mode 2D graphics API designed for text, geometry, and high-performance rendering.
* **Why it's worth checking:** While Scintilla (Notepad++'s core editing component) *can* utilize Direct2D for smoothing fonts, it only calls a very narrow subset of initialization functions. The majority of the layout geometric manipulation and transformation exports remain completely idle.

* **`c:\Windows\System32\WindowsCodecs.dll`** (`.text` size: `0x1a226c` / ~1.6 MB)
* **High-Level Summary:** The core subsystem for the Windows Imaging Component (WIC). It handles decoding, encoding, metadata extraction, and pixel format translations for raw image files (like JPEG, PNG, TIFF, or BMP).
* **Why it's worth checking:** Notepad++ is a text editor, not an image viewer. Unless you are dealing with a highly specialized custom plugin that handles heavy graphics rendering or complex image parsing within the canvas layout, this DLL’s image-processing pipelines are silent.

### Tier 2: Specialized Diagnostics & Utility (High Stealth)

These modules handle background diagnostic tasks, crash reporting, or advanced font metrics. Their functions are typically called on-demand rather than on a continuous execution loop.

* **`c:\Windows\System32\dbghelp.dll`** (`.text` size: `0x199bb0` / ~1.6 MB)
* **High-Level Summary:** The Windows Debug Help library. It provides development applications with the capabilities to parse executable images, walk call stacks, look up PDB symbol information, and generate minidumps.
* **Why it's a prime target:** This module is generally loaded as a passive dependency or pulled in by modern crash-reporting handlers. Under standard text-editing conditions, its symbol-parsing and debugging routines are entirely dormant.


* **`c:\Windows\System32\DWrite.dll`** (`.text` size: `0x192c3c` / ~1.5 MB)
* **High-Level Summary:** Microsoft DirectWrite, responsible for high-quality text rendering, resolution-independent font glyph manipulation, and advanced OpenType layout boundaries.
* **Why it's worth checking:** While it *is* used to calculate text metrics, it contains an extensive array of complex multi-language script layout, historical font processing, and fallback glyph mechanics. Targeting its secondary multi-byte layout parameters provides a safe fit.

### Tier 3: Avoid / High-Risk Targets (Red Flags)

These modules should be **excluded** from your target list because they are heavily utilized by Notepad++'s core UI threads, window frames, or basic file input/output logic. Stomping them will result in an immediate process crash or an EDR alert.

* **`combase.dll` / `ole32.dll`:** Handles COM/OLE object communications, which Notepad++ relies on heavily for shell extensions, Drag-and-Drop operations, and standard Windows integration.
* **`shell32.dll` / `windows.storage.dll`:** Controls file browsing, right-click context menus, path resolving, and the Open/Save dialog boxes. Overwriting these will cause the process to vanish the second a user tries to open a file.
* **`user32.dll` / `KernelBase.dll` / `ntdll.dll`:** Core operating system primitives. The thread scheduler, window message handlers, and memory managers strike these constantly. **Never stomp these.**