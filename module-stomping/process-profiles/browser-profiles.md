# Browser Process Profiles

## Finding Browser Processes
List processes and parent PIDs:
```
Get-CimInstance Win32_Process -Filter "Name='firefox.exe'" | Select-Object ProcessId, ParentProcessId, CommandLine
```

Ignore workers:
```
Get-CimInstance Win32_Process -Filter "Name = 'msedge.exe' AND CommandLine LIKE '%msedge.exe%'" | 
    Where-Object { $_.CommandLine -notlike '*--type=*' } |
    Select-Object ProcessId, CommandLine | 
    Format-List
```

Process ID only:
```
Get-CimInstance Win32_Process -Filter "Name = 'msedge.exe' AND CommandLine LIKE '%msedge.exe%'" | 
    Where-Object { $_.CommandLine -notlike '*--type=*' } |
    Select-Object ProcessId	
```

## Module Testing Table
| Browser | Version Tested | Target Module | Target Function | Payload Size | Beacon Result | Notes |
|----|----|----|----|----|----|----|
| msedge | 148.0.3967.96 | ffmpeg.dll | avcodec_open2 | 287930 | success | Stable during normal browsing |
| chrome | 148.0.7778.218 | ExplorerFrame.dll | DllCanUnloadNow | 287930 | success | Stable during normal browsing, crashed on file download |
| firefox | 151.0.3 | ExplorerFrame.dll | DllCanUnloadNow | 287930 | success | Stable during normal browsing, crashed on file download |

## Module Lists
### Chrome
#### Version 148.0.7778.218 (Official Build) (64-bit)
```
windows-process-injection\module-stomping > .\list-process-dlls.exe -p 5408
[+] Enumerating loaded modules:
--------------------------------------------------
[0x00007FF6DFB90000] chrome.exe
[0x00007FFDE4E80000] ntdll.dll
[0x00007FFDE41C0000] KERNEL32.DLL
[0x00007FFDE25B0000] KERNELBASE.dll
[0x00007FFDD4540000] VERSION.dll
[0x00007FFDE3720000] msvcrt.dll
[0x00007FFD915C0000] chrome_elf.dll
[0x00007FFDE2100000] bcryptprimitives.dll
[0x00007FFDE3FA0000] ADVAPI32.dll
[0x00007FFDE3990000] sechost.dll
[0x00007FFDE4C20000] RPCRT4.dll
[0x00007FFDE0EA0000] ntmarta.dll
[0x00007FFDE2260000] ucrtbase.dll
[0x00007FFDE2EA0000] SHELL32.dll
[0x00007FFDE21B0000] msvcp_win.dll
[0x00007FFDE3DD0000] USER32.dll
[0x00007FFDE29B0000] win32u.dll
[0x00007FFDE3600000] GDI32.dll
[0x00007FFDE1FD0000] gdi32full.dll
[0x00007FFDE23B0000] wintypes.dll
[0x00007FFDE3A40000] combase.dll
[0x00007FFDE4BD0000] IMM32.DLL
[0x00007FFDD9470000] windows.storage.dll
[0x00007FFDE4D40000] SHCORE.dll
[0x00007FFDE3630000] shlwapi.dll
[0x00007FFD75550000] chrome.dll
[0x00007FFDE4140000] WS2_32.dll
[0x00007FFDE29E0000] CRYPT32.dll
[0x00007FFDCE870000] WINMM.dll
[0x00007FFDDE440000] DWrite.dll
[0x00007FFDE1BC0000] DPAPI.DLL
[0x00007FFDE1D80000] WINSTA.dll
[0x00007FFDE2D30000] MSCTF.dll
[0x00007FFDDFCC0000] uxtheme.dll
[0x00007FFDE13A0000] USERENV.dll
[0x00007FFDE1360000] gpapi.dll
[0x00007FFDD8E50000] wkscli.dll
[0x00007FFDE08D0000] netutils.dll
[0x00007FFDE1EF0000] profapi.dll
[0x00007FFDE1620000] MSASN1.dll
[0x00007FFDE4A20000] ole32.dll
[0x00007FFDE1E50000] powrprof.dll
[0x00007FFDE1E30000] UMPDC.dll
[0x00007FFDE03F0000] kernel.appcore.dll
[0x00007FFDE3830000] OLEAUT32.dll
[0x00007FFDD4080000] COMCTL32.dll
[0x00007FFDE15D0000] CRYPTBASE.dll
[0x00007FFDC19B0000] nlansp_c.dll
[0x00007FFDE0910000] IPHLPAPI.DLL
[0x00007FFDE4BC0000] NSI.dll
[0x00007FFDDA230000] dhcpcsvc6.DLL
[0x00007FFDD8FA0000] dhcpcsvc.DLL
[0x00007FFDE0950000] DNSAPI.dll
[0x00007FFDE4080000] clbcatq.dll
[0x00007FFDD7300000] textinputframework.dll
[0x00007FFDDD2B0000] Windows.UI.dll
[0x00007FFDD83F0000] MMDevApi.dll
[0x00007FFDE1B70000] DEVOBJ.dll
[0x00007FFDE1B10000] cfgmgr32.dll
[0x00007FFDD8C30000] mscms.dll
[0x00007FFDDF190000] WTSAPI32.dll
[0x00007FFDE1020000] SspiCli.dll
[0x00007FFDCAD10000] rdpendp.dll
[0x00007FFDD9340000] WINHTTP.dll
[0x00007FFDDAE80000] Windows.UI.Immersive.dll
[0x00007FFDC6D10000] wpnapps.dll
[0x00007FFDE0770000] FirewallAPI.dll
[0x00007FFDE06E0000] fwbase.dll
[0x00007FFDBC350000] CryptoWinRT.dll
[0x00007FFDAC380000] cryptngc.dll
[0x00007FFDE17D0000] ncrypt.dll
[0x00007FFDE1780000] NTASN1.dll
[0x00007FFDE1EC0000] bcrypt.dll
[0x00007FFDC99E0000] ngcksp.dll
[0x00007FFDD7450000] InputHost.dll
[0x00007FFDDF600000] CoreMessaging.dll
[0x00007FFDDA700000] PROPSYS.dll
[0x00007FFDE0150000] dwmapi.dll
[0x00007FFDD5210000] OneCoreUAPCommonProxyStub.dll
[0x00007FFDC8360000] dataexchange.dll
[0x00007FFDDA4B0000] twinapi.appcore.dll
[0x00007FFD74730000] Windows.Media.dll
[0x00007FFDC0470000] OLEACC.dll
[0x00007FFDD71F0000] directmanipulation.dll
[0x00007FFDDB880000] CoreUIComponents.dll
[0x00007FFDE15B0000] CRYPTSP.dll
[0x00007FFDE0E00000] rsaenh.dll
[0x00007FFDCA1B0000] twinapi.dll
[0x00007FFDDB400000] XmlLite.dll
[0x00007FFDD5B30000] LINKINFO.dll
[0x00007FFDCF050000] Windows.Networking.Connectivity.dll
[0x00007FFDD81C0000] npmproxy.dll
[0x00007FFDE1CD0000] sxs.dll
[0x00007FFDCFC80000] Windows.System.Launcher.dll
[0x00007FFDD3B30000] windows.staterepositorycore.dll
[0x00007FFDCF830000] Windows.ApplicationModel.dll
[0x00007FFDD5D10000] windows.internal.shell.broker.dll
[0x00007FFDD5870000] OneCoreCommonProxyStub.dll
[0x00007FFDCADB0000] CapabilityAccessManagerClient.dll
[0x00007FFDBECF0000] PCShellCommonProxyStub.dll
[0x00007FFDC8780000] usermgrproxy.dll
[0x00007FFDD7060000] usermgrcli.dll
[0x00007FFDC01B0000] explorerframe.dll
[0x00007FFDE4540000] SETUPAPI.dll
[0x00007FFDD18D0000] pdh.dll
[0x00007FFDE2520000] WINTRUST.dll
[0x00007FFDD44F0000] Secur32.dll
[0x00007FFDDD410000] netprofm.dll
[0x00007FFDD0BF0000] perfos.dll
[0x00007FFDDFC80000] pfclient.dll
[0x00007FFD71CB0000] optimization_guide_internal.dll
[0x00007FFDE12F0000] mswsock.dll
[0x00007FFDC9140000] PCPKsp.dll
[0x00007FFDCD210000] tbs.dll
[0x00007FFDD0920000] ncryptprov.dll
[0x00007FFDE0870000] profext.dll
[0x00007FFDD8D60000] taskschd.dll
[0x00007FFD912C0000] sapi.dll
[0x00007FFDCA050000] BitsProxy.dll
[0x00007FFDCF7B0000] NETAPI32.dll
[0x00007FFDE08B0000] SAMCLI.DLL
[0x00007FFDE08E0000] SAMLIB.dll
[0x00007FFDC93A0000] Windows.Security.Credentials.UI.UserConsentVerifier.dll
[0x00007FFDD35D0000] webauthn.dll
[0x00007FFDB8C20000] MsSpellCheckingFacility.dll
[0x00007FFDDD860000] Bcp47Langs.dll
windows-process-injection\module-stomping >
```

### Edge
#### Version 148.0.3967.96 (Official build) (64-bit)
```
windows-process-injection\module-stomping > .\list-process-dlls.exe -p 3896
[+] Enumerating loaded modules:
--------------------------------------------------
[0x00007FF6360C0000] msedge.exe
[0x00007FFDE4E80000] ntdll.dll
[0x00007FFDE41C0000] KERNEL32.DLL
[0x00007FFDE25B0000] KERNELBASE.dll
[0x00007FFDC4C10000] msedge_elf.dll
[0x00007FFDE3A40000] combase.dll
[0x00007FFDE2260000] ucrtbase.dll
[0x00007FFDE4C20000] RPCRT4.dll
[0x00007FFDE2100000] bcryptprimitives.dll
[0x00007FFDD4540000] version.dll
[0x00007FFDE3720000] msvcrt.dll
[0x00007FFDE3FA0000] ADVAPI32.dll
[0x00007FFDE3990000] sechost.dll
[0x00007FFDE2EA0000] SHELL32.dll
[0x00007FFDE21B0000] msvcp_win.dll
[0x00007FFDE3DD0000] USER32.dll
[0x00007FFDE29B0000] win32u.dll
[0x00007FFDE3600000] GDI32.dll
[0x00007FFDE1FD0000] gdi32full.dll
[0x00007FFDE23B0000] wintypes.dll
[0x00007FFDE4BD0000] IMM32.DLL
[0x00007FFDD9470000] windows.storage.dll
[0x00007FFDE4D40000] SHCORE.dll
[0x00007FFDE3630000] shlwapi.dll
[0x00007FFDE0EA0000] ntmarta.dll
[0x00007FFD94A10000] msedge.dll
[0x00007FFDCE870000] WINMM.dll
[0x00007FFDE1D80000] WINSTA.dll
[0x00007FFDE2D30000] MSCTF.dll
[0x00007FFDDFCC0000] uxtheme.dll
[0x00007FFDE4A20000] ole32.dll
[0x00007FFDE03F0000] kernel.appcore.dll
[0x00007FFDE4080000] clbcatq.dll
[0x00007FFDD03F0000] Windows.System.Profile.PlatformDiagnosticsAndUsageDataSettings.dll
[0x00007FFDCF810000] DiagnosticDataSettings.dll
[0x00007FFDCF7D0000] coreprivacysettingsstore.dll
[0x00007FFDE13A0000] USERENV.dll
[0x00007FFDE1360000] gpapi.dll
[0x00007FFDD8E50000] wkscli.dll
[0x00007FFDE08D0000] netutils.dll
[0x00007FFDD5B50000] AssignedAccessRuntime.dll
[0x00007FFDE1E50000] powrprof.dll
[0x00007FFDE1E30000] UMPDC.dll
[0x00007FFDCF830000] Windows.ApplicationModel.dll
[0x00007FFDE3830000] OLEAUT32.dll
[0x00007FFDE1EC0000] bcrypt.dll
[0x00007FFDBC350000] CryptoWinRT.dll
[0x00007FFDDE440000] DWrite.dll
[0x00007FFDDA4B0000] twinapi.appcore.dll
[0x00007FFDE4140000] WS2_32.dll
[0x00007FFDCA1B0000] twinapi.dll
[0x00007FFDDB400000] XmlLite.dll
[0x00007FFDD4080000] COMCTL32.dll
[0x00007FFDE29E0000] CRYPT32.dll
[0x00007FFDE1BC0000] DPAPI.dll
[0x00007FFDE15D0000] CRYPTBASE.dll
[0x00007FFDC19B0000] nlansp_c.dll
[0x00007FFDE0910000] IPHLPAPI.DLL
[0x00007FFDE4BC0000] NSI.dll
[0x00007FFDDA230000] dhcpcsvc6.DLL
[0x00007FFDD8FA0000] dhcpcsvc.DLL
[0x00007FFDE0950000] DNSAPI.dll
[0x00007FFDD7300000] textinputframework.dll
[0x00007FFDDD2B0000] Windows.UI.dll
[0x00007FFDE1EF0000] profapi.dll
[0x00007FFDDF190000] WTSAPI32.dll
[0x00007FFDE1020000] SspiCli.dll
[0x00007FFDE1B10000] cfgmgr32.dll
[0x00007FFDD8C30000] mscms.dll
[0x00007FFDD9340000] WINHTTP.dll
[0x00007FFDC1B50000] oneauth.dll
[0x00007FFDD44F0000] Secur32.dll
[0x00007FFDDAE80000] Windows.UI.Immersive.dll
[0x00007FFDD3B30000] windows.staterepositorycore.dll
[0x00007FFDDF730000] policymanager.dll
[0x00007FFDDA700000] PROPSYS.dll
[0x00007FFDCFC80000] Windows.System.Launcher.dll
[0x00007FFDD5B30000] LINKINFO.dll
[0x00007FFDE0150000] dwmapi.dll
[0x00007FFDC8360000] dataexchange.dll
[0x00007FFDD7450000] InputHost.dll
[0x00007FFDDF600000] CoreMessaging.dll
[0x00007FFDD0070000] Windows.System.Profile.RetailInfo.dll
[0x00007FFDC0470000] OLEACC.dll
[0x00007FFDD71F0000] directmanipulation.dll
[0x00007FFDDB880000] CoreUIComponents.dll
[0x00007FFDE1620000] MSASN1.dll
[0x00007FFDE15B0000] CRYPTSP.dll
[0x00007FFDE0E00000] rsaenh.dll
[0x00007FFDC8DE0000] Windows.Security.Authentication.Web.Core.dll
[0x00007FFDD9D70000] iertutil.dll
[0x00007FFDDA3A0000] srvcli.dll
[0x00007FFDCD230000] well_known_domains.dll
[0x00007FFDD0050000] domain_actions.dll
[0x00007FFDCFE40000] VCRUNTIME140.dll
[0x00007FFDC6D10000] wpnapps.dll
[0x00007FFDD5D10000] windows.internal.shell.broker.dll
[0x00007FFDCE150000] wofutil.dll
[0x00007FFDD5870000] OneCoreCommonProxyStub.dll
[0x00007FFDD5210000] OneCoreUAPCommonProxyStub.dll
[0x00007FFDC9DF0000] vaultcli.dll
[0x00007FFDCF910000] Windows.Web.dll
[0x00007FFDBECF0000] PCShellCommonProxyStub.dll
[0x00007FFDD00B0000] aadWamExtension.dll
[0x00007FFDE1CD0000] sxs.dll
[0x00007FFDCFEF0000] MicrosoftAccountWAMExtension.dll
[0x00007FFDBEEF0000] Windows.Internal.UI.Shell.WindowTabManager.dll
[0x00007FFDCD560000] clipc.dll
[0x00007FFDBF780000] ShellCommonCommonProxyStub.dll
[0x00007FFDE4540000] SETUPAPI.dll
[0x00007FFDE1B70000] DEVOBJ.dll
[0x00007FFDE2520000] WINTRUST.dll
[0x00007FFDDD410000] netprofm.dll
[0x00007FFD91880000] telclient.dll
[0x00007FFDA9630000] oneds.dll
[0x00007FFDCD150000] Windows.Devices.Enumeration.dll
[0x00007FFDA9E00000] ffmpeg.dll
[0x00007FFDCADB0000] CapabilityAccessManagerClient.dll
[0x00007FFDE0770000] FirewallAPI.dll
[0x00007FFDE06E0000] fwbase.dll
[0x00007FFDCE6A0000] Geolocation.dll
[0x00007FFDDA3D0000] LocationFrameworkPS.dll
[0x00007FFDCCCB0000] microsoft_shell_integration.dll
[0x00007FFDDFB00000] apphelp.dll
[0x00007FFDC6E70000] appresolver.dll
[0x00007FFDD1860000] windows.staterepositoryclient.dll
[0x00007FFDCAA20000] capauthz.dll
[0x00007FFDD6B30000] AppXDeploymentClient.dll
[0x00007FFDE42A0000] imagehlp.dll
[0x00007FFDCF050000] Windows.Networking.Connectivity.dll
[0x00007FFDD81C0000] npmproxy.dll
[0x00007FFDCF7B0000] NETAPI32.dll
[0x00007FFDC8780000] usermgrproxy.dll
[0x00007FFDD7060000] usermgrcli.dll
[0x00007FFDE17D0000] ncrypt.dll
[0x00007FFDE1780000] NTASN1.dll
[0x00007FFDC9140000] PCPKsp.dll
[0x00007FFDCD210000] tbs.dll
[0x00007FFDD0920000] ncryptprov.dll
[0x00007FFDE12F0000] mswsock.dll
[0x00007FFDCB640000] psmachine_64.dll
[0x00007FFDD7080000] DSREG.DLL
[0x00007FFDD91F0000] wevtapi.dll
[0x00007FFDB8F50000] Windows.System.UserProfile.DiagnosticsSettings.dll
[0x00007FFDE06B0000] slc.dll
[0x00007FFDBFAC0000] SPPC.DLL
[0x00007FFDCAE60000] slwga.dll
[0x00007FFDCCC90000] Windows.System.Diagnostics.Telemetry.PlatformTelemetryClient.dll
[0x00007FFDCA050000] BitsProxy.dll
windows-process-injection\module-stomping >
```
### Firefox
#### 151.0.3 (64-bit)
```
windows-process-injection\module-stomping > .\list-process-dlls.exe -p 1772
[+] Enumerating loaded modules:
--------------------------------------------------
[0x00007FF618B70000] firefox.exe
[0x00007FFDE4E80000] ntdll.dll
[0x00007FFDE41C0000] KERNEL32.DLL
[0x00007FFDE25B0000] KERNELBASE.dll
[0x00007FFDE3630000] SHLWAPI.dll
[0x00007FFDE2260000] ucrtbase.dll
[0x00007FFDC1A70000] mozglue.dll
[0x00007FFDE29E0000] CRYPT32.dll
[0x00007FFDC19E0000] MSVCP140.dll
[0x00007FFDC29A0000] VCRUNTIME140.dll
[0x00007FFDC9630000] VCRUNTIME140_1.dll
[0x00007FFDE1EC0000] bcrypt.dll
[0x00007FFDE3990000] sechost.dll
[0x00007FFDE15D0000] CRYPTBASE.dll
[0x00007FFDE2100000] bcryptPrimitives.dll
[0x00007FFDE3FA0000] ADVAPI32.dll
[0x00007FFDE3720000] msvcrt.dll
[0x00007FFDE4C20000] RPCRT4.dll
[0x00007FFDE3DD0000] user32.dll
[0x00007FFDE29B0000] win32u.dll
[0x00007FFDE3600000] GDI32.dll
[0x00007FFDE1FD0000] gdi32full.dll
[0x00007FFDE21B0000] msvcp_win.dll
[0x00007FFDE4BD0000] IMM32.DLL
[0x00007FFDE3A40000] combase.dll
[0x00007FFDE03F0000] kernel.appcore.dll
[0x00007FFDDFCC0000] uxtheme.dll
[0x00007FFDE0EA0000] ntmarta.dll
[0x00007FFDE3830000] OLEAUT32.dll
[0x00007FFDE2EA0000] shell32.DLL
[0x00007FFDE23B0000] wintypes.dll
[0x00007FFDD9470000] windows.storage.dll
[0x00007FFDE4D40000] SHCORE.dll
[0x00007FFDE4A20000] ole32.DLL
[0x00007FFDC1310000] nss3.dll
[0x00007FFDE4140000] WS2_32.dll
[0x00007FFDC8350000] WSOCK32.dll
[0x00007FFDB7680000] gkcodecs.dll
[0x00007FFDC2970000] lgpllibs.dll
[0x00007FFDAD100000] xul.dll
[0x00007FFDE2520000] WINTRUST.dll
[0x00007FFDE1B10000] CFGMGR32.dll
[0x00007FFDDD7E0000] ktmw32.dll
[0x00007FFDDA700000] PROPSYS.dll
[0x00007FFDD4540000] VERSION.dll
[0x00007FFDE17D0000] ncrypt.dll
[0x00007FFDE1620000] MSASN1.dll
[0x00007FFDE1780000] NTASN1.dll
[0x00007FFDE1D80000] WINSTA.dll
[0x00007FFDE2D30000] MSCTF.dll
[0x00007FFDE2C20000] psapi.dll
[0x00007FFDDE440000] dwrite.dll
[0x00007FFDCD2D0000] dbghelp.dll
[0x00007FFDCFE00000] dbgcore.DLL
[0x00007FFDE1EF0000] profapi.dll
[0x00007FFDCE870000] WINMM.dll
[0x00007FFDC2950000] napinsp.dll
[0x00007FFDE4080000] clbcatq.dll
[0x00007FFDDD2B0000] Windows.UI.dll
[0x00007FFDDD410000] netprofm.dll
[0x00007FFDE12F0000] mswsock.dll
[0x00007FFDE0950000] DNSAPI.dll
[0x00007FFDE0910000] IPHLPAPI.DLL
[0x00007FFDE4BC0000] NSI.dll
[0x00007FFDC19B0000] nlansp_c.dll
[0x00007FFDDAE80000] Windows.UI.Immersive.dll
[0x00007FFDD81C0000] npmproxy.dll
[0x00007FFDC2930000] wshbth.dll
[0x00007FFDC1990000] winrnr.dll
[0x00007FFDDA4B0000] twinapi.appcore.dll
[0x00007FFDDFC00000] WINNSI.DLL
[0x00007FFDDA230000] dhcpcsvc6.DLL
[0x00007FFDD8FA0000] dhcpcsvc.DLL
[0x00007FFDCA1B0000] twinapi.dll
[0x00007FFDDB400000] XmlLite.dll
[0x00007FFDE0150000] dwmapi.dll
[0x00007FFDC1890000] Microsoft.Internal.FrameworkUdk.dll
[0x00007FFDDD860000] Bcp47Langs.dll
[0x00007FFDDF600000] CoreMessaging.dll
[0x00007FFDDEF60000] dcomp.dll
[0x00007FFDDE1E0000] Microsoft.Internal.WarpPal.dll
[0x00007FFDC1260000] Microsoft.Internal.FrameworkUdk.System.dll
[0x00007FFDC11D0000] Microsoft.UI.Windowing.dll
[0x00007FFDC1140000] Microsoft.UI.Windowing.Core.dll
[0x00007FFDC1040000] CoreMessagingXP.dll
[0x00007FFDDF190000] WTSAPI32.dll
[0x00007FFDE1020000] SspiCli.dll
[0x00007FFDD71F0000] directmanipulation.dll
[0x00007FFDE4540000] SETUPAPI.dll
[0x00007FFDE1B70000] DEVOBJ.dll
[0x00007FFDDFFF0000] dxgi.dll
[0x00007FFDE1E50000] powrprof.dll
[0x00007FFDE1E30000] UMPDC.dll
[0x00007FFDDFDA0000] dxcore.dll
[0x00007FFDDD190000] directxdatabasehelper.dll
[0x00007FFDD8C30000] mscms.dll
[0x00007FFDD89D0000] Windows.Globalization.dll
[0x00007FFDC0D80000] Microsoft.UI.Input.dll
[0x00007FFDC1870000] Microsoft.UI.Composition.OSSupport.dll
[0x00007FFDC0D00000] marshal.dll
[0x00007FFDC0C90000] Microsoft.InputStateManager.dll
[0x00007FFDDE6B0000] d3d11.dll
[0x00007FFDDA8D0000] D3D10Warp.dll
[0x00007FFDDE200000] windowscodecs.dll
[0x00007FFDD7300000] textinputframework.dll
[0x00007FFDC01B0000] explorerframe.dll
[0x00007FFDD5210000] OneCoreUAPCommonProxyStub.dll
[0x00007FFDD83F0000] MMDevApi.dll
[0x00007FFDC83C0000] AUDIOSES.DLL
[0x00007FFDC0C30000] softokn3.dll
[0x00007FFDC0AC0000] freebl3.dll
[0x00007FFDD38A0000] WININET.dll
[0x00007FFDD9D70000] iertutil.dll
[0x00007FFDDA3A0000] srvcli.dll
[0x00007FFDE08D0000] netutils.dll
[0x00007FFDD0BC0000] ondemandconnroutehelper.dll
[0x00007FFDD9340000] WINHTTP.dll
[0x00007FFDC8360000] dataexchange.dll
[0x00007FFDD76B0000] rasadhlp.dll
[0x00007FFDD87A0000] fwpuclnt.dll
[0x00007FFDDD0D0000] avrt.dll
[0x00007FFDCFC80000] Windows.System.Launcher.dll
[0x00007FFDD3B30000] windows.staterepositorycore.dll
[0x00007FFDBEBF0000] Windows.Security.Integrity.dll
[0x00007FFDD5B30000] LINKINFO.dll
[0x00007FFDCF830000] Windows.ApplicationModel.dll
[0x00007FFDBC350000] CryptoWinRT.dll
[0x00007FFDC6D10000] wpnapps.dll
[0x00007FFDD5D10000] windows.internal.shell.broker.dll
[0x00007FFDD5870000] OneCoreCommonProxyStub.dll
[0x00007FFDD8D60000] taskschd.dll
[0x00007FFDE15B0000] CRYPTSP.dll
[0x00007FFDE0E00000] rsaenh.dll
[0x00007FFDE42A0000] imagehlp.dll
[0x00007FFDDB880000] CoreUIComponents.dll
[0x00007FFDE36A0000] coml2.dll
[0x00007FFDBFA10000] ntshrui.dll
[0x00007FFDCE130000] cscapi.dll
[0x00007FFDDF730000] policymanager.dll
[0x00007FFDCDFB0000] winspool.drv
[0x00007FFDCF9B0000] edputil.dll
windows-process-injection\module-stomping >
```