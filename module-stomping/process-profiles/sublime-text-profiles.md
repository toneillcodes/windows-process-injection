# Sublime Text Editor Process Profiles

## Module Testing Table
| Process | Version Tested | Target Module | Target Function | Payload Size | Beacon Result | Notes |
|----|----|----|----|----|----|----|
| sublime_text.exe | Build 4200 | wininet.dll | InternetSetOptionW | 287930 | success | Stable during typical usage |
| sublime_text.exe | Build 4200 | wininet.dll | ShowCertificate | 287930 | success | Stable during typical usage |
| sublime_text.exe | Build 4200 | wininet.dll | GopherCreateLocatorA | 287930 | success | Stable during typical usage |


## Module Lists
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