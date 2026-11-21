; ALL RIGHTS RESERVED. © Nasser Aldin Farag (0xFarag).
Unicode true
Name "AuthzLedger Recipient Verifier Preview"
OutFile "AuthzLedgerVerify-Setup.exe"
RequestExecutionLevel user
SetCompressor /SOLID lzma
InstallDir "$LOCALAPPDATA\Programs\AuthzLedgerRecipientVerifierPreview"
ShowInstDetails show
ShowUninstDetails show
Page instfiles
UninstPage instfiles
VIProductVersion "1.5.0.0"
VIAddVersionKey "CompanyName" "Nasser Aldin Farag (0xFarag)"
VIAddVersionKey "FileDescription" "AuthzLedger offline recipient verifier preview installer"
VIAddVersionKey "FileVersion" "1.5.0 preview"
VIAddVersionKey "LegalCopyright" "ALL RIGHTS RESERVED. © Nasser Aldin Farag (0xFarag)."

Section
  SetShellVarContext current
  SetOutPath "$INSTDIR"
  ClearErrors
  File "AuthzLedgerVerify-x64.exe"
  File "NOTICE.txt"
  File "upstream-LICENSE"
  File "upstream-NOTICE.txt"
  File "Go-LICENSE.txt"
  File "NSIS-LICENSE.txt"
  IfErrors failed
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  IfErrors failed
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AuthzLedgerRecipientVerifierPreview" "DisplayName" "AuthzLedger Recipient Verifier Preview"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AuthzLedgerRecipientVerifierPreview" "DisplayVersion" "1.5.0 preview"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AuthzLedgerRecipientVerifierPreview" "Publisher" "Nasser Aldin Farag (0xFarag)"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AuthzLedgerRecipientVerifierPreview" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  Goto done
failed:
  SetErrorLevel 1
  Abort
done:
SectionEnd

Section "Uninstall"
  Delete "$INSTDIR\AuthzLedgerVerify-x64.exe"
  Delete "$INSTDIR\NOTICE.txt"
  Delete "$INSTDIR\upstream-LICENSE"
  Delete "$INSTDIR\upstream-NOTICE.txt"
  Delete "$INSTDIR\Go-LICENSE.txt"
  Delete "$INSTDIR\NSIS-LICENSE.txt"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AuthzLedgerRecipientVerifierPreview"
SectionEnd
