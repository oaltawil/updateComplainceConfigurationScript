@echo off
set filePath=%1
set logPath=%2
@echo Diagnose Appraiser
@echo %filePath%
@echo %logPath%

net session > nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Please run the script as administrator.  Press any key to exit...
    pause
    exit /B 1
)

for /F "usebackq tokens=1" %%i in (`powershell ^(get-date^).ToUniversalTime^(^).ToString^('"yyyy_MM_dd_HH_mm_ss"'^)`) do set today=%%i

set source=%filePath%
set hostname=APPRAISER_%today%_%computername%
set logfolder=%logPath%\

if not exist %logfolder% mkdir %logfolder%

set logfolder=%logfolder:"=%

powershell -ExecutionPolicy Bypass -File %source%\VerifyInstall.ps1 -ToolsPath %source% > "%logfolder%\binarylist.txt"

powershell -ExecutionPolicy Bypass -Command "Get-WmiObject -Query 'select * from win32_quickfixengineering' | sort hotfixid" > "%logfolder%\installedKBs.txt"

ROBOCOPY "%windir%\appcompat" "%logfolder%\appcompat" *.* /E /XF *.hve* /R:1

regedit /e "%logfolder%\RegAppCompatFlags.txt" "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags"
regedit /e "%logfolder%\RegCensus.txt" "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Census"
regedit /e "%logfolder%\RegSQM.txt" "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SQMClient"
regedit /e "%logfolder%\RegDiagTrack.txt" "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack"
regedit /e "%logfolder%\RegPoliciesDataCollection.txt" "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
regedit /e "%logfolder%\RegDataCollection.txt" "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection"