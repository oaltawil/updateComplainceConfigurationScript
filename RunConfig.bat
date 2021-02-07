@echo off
@echo Running config batch

:: Run Mode, set runMode=Pilot for debugging with verbose logs or else set runMode=Deployment
set runMode=Pilot
set runMode=%runMode:"=%

:: File share to store telemetry logs
set logPath=C:\Users\Public\Documents
set logPath=%logPath:"=%

:: Commercial ID provided to you
:: Copy COMMERCIAL ID KEY in above path and replace it in the line below
set commercialIDValue=464730d5-fcfa-4153-8ffb-3cec653f146d

:: By Default script logs to both console and log file.
:: logMode == 0 log to console only
:: logMode == 1 log to file and console
:: logMode == 2 log to file only
set logMode=1

:: If DeviceNameOptIn is set to true, device name will be sent to Microsoft.
:: If DeviceNameOptIn is set to false, device name will not be sent to Microsoft.
:: This setting is applicable only to OS version 16300 or higher
set DeviceNameOptIn=true

:: Switch to select if the client machines are behind a proxy
:: ClientProxy=Direct means there is no proxy, the connection to the end points is direct
:: ClientProxy=System means there is a system wide proxy. It does not require Authentication. The client machine should have the proxy configured through netsh
:: ClientProxy=User means the proxy is configured through IE and it might or migt not require user authentication. We will still need to go through authenticated route.
:: Please see https://go.microsoft.com/fwlink/?linkid=843397 for more information
set ClientProxy=Direct

set source="%~dp0"
set sourceWithoutQuotes=%source:"=%

for /f %%i in ('Powershell.exe $pshome') do set PowershellHome=%%i

:: Make sure we are running x64 PS on 64 bit OS. If not then start a new x64 process of powershell
reg Query "HKLM\Hardware\Description\System\CentralProcessor\0" | find /i "x86" > NUL && set OS=32BIT || set OS=64BIT

if %OS%==64BIT (
if exist %WINDIR%\sysnative\reg.exe (
set PowershellHome=%PowershellHome:syswow64=sysnative%
) 
)

if exist %PowershellHome%\powershell.exe.config ( 
  Copy /Y %PowershellHome%\powershell.exe.config %source%\powershell.exe.config.bak
  Copy /Y %source%\powershell.exe.config %PowershellHome%\powershell.exe.config
) else (
  Copy /Y %source%\powershell.exe.config  %PowershellHome%\powershell.exe.config
)

:: Getting the HKCU proxy setting for the account running the RunConfig.bat (useful for debugging in Pilot mode when the logged on user runs this batch file) 
set HKCUProxyEnable=0x0
for /f "usebackq tokens=3*" %%A IN (`REG QUERY "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable`) do (
    set HKCUProxyEnable=%%A 
    )

if %HKCUProxyEnable%==0x0 (
set HKCUProxyServer=
) else (
for /f "usebackq tokens=3*" %%A IN (`REG QUERY "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer`) do (
set HKCUProxyServer=%%A 
)
)

set powershellCommand="&{&'%sourceWithoutQuotes%ConfigScript.ps1' %runMode% '%logPath%' %commercialIDValue% %logMode% %DeviceNameOptIn% %ClientProxy% %HKCUProxyEnable% %HKCUProxyServer%; exit $LASTEXITCODE}"
set psexecPath="%sourceWithoutQuotes%Psexec.exe"

%psexecPath% -accepteula -si %PowershellHome%\powershell.exe -ExecutionPolicy Bypass -noexit -Command %powershellCommand%
@echo %ERRORLEVEL%
set exitCode=%ERRORLEVEL%

:: restore the powershell.exe.config to what was before if there was one, or else remove it
if exist %source%\powershell.exe.config.bak (
   Copy %source%\powershell.exe.config.bak %PowershellHome%\powershell.exe.config
   Del /F /Q %source%\powershell.exe.config.bak
) else (
   Del /F /Q   %PowershellHome%\powershell.exe.config
)

set powershellCommand=""
set sourceWithoutQuotes=""
set source=""
set PowershellHome=""
exit /b %exitCode%
