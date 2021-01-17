[CmdletBinding()]
Param(
    [string] $ToolsPath
)

$ScriptRootPath = Split-Path ((Get-Variable MyInvocation).Value.MyCommand.Path);
. ($ScriptRootPath + '\FileUtilities.ps1');

$SdToolsPath = $ToolsPath;

# If we're running from an enlistment, see if there's a user-provided script with machine-specific information like SD paths
if(((Get-Variable MyInvocation).Value.MyCommand.Path).IndexOf("base\appcompat\appraiser\scripts") -ne -1)
{
    $SdRoot = ((Get-Variable MyInvocation).Value.MyCommand.Path).Remove(((Get-Variable MyInvocation).Value.MyCommand.Path).IndexOf("base\appcompat\appraiser\scripts"));
    . $SdRoot\developer\$env:Username\UserSettings.ps1;
    $SdToolsPath = "$SdRoot\tools\x86";
}

if($SdToolsPath.Equals(""))
{
    Write-Host -ForegroundColor Red "You must pass in a path to a directory containing signtool.exe`ne.g. VerifyInstall.ps1 -ToolsPath c:\tools";
    return;
}

$PathsToCheck = @("$env:Windir\system32\appraiser",
                  "$env:Windir\system32\CompatTel\diagtrack.dll",
                  "$env:Windir\system32\CompatTel\diagtrackrunner.exe",
                  "$env:Windir\system32\appraiser.dll",
                  "$env:Windir\system32\invagent.dll",
                  "$env:Windir\system32\aeinv.dll",
                  "$env:Windir\system32\devinv.dll",
                  "$env:Windir\system32\aepic.dll",
                  "$env:Windir\system32\acmigration.dll",
                  "$env:Windir\system32\generaltel.dll",
                  "$env:Windir\system32\compattelrunner.exe",
                  "$env:Windir\system32\aitstatic.exe");

function RecurseDirectories($Path)
{
    $CurrentFile = Get-Item $Path -ErrorAction SilentlyContinue;
    if($CurrentFile -eq $null)
    {
        Write-Output ("$Path does not exist!");
    }
    elseif(($CurrentFile.Attributes -band [io.fileattributes]::Directory) -ne 0)
    {
        $Children = Get-ChildItem $CurrentFile;
        foreach ($Child in $Children)
        {
            RecurseDirectories($Child.FullName);
        }
    }
    else
    {
        CheckBinaries($CurrentFile);
    }
}

function CheckBinaries($CurrentFile)
{
    Write-Output ("`tFile:`t" + $CurrentFile.FullName);
    Write-Output ("`t`tLastWriteTime:`t" + $CurrentFile.LastWriteTime);
    Write-Output ("`t`tSize:`t`t`t" + $CurrentFile.Length);
    if(($CurrentFile.Extension -eq ".exe") -or ($CurrentFile.Extension -eq ".dll") -or ($CurrentFile.Extension -eq ".sys"))
    {
        [String] $FileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($CurrentFile.FullName).FileVersion;
        [String] $Arch = GetPEArch $CurrentFile;
        $IsSigned = GetPESigned $CurrentFile;
        Write-Output ("`t`tVersion:`t" + $FileVersion);
        Write-Output ("`t`tArch:`t`t" + $Arch);
        if(ProperlySigned $CurrentFile $IsSigned)
        {
            if ($IsSigned.Equals("TestSigned") -or $IsSigned.Equals("OtherSigned"))
            {
                Write-Output ("***ERROR: Test signing***`t`tIsSigned:`t" + $IsSigned);
            }
            else
            {
                Write-Output ("`t`tIsSigned:`t" + $IsSigned);
            }
        }
        else
        {
            Write-Output ("***ERROR: Unexpected signing*** IsSigned:`t" + $IsSigned);
        }
    }
    elseif ($CurrentFile.Extension -eq ".sdb")
    {
        $SdbInfo = & "$ScriptRootPath\Get-SdbFileInfo.ps1" $CurrentFile.FullName;
        Write-Output ("`t`tDbName:`t`t`t" + $SdbInfo.DbName);
        Write-Output ("`t`tTimestamp:`t`t" + $SdbInfo.Timestamp);
        Write-Output ("`t`tTimeRaw:`t`t" + $SdbInfo.TimeRaw);
        Write-Output ("`t`tOSPlatform:`t`t" + $SdbInfo.OSPlatform);
    }
}

foreach ($Path in $PathsToCheck)
{
    RecurseDirectories($Path);
}
