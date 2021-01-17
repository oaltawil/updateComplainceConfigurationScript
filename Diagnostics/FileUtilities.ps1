function GetPEArch ($PE)
{
    $fs = New-Object -TypeName System.IO.FileStream -ArgumentList @($PE.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read);
    $br = New-Object -TypeName System.IO.BinaryReader -ArgumentList $fs;
    $fs.Seek(0x3c, [System.IO.SeekOrigin]::Begin) | Out-Null;
    [System.Int32] $peOffset = $br.ReadInt32();
    $fs.Seek($peOffset, [System.IO.SeekOrigin]::Begin) | Out-Null;
    [System.UInt32] $peHead = $br.ReadUInt32();

    if ($peHead -eq 0x00004550)
    {
        [System.UInt16] $type = $br.ReadUInt16();
    }

    $br.Close() | Out-Null;
    $fs.Close() | Out-Null;

    if ($type -eq 0x8664)
    {
        return "amd64";
    }
    elseif ($type -eq 0x14c)
    {
        return "x86";
    }
    else
    {
        return "unknown";
    }
}

function GetPESigned ($PE)
{
    $Path = $PE.FullName;

    if(Test-Path "$env:Windir\syswow64")
    {
        $Path = $Path.Replace("\system32\", "\sysnative\");
    }

    $SignedOutput = & "$SdToolsPath\signtool.exe" verify /v /pa $Path 2>&1;
    
    if($LASTEXITCODE -eq 0)
    {
        foreach($Line in $SignedOutput)
        {
            if($Line.Contains("Microsoft Test Root Authority"))
            {
                return "TestSigned";
            }
            if($Line.Contains("Microsoft Root Certificate Authority"))
            {
                return "ProductionSigned";
            }
        }
        return "OtherSigned"
    }
    
    return "Unsigned";
}

function ProperlySigned($Binary, $Signed)
{
    return !(($Signed.Equals("TestSigned") -or $Signed.Equals("ProductionSigned")) -xor
            (($Binary.Extension -eq ".exe") -or ($Binary.Extension -eq ".sys") -or ($Binary.Name -eq "compatResources.dll")));
}
