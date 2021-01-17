[CmdletBinding()]

Param(
    [Parameter(Position=0,ValueFromPipelineByPropertyName=$true)][Alias('Path')]$FullName,
    [Parameter()][Switch]$Summarize
    )

BEGIN {
$PInvokeCode = @'
using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

using BYTE = System.Byte;
using WORD = System.UInt16;
using DWORD = System.UInt32;
using ULONGLONG = System.UInt64;
using QWORD = System.UInt64;

using TAGREF = System.UInt32;
using TAGID = System.UInt32;
using TAG = System.UInt16;
using TAG_TYPE = System.UInt16;

namespace SdbAPI
{
    public enum PATH_TYPE : uint
    {
        DOS_PATH = 0,
        NT_PATH = 1,
    }

    [Flags]
    public enum SdbRuntimePlatform
    {
        NONE              = 0x00000000,
        INTEL             = 0x00000001,
        AMD64             = 0x00000002,
        AMD3264           = 0x00000004,
        ARM               = 0x00000008,
        ARM64             = 0x00000010,
        ARM3264           = 0x00000020,

        ANY               = INTEL | AMD64 | AMD3264 | ARM | ARM64 | ARM3264,
    }

    public enum SdbTAG : ushort
    {
        DATABASE          = 0x7001,
        TIME              = 0x5001,
        NAME              = 0x6001,
        DATABASE_ID       = 0x9007,
        OS_PLATFORM       = 0x4023,
        RUNTIME_PLATFORM  = 0x4021,
        COMPILER_VERSION  = 0x6022,
    }


    public class Apphelp
    {
        public static IntPtr SdbOpenDatabase(string sdbPath, PATH_TYPE eType)
        {
            IntPtr temp;
            
            temp = SdbMethods.ApphelpSdbOpenDatabase(sdbPath, eType);
            if (temp == IntPtr.Zero)
            {
                try
                {
                    temp = SdbMethods.SdbOpenDatabase(sdbPath, eType);
                }
                catch(DllNotFoundException)
                {
                    temp = IntPtr.Zero;
                }
                
                if (temp != IntPtr.Zero)
                {
                    UseApphelp = false;
                }
            }
            return temp;
        }
        public static bool SdbGetDatabaseVersion(string sdbPath, ref DWORD verMajor, ref DWORD verMinor)
        {
            return UseApphelp ? SdbMethods.ApphelpSdbGetDatabaseVersion(sdbPath, ref verMajor, ref verMinor) : SdbMethods.SdbGetDatabaseVersion(sdbPath, ref verMajor, ref verMinor);
        }
        public static void SdbCloseDatabase(ref IntPtr pdb)
        {
            if(UseApphelp){
                SdbMethods.ApphelpSdbCloseDatabase(pdb);
            } else {
                SdbMethods.SdbCloseDatabase(pdb);
            }
            pdb = IntPtr.Zero;
        }

        public static string SdbTagToString(TAG tag)
        {
            IntPtr rtnPtr;
            string szRtn;
            rtnPtr = UseApphelp ?  SdbMethods.ApphelpSdbTagToString(tag) : SdbMethods.SdbTagToString(tag);
            szRtn = Marshal.PtrToStringUni(rtnPtr);

            return szRtn;
        }

        public static string SdbGetStringFromTagPtr(IntPtr pdb, TAGID tiWhich)
        {
            IntPtr rtnPtr;
            string szRtn;

            rtnPtr = UseApphelp ?  SdbMethods.ApphelpSdbGetStringTagPtr(pdb, tiWhich) : SdbMethods.SdbGetStringTagPtr(pdb, tiWhich);
            szRtn = Marshal.PtrToStringUni(rtnPtr);
            return szRtn;
        }

        public static QWORD SdbReadQWORDTag(IntPtr pdb, TAGID tiWhich, QWORD qwDefault)
        {
            return UseApphelp ?  SdbMethods.ApphelpSdbReadQWORDTag(pdb, tiWhich, qwDefault) : SdbMethods.SdbReadQWORDTag(pdb, tiWhich, qwDefault);
        }
        public static Guid SdbReadGUIDTag(IntPtr pdb, TAGID tiWhich, Guid guidDefault)
        {
            return UseApphelp ?  SdbMethods.ApphelpSdbReadGUIDTag(pdb, tiWhich, guidDefault) : SdbMethods.SdbReadGUIDTag(pdb, tiWhich, guidDefault);
        }
        public static DWORD SdbGetTagDataSize(IntPtr pdb, TAGID tiWhich)
        {
            return UseApphelp ?  SdbMethods.ApphelpSdbGetTagDataSize(pdb, tiWhich): SdbMethods.SdbGetTagDataSize(pdb, tiWhich);
        }

        public static Guid SdbGetBinaryTagDataAsGUID(IntPtr pdb, TAGID tiWhich)
        {
            IntPtr ptrPVoid;
            int byteCount;
            byte[] rtnBytes;
            DWORD dataLength;

            dataLength = UseApphelp ?  SdbMethods.ApphelpSdbGetTagDataSize(pdb, tiWhich): SdbMethods.SdbGetTagDataSize(pdb, tiWhich);
            byteCount = (int)dataLength;

            if (byteCount != 16)
            {
                return Guid.Empty;
            }

            ptrPVoid = UseApphelp ?  SdbMethods.ApphelpSdbGetBinaryTagData(pdb, tiWhich): SdbMethods.SdbGetBinaryTagData(pdb, tiWhich);
            rtnBytes = new byte[byteCount];
            Marshal.Copy(ptrPVoid, rtnBytes, 0, byteCount);

            return new Guid(rtnBytes);
        }

        public static TAGREF SdbFindFirstTag(IntPtr pdb, TAGREF trParent, SdbTAG tTag)
        {
            return UseApphelp ?  SdbMethods.ApphelpSdbFindFirstTag(pdb, trParent, (TAG)tTag) : SdbMethods.SdbFindFirstTag(pdb, trParent, (TAG)tTag);
        }
        public static byte SdbReadBYTETag(IntPtr pdb, TAGID tiWhich, byte jDefault)
        {
            return UseApphelp ?  SdbMethods.ApphelpSdbReadBYTETag(pdb, tiWhich, jDefault) : SdbMethods.SdbReadBYTETag(pdb, tiWhich, jDefault);
        }

        public static WORD SdbReadWORDTag(IntPtr pdb, TAGID tiWhich, WORD wDefault)
        {
            return UseApphelp ?  SdbMethods.ApphelpSdbReadWORDTag(pdb, tiWhich, wDefault) : SdbMethods.SdbReadWORDTag(pdb, tiWhich, wDefault);
        }
        public static DWORD SdbReadDWORDTag(IntPtr pdb, TAGID tiWhich, DWORD dwDefault)
        {
            return UseApphelp ?  SdbMethods.ApphelpSdbReadDWORDTag(pdb, tiWhich, dwDefault) : SdbMethods.SdbReadDWORDTag(pdb, tiWhich, dwDefault);
        }
        private static bool UseApphelp = true;
    }

    internal class SdbMethods
    {
        [DllImport("apphelp.dll", EntryPoint = "SdbOpenDatabase", CharSet = CharSet.Unicode)]
        internal static extern IntPtr ApphelpSdbOpenDatabase(
            [MarshalAs(UnmanagedType.LPTStr)]string pwszPath,
            PATH_TYPE eType
            );

        [DllImport("compattel\\sdbapiu.dll", CharSet = CharSet.Unicode)]
        internal static extern IntPtr SdbOpenDatabase(
            [MarshalAs(UnmanagedType.LPTStr)]string pwszPath,
            PATH_TYPE eType
            );
            
        [DllImport("apphelp.dll", EntryPoint = "SdbGetDatabaseVersion", CharSet = CharSet.Unicode)]
        internal static extern bool ApphelpSdbGetDatabaseVersion(
            [MarshalAs(UnmanagedType.LPTStr)]string pwszPath,
            ref DWORD lpdwMajor,
            ref DWORD lpdwMinor
            );

        [DllImport("compattel\\sdbapiu.dll", CharSet = CharSet.Unicode)]
        internal static extern bool SdbGetDatabaseVersion(
            [MarshalAs(UnmanagedType.LPTStr)]string pwszPath,
            ref DWORD lpdwMajor,
            ref DWORD lpdwMinor
            );

        [DllImport("apphelp.dll", EntryPoint = "SdbFindFirstTag")]
        internal static extern TAGREF ApphelpSdbFindFirstTag(
            IntPtr pdb,
            TAGREF trParent,
            TAG    tTag
            );

        [DllImport("compattel\\sdbapiu.dll")]
        internal static extern TAGREF SdbFindFirstTag(
            IntPtr pdb,
            TAGREF trParent,
            TAG    tTag
            );

        [DllImport("apphelp.dll", EntryPoint = "SdbReadBYTETag")]
        internal static extern BYTE ApphelpSdbReadBYTETag(
            IntPtr pdb,
            TAGID tiWhich,
            BYTE jDefault
            );

        [DllImport("compattel\\sdbapiu.dll")]
        internal static extern BYTE SdbReadBYTETag(
            IntPtr pdb,
            TAGID tiWhich,
            BYTE jDefault
            );

        [DllImport("apphelp.dll", EntryPoint = "SdbReadWORDTag")]
        internal static extern WORD ApphelpSdbReadWORDTag(
            IntPtr pdb,
            TAGID tiWhich,
            WORD wDefault
            );

        [DllImport("compattel\\sdbapiu.dll")]
        internal static extern WORD SdbReadWORDTag(
            IntPtr pdb,
            TAGID tiWhich,
            WORD wDefault
            );

        [DllImport("apphelp.dll", EntryPoint = "SdbReadDWORDTag")]
        internal static extern DWORD ApphelpSdbReadDWORDTag(
            IntPtr pdb,
            TAGID tiWhich,
            DWORD dwDefault
            );

        [DllImport("compattel\\sdbapiu.dll")]
        internal static extern DWORD SdbReadDWORDTag(
            IntPtr pdb,
            TAGID tiWhich,
            DWORD dwDefault
            );

        [DllImport("apphelp.dll", EntryPoint = "SdbCloseDatabase")]
        internal static extern void ApphelpSdbCloseDatabase(
            IntPtr pdb
            );

        [DllImport("compattel\\sdbapiu.dll")]
        internal static extern void SdbCloseDatabase(
            IntPtr pdb
            );

        [DllImport("apphelp.dll", EntryPoint = "SdbReadQWORDTag")]
        internal static extern ULONGLONG ApphelpSdbReadQWORDTag(
            IntPtr pdb,
            TAGID tiWhich,
            ULONGLONG qwDefault
            );

        [DllImport("compattel\\sdbapiu.dll")]
        internal static extern ULONGLONG SdbReadQWORDTag(
            IntPtr pdb,
            TAGID tiWhich,
            ULONGLONG qwDefault
            );

        [DllImport("apphelp.dll", EntryPoint = "SdbGetTagDataSize")]
        internal static extern DWORD ApphelpSdbGetTagDataSize(
            IntPtr pdb,
            TAGID tiWhich
            );

        [DllImport("compattel\\sdbapiu.dll")]
        internal static extern DWORD SdbGetTagDataSize(
            IntPtr pdb,
            TAGID tiWhich
            );

        [DllImport("apphelp.dll", EntryPoint = "SdbGetStringTagPtr")]
        internal static extern IntPtr ApphelpSdbGetStringTagPtr(
            IntPtr pdb,
            TAGID tiWhich
            );

        [DllImport("compattel\\sdbapiu.dll")]
        internal static extern IntPtr SdbGetStringTagPtr(
            IntPtr pdb,
            TAGID tiWhich
            );

        [DllImport("apphelp.dll", EntryPoint = "SdbGetBinaryTagData")]
        internal static extern IntPtr ApphelpSdbGetBinaryTagData(
            IntPtr pdb,
            TAGID tiWhich
            );

        [DllImport("compattel\\sdbapiu.dll")]
        internal static extern IntPtr SdbGetBinaryTagData(
            IntPtr pdb,
            TAGID tiWhich
            );

        [DllImport("apphelp.dll", EntryPoint = "SdbTagToString", CharSet = CharSet.Unicode)]
        internal static extern IntPtr ApphelpSdbTagToString(TAG tag);

        [DllImport("compattel\\sdbapiu.dll", CharSet = CharSet.Unicode)]
        internal static extern IntPtr SdbTagToString(TAG tag);

        [DllImport("apphelp.dll", EntryPoint = "SdbReadGUIDTag")]
        internal static extern Guid ApphelpSdbReadGUIDTag(
            IntPtr pdb,
            TAGID tiWhich,
            Guid guidDefault
            );

        [DllImport("compattel\\sdbapiu.dll")]
        internal static extern Guid SdbReadGUIDTag(
            IntPtr pdb,
            TAGID tiWhich,
            Guid guidDefault
            );
    }

}
'@

Add-Type -TypeDefinition $PInvokeCode

Function GetOSPlatforms_V2
{
    Param([System.UInt32]$dwOSPlat)
    $ba = [System.BitConverter]::GetBytes($dwOSPlat)[0..3]

    $ba |ForEach-Object{
        $bt = $_
        switch($bt)
        {
            0x01 { 'X86'   ; break; }
            0x02 { 'IA64'  ; break; }
            0x04 { 'AMD64' ; break; }
            0x06 { 'WOW64' ; break; }
            0x08 { 'ARM'   ; break; }
            default { break; }
        }
    }
}

Function GetRTPlatforms
{
    Param([System.UInt32]$dwRTPlat)

    return [SdbApi.SdbRuntimePlatform]$dwRTPlat
}

$SummaryData = New-Object 'System.Collections.Generic.List[PSObject]'

}
PROCESS {
    If(-Not (Test-Path $FullName))
    {
        throw "File not found: $FullName"
    }

    $sdbFullPath = Convert-Path $FullName

    $hSdb = [SdbAPI.Apphelp]::SdbOpenDatabase($sdbFullPath, 'DOS_PATH')

    If($hSdb -ne $null -and $hSdb -ne [System.IntPtr]::Zero){

        try {
            $trDatabase = [SdbAPI.Apphelp]::SdbFindFirstTag($hSdb, 0, 0x7001)

            if($trDatabase -ne 0) {

                $trTime = [SdbAPI.Apphelp]::SdbFindFirstTag($hSdb, $trDatabase, 'TIME')
                $trName = [SdbAPI.Apphelp]::SdbFindFirstTag($hSdb, $trDatabase, 'NAME')
                $trComp = [SdbAPI.Apphelp]::SdbFindFirstTag($hSdb, $trDatabase, 'COMPILER_VERSION')
                $trGuid = [SdbAPI.Apphelp]::SdbFindFirstTag($hSdb, $trDatabase, 'DATABASE_ID')

                if($trTime -ne 0) { $qwTime  = [SdbAPI.Apphelp]::SdbReadQWORDTag($hSdb, $trTime, 0) } else { $qwTime = 0 }
                if($trName -ne 0) { $szName  = [SdbAPI.Apphelp]::SdbGetStringFromTagPtr($hSdb, $trName) } else { $szName = "??" }
                if($trComp -ne 0) { $szComp  = [SdbAPI.Apphelp]::SdbGetStringFromTagPtr($hSdb, $trComp) } else { $szComp = "??" }
                if($trGuid -ne 0) { $gidGuid = [SdbAPI.Apphelp]::SdbGetBinaryTagDataAsGUID($hSdb, $trGuid) } else { $gidGuid = [System.Guid]::Empty }


                $verSdb = [System.Version]$szComp;
                
                if ($verSdb.Major -lt 3) {
                    $trOSPf = [SdbAPI.Apphelp]::SdbFindFirstTag($hSdb, $trDatabase, 'OS_PLATFORM')
                    if($trOSPf -ne 0) { $dwPlat  = [SdbAPI.Apphelp]::SdbReadDWORDTag($hSdb, $trOSPf, 0) } else { $dwPlat = 0x00000000 }
                    $szPlat = GetOSPlatforms_V2 $dwPlat
                } else {
                    $trOSPf = [SdbAPI.Apphelp]::SdbFindFirstTag($hSdb, $trDatabase, 'RUNTIME_PLATFORM')
                    if($trOSPf -ne 0) { $dwPlat  = [SdbAPI.Apphelp]::SdbReadDWORDTag($hSdb, $trOSPf, 0) } else { $dwPlat = 0x00000000 }
                    $szPlat = GetRTPlatforms $dwPlat
                }


                $rtn = [PSCustomObject]@{
                        File            = $sdbFullPath
                        DbName          = $szName
                        Timestamp       = ([System.DateTime]::FromFileTime($qwTime))
                        DbGuid          = $gidGuid.ToString("b").ToUpper()
                        OSPlatform      = $szPlat
                        CompilerVersion = $verSdb
                        TimeRaw         = [System.String]::Format("0x{0:X16}",$qwTime)
                        OSPlatformRaw   = [System.String]::Format("0x{0:X8}",$dwPlat)
                        VersionString   = $szComp
                    }

                If ($Summarize) {
                    $SummaryData.Add($rtn);
                } Else {
                    $rtn
                }

            } else { "trDatabase was null" }

        }
        finally {
            [SdbAPI.Apphelp]::SdbCloseDatabase([ref] $hSdb)
        }
    } else { "hSdb was null" }
}
END {

    if ($Summarize) {
        $tsData = $SummaryData | Measure-Object -Property Timestamp -Minimum -Maximum

        [PSCustomObject]@{
            FileCount    = $SummaryData.Count
            TimestampMin = $tsData.Minimum
            TimestampMax = $tsData.Maximum
            TimeDiff     = $tsData.Maximum - $tsData.Minimum
            TSMin        = "0x{0:X16}" -F ($tsData.Minimum.ToFileTime())
            TSMax        = "0x{0:X16}" -F ($tsData.Maximum.ToFileTime())
            TSDiff       = "0x{0:X16}" -F (($tsData.Maximum.ToFileTime()) - ($tsData.Minimum.ToFileTime()))
            Files        = @($SummaryData |ForEach-Object{ [System.IO.Path]::GetFileName($_.File) })
        }
    }
}

