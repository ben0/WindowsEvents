
function Get-DllFiles
{
    <#
    .SYNOPSIS
    

    .DESCRIPTION

    .PARAMETER Path 

    .EXAMPLE
    Get-DllFiles -Path "C:\windows\system32"
    Get-DllFiles -Path "C:\ProgramData" | Select-Object FullName, OriginalFilename, NameMatch, FileDescription, CompanyName, Size, Sha256, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc, AuthenticodeStatus, AuthenticodeSigType, AuthenticodeIsOSbinary
    Get-DllFiles -Path "C:\ProgramData" | ? { $_.AuthenticodeStatus -eq $true }
    Get-DllFiles -Path "C:\ProgramData" | Select FullName, Sha256

    .INPUTS
    System.String

    .OUTPUTS
    Object with files matching below:

    FullName               : C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2111.5-0\X86\MsMpLics.dll
    OriginalFilename       : MsMpLics.dll
    NameMatch              : True
    FileDescription        : License Module
    CompanyName            : Microsoft Corporation
    Size                   : 12520
    Sha256                 : 8AF4179A985DCEFE8FCECBB0FE1CD902BB478B5ED60E5A2A884959F7C6EB52E6
    CreationTimeUtc        : 22/12/2021 13:50:12
    LastAccessTimeUtc      : 30/12/2021 18:05:37
    LastWriteTimeUtc       : 22/12/2021 13:49:58
    AuthenticodeStatus     : Valid
    AuthenticodeSigType    : Authenticode
    AuthenticodeIsOSbinary : True
    
    .NOTES

    .LINK

    #>
    [CmdletBinding()]
    [OutputType([String])]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)] 
        [string]$Path
    )

    $results = @()
    $files = Get-ChildItem -Path $Path -Filter "*.dll" -Force -Recurse -ErrorAction SilentlyContinue

    ForEach ($file in $files)
    {
        $authenticode = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction SilentlyContinue
        $sha256 = Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Hash
        $NameMatch = $false
        if($file.Name -eq $file.VersionInfo.OriginalFilename) { $NameMatch = $true }
        $PSObjectRow = New-Object PSObject -Property @{
            FullName                = $file.FullName
            Size                    = $file.Length
            CreationTimeUtc         = $file.CreationTimeUtc
            LastAccessTimeUtc       = $file.LastAccessTimeUtc
            LastWriteTimeUtc        = $file.LastWriteTimeUtc 
            Sha256                  = $sha256
            OriginalFilename        = $file.VersionInfo.OriginalFilename
            NameMatch               = $NameMatch
            CompanyName             = $file.VersionInfo.CompanyName
            FileDescription         = $file.VersionInfo.FileDescription
            AuthenticodeStatus      = $authenticode.Status
            AuthenticodePath        = $authenticode.Path
            AuthenticodeSigType     = $authenticode.SignatureType
            AuthenticodeIsOSbinary  = $authenticode.IsOSBinary
        }
        $results += $PSObjectRow
    }
    Write-Output $results
}
$DllFiles = Get-DllFiles -Path "C:\ProgramData" | Select-Object FullName, OriginalFilename, NameMatch, FileDescription, CompanyName, Size, Sha256, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc, AuthenticodeStatus, AuthenticodeSigType, AuthenticodeIsOSbinary
$DllFiles | ? { $_.AuthenticodeStatus -eq $true }
