function Get-TaskComHandler
{
    <#
    .SYNOPSIS

    .DESCRIPTION

    .PARAMETER Path 

    .EXAMPLE

    .INPUTS

    .OUTPUTS
    Object with files matching below:
    
    .NOTES

    .LINK

    #>
    $results = @()
    $Tasks = Get-ChildItem -Path 'c:\windows\system32\tasks' -Recurse | Where-Object { ! $_.PSIsContainer } 
    Foreach ($Task in $Tasks)
    {
        [Xml]$TaskXML = Get-Content -Path $Task.Fullname
        if($TaskXML.Task.Actions.ComHandler)
        {
            $classId = $TaskXML.Task.Actions.ComHandler.ClassID
            $regProperty = "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\$($ClassID)\InProcServer32"
            if(Test-Path -LiteralPath $regProperty)
            {
                $targetDll = (Get-ItemProperty -LiteralPath $regProperty -ErrorAction SilentlyContinue).'(Default)'
                if (Test-Path $targetDll) {
                    $file = Get-Item -Path $targetDll -ErrorAction SilentlyContinue
                    $authenticode = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction SilentlyContinue
                    $sha256 = Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Hash
                }
            }
        }

        $PSObjectRow = New-Object PSObject -Property @{
            TaskName                = $Task.Name
            TaskFullName            = $Task.FullName
            IsEnabled               = $TaskXML.Task.Settings.Enabled
            TaskAction              = $TaskXML.Task.Actions.Exec.Command
            TaskArgs                = $TaskXML.Task.Actions.Exec.Arguments
            IsHidden                = $TaskXML.Task.Settings.Hidden
            ClassId                 = $classId 
            COMregProperty          = $regProperty
            COMtargetDll            = $targetDll 
            COMSha256               = $sha256
            COMDirectoryName        = $file.DirectoryName
            COMOriginalFilename     = $file.VersionInfo.OriginalFilename
            COMCompanyName          = $file.VersionInfo.CompanyName
            COMFileDescription      = $file.VersionInfo.FileDescription
            COMLastWriteTimeUTC     = $file.LastWriteTimeUTC
            COMAuthenticodeStatus   = $authenticode.Status
            COMAuthenticodePath     = $authenticode.Path
            COMAuthenticodeSigType  = $authenticode.SignatureType
            COMAuthenticodeIsOSbinary = $authenticode.IsOSBinary
        }
        $results += $PSObjectRow
    }
    return $results
}

# Use Cases:

## Get all tasks and data
Get-TaskComHandler | Select-Object TaskName, TaskFullName, IsEnabled, TaskAction, TaskArgs, IsHidden, ClassId, COMregProperty, COMtargetDll, COMSha256, COMDirectoryName, COMOriginalFilename, COMCompanyName, COMFileDescription, COMLastWriteTimeUTC, COMAuthenticodeStatus, COMAuthenticodePath, COMAuthenticodeSigType, COMAuthenticodeIsOSbinary

## Where COMDirectoryName is not in C:\windows\
Get-TaskComHandler | Where-Object { $_.ClassId -ne ""} | Where-Object { $_.COMDirectoryName -notlike "*c:\windows\*"} | Select-Object TaskName, TaskFullName, IsEnabled, TaskAction, TaskArgs, IsHidden, ClassId, COMregProperty, COMtargetDll, COMSha256, COMDirectoryName, COMOriginalFilename, COMCompanyName, COMFileDescription, COMLastWriteTimeUTC, COMAuthenticodeStatus, COMAuthenticodePath, COMAuthenticodeSigType, COMAuthenticodeIsOSbinary

## Group By on COMDirectoryName
Get-TaskComHandler | Where-Object { $_.ClassId -ne ""} | Group-Object -Property COMDirectoryName -NoElement | Sort-Object -Property Count -Descending

## Where COMAuthenticateStatus isn't valid
Get-TaskComHandler | Where-Object { $_.ClassId -ne ""} | Where-Object { $_.COMAuthenticodeStatus -notlike "Valid"} | Select-Object TaskName, TaskFullName, IsEnabled, TaskAction, TaskArgs, IsHidden, ClassId, COMregProperty, COMtargetDll, COMSha256, COMDirectoryName, COMOriginalFilename, COMCompanyName, COMFileDescription, COMLastWriteTimeUTC, COMAuthenticodeStatus, COMAuthenticodePath, COMAuthenticodeSigType, COMAuthenticodeIsOSbinary

## Where COM OS binary isn't valid
Get-TaskComHandler | Where-Object { $_.ClassId -ne ""} | Where-Object { $_.COMAuthenticodeIsOSbinary -eq $false} | Select-Object TaskName, TaskFullName, IsEnabled, TaskAction, IsHidden, ClassId, COMregProperty, COMtargetDll, COMSha256, COMDirectoryName, COMOriginalFilename, COMCompanyName, COMFileDescription, COMLastWriteTimeUTC, COMAuthenticodeStatus, COMAuthenticodePath, COMAuthenticodeSigType, COMAuthenticodeIsOSbinary

## Get all COM target DLL file hashes
Get-TaskComHandler | Group-Object -Property Sha256 -NoElement | Sort-Object -Property Count -Descending | Format-Table -Autosize

## Task action is PowerShell or cmd
Get-TaskComHandler | Where-Object { $_.TaskAction -match "powershell|cmd"} | Select-Object TaskName, TaskFullName, IsEnabled, TaskAction, IsHidden, ClassId, regProperty, targetDll, Sha256, DirectoryName, OriginalFilename, CompanyName, FileDescription, LastWriteTimeUTC, AuthenticodeStatus, AuthenticodePath, AuthenticodeSigType, AuthenticodeIsOSbinary
