Function Show-UninstallRegistry {
    #The Show-UninstallRegistry searches the registry uninstall keys for a name you specify
    param(
        [Parameter(Mandatory = $true)][string]$NameToFind,
        [switch]$ShowDetails
    )

    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    if (!($NameToFind)) {
        Write-Host "Please add -NameToFind and a full or partial name that you are looking for" -ForegroundColor Red
        exit
    }

    if ($ShowDetails) {
        Get-ItemProperty $uninstallPaths | Where-Object { $_.DisplayName -like "*$NameToFind*" }
    } else {
        Get-ItemProperty $uninstallPaths | Where-Object { $_.DisplayName -like "*$NameToFind*" } | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
        Write-Host "Use -ShowDetails to show all details" -ForegroundColor Yellow
    }
}

Function Get-OSArchitecture {
    if ($env:PROCESSOR_ARCHITECTURE -eq "x86") {
        "32-Bit CPU"
    }
    Else {
        "64-Bit CPU"
    }
}

Function Write-CustomLog {
    #Begin Logging Setup
    param
    (
        [Parameter(Mandatory = $true)] [string] $Message,
        [Parameter(Mandatory = $true)] [string] [ValidateSet("Error", "Warning", "Info", "Verbose")] $Type,
        [Parameter(Mandatory = $true)] [string] $LogFile,
        [string]$LogDir
    )

    $Component = "Main"

    #Log Location and Name
    if (!($LogDir)) {
        $LogDir = "C:\Windows\CCM\Logs\"
    }

    if (!($LogFile)) {
        Write-Host "Please supply a log file name" -ForegroundColor Red
        exit
    }

    $LogFile = "$LogDir" + "$LogFile"
    If ((Test-path -path $LogDir) -eq $false) {
        New-Item -path $LogDir -ItemType "Directory"
    }

    #Set logging level
    switch ($LoggingLevel) {
        "Verbose" { $LoggingLevelNumber = 4 }
        "Info" { $LoggingLevelNumber = 3 }
        "Warning" { $LoggingLevelNumber = 2 }
        "Error" { $LoggingLevelNumber = 1 }
        Default { $LoggingLevelNumber = 3 }
    }
    switch ($Type) {
        "Verbose" { $TypeLevelNumber = 4 }
        "Info" { $TypeLevelNumber = 3 }
        "Warning" { $TypeLevelNumber = 2 }
        "Error" { $TypeLevelNumber = 1 }
        Default { $TypeLevelNumber = 3 }
    }
    if ($TypeLevelNumber -le $LoggingLevelnumber) {
        $LogMessage = "${Type}: $(Get-Date -Format "MM-dd-yyyy | HH:mm:ss.") | $Message,$($Global:ScriptName)"
        $LogMessage | Out-File $LogFile -Append
    }
}

Function Get-ADUser_FullName {
    param(
        [Parameter(Mandatory = $true)][string]$CSVFile,
        [Parameter(Mandatory = $true)][string]$DomainServer
    )
    $CSVImport = Import-Csv $CSVFile

    Write-Output "FirstName,LastName,UserName,Domain" > Output.csv
    foreach ($user in $CSVImport) {
        $FirstName = $user.FirstName
        $LastName = $user.LastName
        $ADUser = Get-ADUser -server $DomainServer -Filter "GivenName -eq '$FirstName' -and sn -eq '$LastName'" -Properties *
        if ($ADUser) {
            $ADAccountName = $ADUser.SamAccountName
            Write-Output "$FirstName,$LastName,$ADAccountName,$DomainServer" >> Output.csv
        }
    }
}

function Open-File{
    $initialDirectory = "C:\"
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.initialDirectory = $initialDirectory
    $OpenFileDialog.filter = "All files (*.*)| *.*"
    $OpenFileDialog.ShowDialog() |  Out-Null
    return OpenFileDialog.filename
}

function Invoke-AnyKeyToContinue {
    Write-Host -NoNewline 'Press any key to continue...';
    $null = Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
}

Function Publish-ActiveSetup {
    param (
        [Parameter(Mandatory = $true)][string]$ActiveSetupName,
        [Parameter(Mandatory = $true)][string]$VersionNumber,
        [Parameter(Mandatory = $true)][string]$ActiveSetupStubPath
    )

    #Setup ActiveSetup to run at each user login.
    $ParentKey="HKLM:Software\Microsoft\Active Setup\Installed Components"
    $Key=$ParentKey + "\" + $ActiveSetupName
    # Check for key
    if (!(Test-Path $Key)){
        New-Item -type Directory $($ParentKey + "\" + $ActiveSetupName)
    } else {
        Write-Host "Key exists"
    }

    Set-ItemProperty $($Key) -name "StubPath" -value $ActiveSetupStubPath
    Set-ItemProperty $($Key) -name "Version" -value $VersionNumber
    Set-ItemProperty $($Key) -name "Locale" -value "*"0
}

Function Set-NetworkAsPrivate {
    param{
        [string]$NetworkConnectionName
    }
    if ($NetworkConnectionName) {
        Get-NetConnectionProfile;Set-NetConnectionProfile -Name $NetworkConnectionName -NetworkCategory Private
    } else {
        Write-Host "Please supply a network connection name." -ForegroundColor Red
        Write-Host "Available Connection Names:" -ForegroundColor Yellow
        $Connections = Get-NetConnectionProfile
        ForEach ($c in $Connections) {
            Write-Host $c.Name  -ForegroundColor Yellow
        }
    }
}

Function Invoke-FileSystemRepair {
    Write-Host "Starting 1 of 5: SFC Scan"
    sfc /scannow
    Write-Host "Starting 2 of 5: DISM Check Health"
    dism /online /cleanup-image /CheckHealth
    Write-Host "Starting 2 of 5: DISM Scan Health"
    dism /online /cleanup-image /ScanHealth
    Write-Host "Starting 2 of 5: DISM Component Cleanup"
    dism /online /cleanup-image /startcomponentcleanup
    Write-Host "Starting 2 of 5: DISM Restore Health"
    dism /online /cleanup-image /restorehealth
}

Function Invoke-SCCMActions {
    param(
        [switch]$ClearCache
    )

    if ($PSBoundParameters.ContainsKey('ClearCache')) {
        #CLEAR SCCM CACHE
        ## Initialize the CCM resource manager com object
        [__comobject]$CCMComObject = New-Object -ComObject 'UIResource.UIResourceMgr'
        ## Get the CacheElementIDs to delete
        $CacheInfo = $CCMComObject.GetCacheInfo().GetCacheElements()
        ## Remove cache items
        ForEach ($CacheItem in $CacheInfo) {
            $null = $CCMComObject.GetCacheInfo().DeleteCacheElement([string]$($CacheItem.CacheElementID))
        }
    }

    #Machine policy retrieval & Evaluation Cycle
    Start-Process -Wait -Passthru -FilePath "WMIC" -ArgumentList "/namespace:\\root\ccm path sms_client CALL TriggerSchedule '{00000000-0000-0000-0000-000000000002}' /NOINTERACTIVE"
    #Application deployment evaluation cycle
    Start-Process -Wait -Passthru -FilePath "WMIC" -ArgumentList "/namespace:\\root\ccm path sms_client CALL TriggerSchedule '{00000000-0000-0000-0000-000000000121}' /NOINTERACTIVE"
    #Software inventory cycle
    Start-Process -Wait -Passthru -FilePath "WMIC" -ArgumentList "/namespace:\\root\ccm path sms_client CALL TriggerSchedule '{00000000-0000-0000-0000-000000000002}' /NOINTERACTIVE"
}

Function Invoke-RemoteSCCMActions {
    param (
        [Parameter(Mandatory = $true)][string]$ComputerName
    )
    #Machine Policy Evaluation Cycle
    Invoke-WMIMethod -ComputerName $ComputerName -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000022}"
    #Application Deployment Evaluation Cycle
    Invoke-WMIMethod -ComputerName $ComputerName -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000121}"
    #Software Inventory Cycle
    Invoke-WMIMethod -ComputerName $ComputerName -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000002}"
}

Export-ModuleMember -Function Show-UninstallRegistry
Export-ModuleMember -Function Get-OSArchitecture
Export-ModuleMember -Function Write-CustomLog
Export-ModuleMember -Function Get-ADUser_FullName
Export-ModuleMember -Function Open-File
Export-ModuleMember -Function Invoke-AnyKeyToContinue
Export-ModuleMember -Function Publish-ActiveSetup
Export-ModuleMember -Function Set-NetworkAsPrivate
Export-ModuleMember -Function Invoke-FileSystemRepair
Export-ModuleMember -Function Invoke-SCCMActions
Export-ModuleMember -Function Invoke-RemoteSCCMActions