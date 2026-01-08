Function Get-UninstallRegistry {
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
    Write-Host"Importing CSV file $CSVFile" -ForegroundColor Green
    $CSVImport = Import-Csv $CSVFile

    Write-Host "Creating Output.csv. This may take time depending on how many users exist within the CSV." -ForegroundColor Green
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

Function Publish-ActiveSetup {
    param (
        [Parameter(Mandatory = $true)][string]$ActiveSetupName,
        [Parameter(Mandatory = $true)][string]$VersionNumber,
        [Parameter(Mandatory = $true)][string]$ActiveSetupStubPath
    )
    Write-Host "Publishing ActiveSetupwith the following settings:" -ForegroundColor Green
    Write-Host "Name: $ActiveSetupName" -ForegroundColor Green
    Write-Host "Version: $VersionNumber" -ForegroundColor Green
    Write-Host "StubPath: $ActiveSetupStubPath" -ForegroundColor Green

    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\$ActiveSetupUniqueName") {
        $ActiveSetupVersion = $ActiveSetupVersion + 1
    }

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
    Set-ItemProperty $($Key) -name "Locale" -value "*"
}

Function Set-NetworkAsPrivate {
    param{
        [string]$NetworkConnectionName
    }
    if ($NetworkConnectionName) {
        Write-Host "Setting Network Connection, $NetworkConnectionName, to Private" -ForegroundColor Green
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
    Write-Host "Starting 1 of 5: SFC Scan" -ForegroundColor Green
    sfc /scannow
    Write-Host "Starting 2 of 5: DISM Check Health" -ForegroundColor Green
    dism /online /cleanup-image /CheckHealth
    Write-Host "Starting 3 of 5: DISM Scan Health" -ForegroundColor Green
    dism /online /cleanup-image /ScanHealth
    Write-Host "Starting 4 of 5: DISM Component Cleanup" -ForegroundColor Green
    dism /online /cleanup-image /startcomponentcleanup
    Write-Host "Starting 5 of 5: DISM Restore Health" -foregroundColor Green
    dism /online /cleanup-image /restorehealth

    Write-Host "The file system repair has completed. Please check the logs for any errors." -ForegroundColor Green
    Write-Host "C:\Windows\Logs\DISM\dism.log" -ForegroundColor Yellow
    Write-Host "C:\Windows\Logs\CBS\CBS.log" -ForegroundColor Yellow
    Write-Host "C:\Windows\Logs\SFC\sfc.log" -ForegroundColor Yellow
    Write-Host "C:\Windows\Logs\SFC\CBS.log" -ForegroundColor Yellow
    Write-Host "C:\Windows\Logs\SFC\DISM.log" -ForegroundColor Yellow
}

Function Invoke-SCCMActions {
    param(
        [switch]$ClearCache
    )

    if ($PSBoundParameters.ContainsKey('ClearCache')) {
        Write-Host "Clearing SCCM Cache" -ForegroundColor Green
        #CLEAR SCCM CACHE
        ## Initialize the CCM resource manager com object
        [__comobject]$CCMComObject = New-Object -ComObject 'UIResource.UIResourceMgr'
        ## Get the CacheElementIDs to delete
        $CacheInfo = $CCMComObject.GetCacheInfo().GetCacheElements()
        ## Remove cache items
        ForEach ($CacheItem in $CacheInfo) {
            $null = $CCMComObject.GetCacheInfo().DeleteCacheElement([string]$($CacheItem.CacheElementID))
        }

        Write-Host "SCCM Cache cleared" -ForegroundColor Green
    }

    #Machine policy retrieval & Evaluation Cycle
    Write-Host "Starting Machine Policy Retrieval & Evaluation Cycle" -ForegroundColor Green
    Start-Process -Wait -Passthru -FilePath "WMIC" -ArgumentList "/namespace:\\root\ccm path sms_client CALL TriggerSchedule '{00000000-0000-0000-0000-000000000002}' /NOINTERACTIVE"
    #Application deployment evaluation cycle
    Write-Host "Starting Application Deployment Evaluation Cycle" -ForegroundColor Green
    Start-Process -Wait -Passthru -FilePath "WMIC" -ArgumentList "/namespace:\\root\ccm path sms_client CALL TriggerSchedule '{00000000-0000-0000-0000-000000000121}' /NOINTERACTIVE"
    #Software inventory cycle
    Write-Host "Starting Software Inventory Cycle" -ForegroundColor Green
    Start-Process -Wait -Passthru -FilePath "WMIC" -ArgumentList "/namespace:\\root\ccm path sms_client CALL TriggerSchedule '{00000000-0000-0000-0000-000000000002}' /NOINTERACTIVE"

    Write-Host "SCCM actions completed" -ForegroundColor Green
}

Function Invoke-RemoteSCCMActions {
    param (
        [Parameter(Mandatory = $true)][string]$ComputerName
    )

    If ((Test-Connection -ComputerName $ComputerName).PingSucceeded) {
        Write-Host "Connection test to $ComputerName is successful. Continuing with invoking SCCM commands." -ForegroundColor Green
    } else {
        Write-Host "Connection test to $ComputerName failed. Exiting." -ForegroundColor Red
        exit
    }

    #Machine Policy Evaluation Cycle
    Write-Host "Starting Machine Policy Evaluation Cycle against $ComputerName" -ForegroundColor Green
    Invoke-WMIMethod -ComputerName $ComputerName -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000022}"
    #Application Deployment Evaluation Cycle
    Write-Host "Starting Application Deployment Evaluation Cycle against $ComputerName" -ForegroundColor Green
    Invoke-WMIMethod -ComputerName $ComputerName -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000121}"
    #Software Inventory Cycle
    Write-Host "Starting Software Inventory Cycle against $ComputerName" -ForegroundColor Green
    Invoke-WMIMethod -ComputerName $ComputerName -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000002}"

    Write-Host "SCCM actions completed on $ComputerName" -ForegroundColor Green
}

Function New-EventLogSource {
    param (
        [Parameter(Mandatory = $true)][string]$EventLogName
    )
    #set permissions for the event log; read and write to the EventLog key and its subkeys and values.
    $acl= get-acl -path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog"
    $inherit = [system.security.accesscontrol.InheritanceFlags]"ContainerInherit, ObjectInherit"
    $propagation = [system.security.accesscontrol.PropagationFlags]"None"
    $rule=new-object system.security.accesscontrol.registryaccessrule "Authenticated Users","FullControl",$inherit,$propagation,"Allow"
    $acl.addaccessrule($rule)
    $acl|set-acl

    #create the Event Log
    $EventLogExists = Get-EventLog -list | Where-Object {$_.logdisplayname -eq $EventLogName}

    if (! $EventLogExists) {
        Try {
        Write-Host "Creating '$EventLogName' event log"
        New-EventLog -LogName $EventLogName -Source $EventLogName -ErrorAction Ignore| Out-Null
        Write-EventLog -LogName $EventLogName -Source $EventLogName -Message "Creating Event Log $EventLogName" -EventId 0 -EntryType information
        Write-Host "If you have Event Viewer open, you should probably close and reopen it."
        Get-EventLog -list
        } Catch {
            Write-Host "Error creating event log: $_" -ForegroundColor Red
        }
    }
    else{
        Write-Host "There is already an '$EventLogName' event log"
        Write-EventLog -LogName $EventLogName -Source $EventLogName -Message "Hello Event Log $EventLogName" -EventId 0 -EntryType information
    }
}

Function Invoke-ModifyFolderPermissions {
    param (
        [Parameter(Mandatory = $true)][string]$FolderPath
    )

    # Method 2: PowerShell fallback method
    $folderACL = Get-Acl -Path $FolderPath
    $folderAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone","FullControl","ContainerInherit,ObjectInherit","None","Allow")
    $folderACL.SetAccessRule($folderAccessRule)
    Set-Acl -Path $FolderPath -AclObject $folderACL

    # Apply to all subdirectories and files
    Get-ChildItem -Path $FolderPath -Recurse | ForEach-Object {
        try {
            Write-Host "Setting permissions on $($_.FullName)" -ForegroundColor Green
            $itemACL = Get-Acl -Path $_.FullName
            $itemAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone","FullControl","ContainerInherit,ObjectInherit","None","Allow")
            $itemACL.SetAccessRule($itemAccessRule)
            Set-Acl -Path $_.FullName -AclObject $itemACL
        } catch {
            Write-Host "Failed to set permissions on $($_.FullName): $_" -ForegroundColor Red
        }
    }
    Write-Host "Successfully set permissions using PowerShell method" -ForegroundColor Green
}

Function Publish-StartShortcut {
    param (
        [string]$StartFolder,
        [Parameter(Mandatory = $true)][string]$ShortcutLNK,
        [string]$ShortcutIcon,
        [Parameter(Mandatory = $true)][string]$ShortcutEXE,
        [string]$ShortcutArguments
    )
    #Sets default values for optional parameters
    If (!$StartFolder) { $StartFolder = "NEW FOLDER NAME" }
    If (!$ShortcutIcon) { $ShortcutIcon = "PATH TO ICON" }
    If (!$ShortcutArguments) { $ShortcutArguments = "SHORTCUT ARGUMENTS" }

    ###Don't Change $StartPath###
    $StartPath = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs"

    $WshShell = New-Object -ComObject WScript.Shell
    if ($StartFolder -ne "NEW FOLDER NAME") {
        #Write-Log -message "Creating shortcut in $StartPath\StartFolder\$ShortcutLNK" -component "Main" -type "Info"
        if (Test-Path -Path "$StartPath\$StartFolder\$ShortcutLNK") {
            Write-Log -message "Removing existing duplicate shortcut" -component "Main" -type "Info"
            Remove-Item -Path "$StartPath\$StartFolder\$ShortcutLNK" -Force
        }
        Write-Log -message "Creating Start Menu folder" -component "Main" -type "Info"
        New-Item -Name $StartFolder -Path $StartPath -ItemType Directory -Force
        $Shortcut = $WshShell.CreateShortcut("$StartPath\$StartFolder\$ShortcutLNK")

    } else {
        #Write-Log -message "Creating shortcut in $StartPath\ShortcutLNK" -component "Main" -type "Info"
        if (Test-Path -Path "$StartPath\$ShortcutLNK") {
            Write-Log -message "Removing existing duplicate shortcut" -component "Main" -type "Info"
            Remove-Item -Path "$StartPath\$ShortcutLNK" -Force
        }
        $Shortcut = $WshShell.CreateShortcut("$StartPath\$ShortcutLNK")
    }
    $Shortcut.TargetPath = $ShortcutEXE
    if ($ShortcutIcon -ne "PATH TO ICON") {
        Write-Log -message "Adding icon to shortcut: $ShortcutIcon" -component "Main" -type "Info"
        $Shortcut.IconLocation = $ShortcutIcon
    }
    if ($ShortcutArguments -ne "SHORTCUT ARGUMENTS") {
        Write-Log -message "Adding arguments to shortcut: $ShortcutArguments" -component "Main" -type "Info"
        $Shortcut.Arguments = $ShortcutArguments
    }
    $Shortcut.Save()
}

Export-ModuleMember -Function Get-UninstallRegistry
Export-ModuleMember -Function Get-OSArchitecture
Export-ModuleMember -Function Write-CustomLog
Export-ModuleMember -Function Get-ADUser_FullName
Export-ModuleMember -Function Open-File
Export-ModuleMember -Function Publish-ActiveSetup
Export-ModuleMember -Function Set-NetworkAsPrivate
Export-ModuleMember -Function Invoke-FileSystemRepair
Export-ModuleMember -Function Invoke-SCCMActions
Export-ModuleMember -Function Invoke-RemoteSCCMActions
Export-ModuleMember -Function New-EventLogSource
Export-ModuleMember -Function Invoke-ModifyFolderPermissions
Export-ModuleMember -Function Publish-StartShortcut