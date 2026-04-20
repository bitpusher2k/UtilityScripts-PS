#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#          @VinceVulpes
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Detect-Persistence.ps1 - By Bitpusher/The Digital Fox
# v1.3 last updated 2026-04-19
# Script to scan common persistence mechanisms on a Windows endpoint and output a CSV report.
# Checks: Registry Run/RunOnce keys (HKLM + all user hives), scheduled tasks (non-Microsoft),
# startup folders (All Users + per-user), services (non-system), WMI event subscriptions,
# LSA authentication/notification packages, and Active Setup registry entries.
# Intended for incident response triage and scheduled security audits.
#
# Run with admin/SYSTEM privileges for full coverage (WMI subscriptions, all user hives).
#
# Usage:
# powershell -executionpolicy bypass -f .\Detect-Persistence.ps1
# powershell -executionpolicy bypass -f .\Detect-Persistence.ps1 -OutputPath "C:\temp" -FlagSuspicious 1
#
# Email report to yourself by including the emailServer, emailFrom, emailTo,
# emailUsername, and emailPassword parameters.
#
# To run as a scheduled task start PowerShell:
# C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.exe
# With arguments: -Command "& 'C:\Utility\Detect-Persistence.ps1'"
#
#comp #security #incident #persistence #autoruns #registry #scheduled #task #wmi #service #script #powershell

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$OutputPath = "C:\temp",               # Folder for CSV report output
    [int]$FlagSuspicious = 1,                       # 1 = add Suspicious column with heuristic flags
    [string]$scriptName = "Detect-Persistence",
    [string]$Priority = "Normal",
    [int]$RandMax = "10",
    [string]$DebugPreference = "SilentlyContinue",
    [string]$VerbosePreference = "SilentlyContinue",
    [string]$InformationPreference = "Continue",
    [string]$logFileFolderPath = "C:\Utility\log",
    [string]$ComputerName = $env:computername,
    [string]$ScriptUserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
    [string]$emailServer = "",
    [string]$emailPort = "587",
    [string]$emailFrom = "",
    [string]$emailTo = "",
    [string]$emailUsername = "",
    [string]$emailPassword = "",
    [string]$shareLocation = "",
    [string]$shareUsername = "",
    [string]$sharePassword = "",
    [string]$logFilePrefix = "$scriptName" + "_" + "$ComputerName" + "_",
    [string]$logFileDateFormat = "yyyyMMdd_HHmmss",
    [int]$logFileRetentionDays = 30,
    [string]$Encoding = "utf8bom" # "ascii","ansi","bigendianunicode","unicode","utf8","utf8NoBOM","utf32"
)

process {
    #region initialization
    if ($PSVersionTable.PSVersion.Major -eq 5 -and ($Encoding -eq "utf8bom" -or $Encoding -eq "utf8nobom")) { $Encoding = "utf8" }

    function Get-TimeStamp {
        param([switch]$NoWrap, [switch]$Utc)
        $dt = Get-Date
        if ($Utc -eq $true) { $dt = $dt.ToUniversalTime() }
        $str = "{0:yyyy-MM-dd} {0:HH:mm:ss}" -f $dt
        if ($NoWrap -ne $true) { $str = "[$str]" }
        return $str
    }

    if ($logFileFolderPath -ne "") {
        if (!(Test-Path -PathType Container -Path $logFileFolderPath)) {
            New-Item -ItemType Directory -Force -Path $logFileFolderPath | Out-Null
        } else {
            $DatetoDelete = $(Get-Date).AddDays(-$logFileRetentionDays)
            Get-ChildItem $logFileFolderPath | Where-Object { $_.Name -like "*$logFilePrefix*" -and $_.LastWriteTime -lt $DatetoDelete } | Remove-Item | Out-Null
        }
        $logFilePath = $logFileFolderPath + "\$logFilePrefix" + (Get-Date -Format $logFileDateFormat) + ".LOG"
        try {
            Start-Transcript -Path $logFilePath -Append
        } catch [Exception] {
            Write-Warning "$(Get-TimeStamp) Unable to start Transcript: $($_.Exception.Message)"
            $logFileFolderPath = ""
        }
    }

    $process = Get-Process -Id $pid
    $process.PriorityClass = $Priority
    #endregion initialization

    #region main
    Set-PSDebug -Trace 0
    [int]$MyExitStatus = 1
    $StartTime = $(Get-Date)
    Write-Output "Script $scriptName started at $(Get-TimeStamp)"
    Write-Output "ISO8601:$(Get-Date (Get-Date).ToUniversalTime() -UFormat '+%Y%m%dT%H%M%S.000Z')`n"
    $RandSeconds = Get-Random -Minimum 1 -Maximum $RandMax
    Write-Output "Waiting $RandSeconds seconds to stagger execution`n"
    Start-Sleep -Seconds $RandSeconds

    # Ensure output path exists
    New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
    $ReportPath = "$OutputPath\$ComputerName-Persistence-$($(Get-Date).ToString('yyyyMMddHHmm')).csv"

    $Results = [System.Collections.Generic.List[PSCustomObject]]::new()

    function Add-Finding {
        param(
            [string]$Category,
            [string]$Name,
            [string]$Value,
            [string]$Path,
            [string]$Notes = ""
        )
        $suspicious = ""
        if ($FlagSuspicious -eq 1) {
            # Heuristic: flag entries pointing at temp/appdata/unusual dirs or encoded commands
            $suspiciousPaths = @("\\temp\\", "\\tmp\\", "\\appdata\\local\\temp", "\\users\\public\\", "\\windows\\temp\\", "\\recycle", "\\downloads\\")
            $suspiciousKeywords = @("-enc ", "-encodedcommand", "iex(", "invoke-expression", "downloadstring", "hidden", "bypass", "frombase64")
            $combined = ($Value + $Path).ToLower()
            foreach ($s in $suspiciousPaths) { if ($combined -like "*$s*") { $suspicious = "SuspiciousPath"; break } }
            if ($suspicious -eq "") {
                foreach ($k in $suspiciousKeywords) { if ($combined -like "*$k*") { $suspicious = "SuspiciousKeyword"; break } }
            }
        }
        $Results.Add([PSCustomObject]@{
            ComputerName = $ComputerName
            Category     = $Category
            Name         = $Name
            Value        = $Value
            Path         = $Path
            Notes        = $Notes
            Suspicious   = $suspicious
            Timestamp    = (Get-Date -Format "o")
        })
    }

    # ----------------------------------------------------------------
    # 1. Registry Run / RunOnce keys - HKLM
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Checking HKLM Run/RunOnce registry keys..."
    $HKLMRunKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    )
    foreach ($key in $HKLMRunKeys) {
        if (Test-Path $key) {
            $props = Get-ItemProperty $key -ErrorAction SilentlyContinue
            if ($props) {
                $props.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                    Add-Finding -Category "RunKey-HKLM" -Name $_.Name -Value ($_.Value -join "; ") -Path $key
                }
            }
        }
    }

    # ----------------------------------------------------------------
    # 2. Registry Run / RunOnce keys - All user HKCU hives
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Checking HKCU Run/RunOnce registry keys for all user profiles..."
    $HKCURunSubkeys = @(
        "SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    # Load unloaded hives temporarily
    $ProfileList = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" -ErrorAction SilentlyContinue
    foreach ($profile in $ProfileList) {
        $profilePath = (Get-ItemProperty $profile.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
        $sid = $profile.PSChildName
        if ($sid -notmatch "^S-1-5-21") { continue } # only real user accounts
        $hiveLoaded = Test-Path "Registry::HKEY_USERS\$sid"
        if (-not $hiveLoaded) {
            $hivePath = "$profilePath\NTUSER.DAT"
            if (Test-Path $hivePath) {
                Start-Process reg -ArgumentList "LOAD HKU\$sid `"$hivePath`"" -PassThru -Wait | Out-Null
                $hiveLoaded = $true
                $loadedHive = $true
            }
        } else { $loadedHive = $false }

        foreach ($subkey in $HKCURunSubkeys) {
            $fullKey = "Registry::HKEY_USERS\$sid\$subkey"
            if (Test-Path $fullKey) {
                $props = Get-ItemProperty $fullKey -ErrorAction SilentlyContinue
                if ($props) {
                    $props.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                        Add-Finding -Category "RunKey-HKCU" -Name $_.Name -Value ($_.Value -join "; ") -Path $fullKey -Notes "SID:$sid Profile:$profilePath"
                    }
                }
            }
        }
        if ($loadedHive) {
            Start-Process reg -ArgumentList "UNLOAD HKU\$sid" -PassThru -Wait | Out-Null
        }
    }

    # ----------------------------------------------------------------
    # 3. Scheduled Tasks (non-Microsoft)
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Checking scheduled tasks..."
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            $_.TaskPath -notlike "\Microsoft\*" -and $_.State -ne "Disabled"
        }
        foreach ($task in $tasks) {
            $actions = $task.Actions | ForEach-Object {
                if ($_.Execute) { "$($_.Execute) $($_.Arguments)" } else { $_.ClassId }
            }
            Add-Finding -Category "ScheduledTask" -Name $task.TaskName -Value ($actions -join " | ") -Path $task.TaskPath -Notes "State:$($task.State) Author:$($task.Author)"
        }
    } catch {
        Write-Warning "$(Get-TimeStamp) Error enumerating scheduled tasks: $($_.Exception.Message)"
    }

    # ----------------------------------------------------------------
    # 4. Startup Folders
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Checking startup folders..."
    $startupFolders = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    # Also check per-user startup folders from profile list
    foreach ($profile in $ProfileList) {
        $profilePath = (Get-ItemProperty $profile.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
        $sid = $profile.PSChildName
        if ($sid -notmatch "^S-1-5-21") { continue }
        $userStartup = "$profilePath\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
        if ($userStartup -notin $startupFolders) { $startupFolders += $userStartup }
    }
    foreach ($folder in $startupFolders) {
        if (Test-Path $folder) {
            Get-ChildItem $folder -File -ErrorAction SilentlyContinue | ForEach-Object {
                Add-Finding -Category "StartupFolder" -Name $_.Name -Value $_.FullName -Path $folder -Notes "Size:$($_.Length) Modified:$($_.LastWriteTime)"
            }
        }
    }

    # ----------------------------------------------------------------
    # 5. Services (non-system / third-party)
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Checking non-system services..."
    $SystemServicePaths = @("system32", "syswow64", "sysmon", "program files\windows defender")
    $allServices = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.StartMode -ne "Disabled" }
    foreach ($svc in $allServices) {
        $isSystem = $false
        foreach ($sp in $SystemServicePaths) {
            if ($svc.PathName -ilike "*$sp*") { $isSystem = $true; break }
        }
        if (-not $isSystem) {
            Add-Finding -Category "Service" -Name $svc.Name -Value $svc.PathName -Path $svc.PathName -Notes "State:$($svc.State) StartMode:$($svc.StartMode) Account:$($svc.StartName) DisplayName:$($svc.DisplayName)"
        }
    }

    # ----------------------------------------------------------------
    # 6. WMI Event Subscriptions
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Checking WMI event subscriptions..."
    try {
        $wmiFilters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
        foreach ($filter in $wmiFilters) {
            Add-Finding -Category "WMI-EventFilter" -Name $filter.Name -Value $filter.Query -Path "root\subscription\__EventFilter" -Notes "QueryLanguage:$($filter.QueryLanguage)"
        }
        $wmiConsumers = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue
        foreach ($consumer in $wmiConsumers) {
            $value = if ($consumer.CommandLineTemplate) { $consumer.CommandLineTemplate } elseif ($consumer.ScriptText) { $consumer.ScriptText } else { $consumer.PSObject.Properties | Where-Object { $_.Name -notlike "__*" -and $_.Value } | ForEach-Object { "$($_.Name)=$($_.Value)" } | Select-Object -First 3 | Join-String -Separator "; " }
            Add-Finding -Category "WMI-EventConsumer" -Name $consumer.Name -Value $value -Path "root\subscription\__EventConsumer" -Notes "Class:$($consumer.CimClass.CimClassName)"
        }
        $wmiBindings = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue
        foreach ($binding in $wmiBindings) {
            Add-Finding -Category "WMI-Binding" -Name "$($binding.Filter) -> $($binding.Consumer)" -Value "" -Path "root\subscription\__FilterToConsumerBinding"
        }
    } catch {
        Write-Warning "$(Get-TimeStamp) Error querying WMI subscriptions (may require SYSTEM): $($_.Exception.Message)"
    }

    # ----------------------------------------------------------------
    # 7. LSA Authentication & Notification Packages
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Checking LSA authentication packages..."
    $LsaKeys = @{
        "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"                                                           = @("Authentication Packages", "Notification Packages", "Security Packages")
        "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig"                                                  = @("Security Packages")
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"                                          = @("Userinit", "Shell", "Taskman")
    }
    foreach ($keyPath in $LsaKeys.Keys) {
        if (Test-Path $keyPath) {
            foreach ($valueName in $LsaKeys[$keyPath]) {
                $val = (Get-ItemProperty $keyPath -ErrorAction SilentlyContinue).$valueName
                if ($val) {
                    $knownDefaults = @("msv1_0", "schannel", "wdigest", "tspkg", "pku2u", "cloudap", "kerberos", "explorer.exe", "userinit.exe,", "C:\Windows\system32\userinit.exe,")
                    $entries = $val -split "`n|,| " | Where-Object { $_ -and $_ -notin $knownDefaults }
                    foreach ($entry in $entries) {
                        Add-Finding -Category "LSA-Package" -Name $valueName -Value $entry -Path $keyPath -Notes "FullValue:$($val -join ', ')"
                    }
                }
            }
        }
    }

    # ----------------------------------------------------------------
    # 8. Active Setup
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Checking Active Setup registry entries..."
    $ActiveSetupKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components"
    )
    foreach ($key in $ActiveSetupKeys) {
        if (Test-Path $key) {
            Get-ChildItem $key -ErrorAction SilentlyContinue | ForEach-Object {
                $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                $stubPath = $props.StubPath
                if ($stubPath -and $stubPath -notlike "*system32*" -and $stubPath -notlike "*syswow64*") {
                    Add-Finding -Category "ActiveSetup" -Name ($props."(default)" -or $_.PSChildName) -Value $stubPath -Path $_.PSPath -Notes "GUID:$($_.PSChildName)"
                }
            }
        }
    }

    # ----------------------------------------------------------------
    # Summary and Export
    # ----------------------------------------------------------------
    $FindingCount = $Results.Count
    $SuspiciousCount = ($Results | Where-Object { $_.Suspicious -ne "" }).Count
    Write-Output "`n$(Get-TimeStamp) Scan complete. Found $FindingCount persistence entries."
    if ($FlagSuspicious -eq 1) {
        Write-Output "$(Get-TimeStamp) Entries flagged as suspicious: $SuspiciousCount"
    }
    Write-Output "`nCategory breakdown:"
    $Results | Group-Object Category | Sort-Object Count -Descending | ForEach-Object {
        Write-Output "  $($_.Name): $($_.Count)"
    }

    $Results | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding $Encoding
    Write-Output "`nReport saved to: $ReportPath"

    # Also print flagged entries to console for quick review
    if ($FlagSuspicious -eq 1 -and $SuspiciousCount -gt 0) {
        Write-Output "`n=== FLAGGED ENTRIES ==="
        $Results | Where-Object { $_.Suspicious -ne "" } | ForEach-Object {
            Write-Output "  [$($_.Category)] $($_.Name) => $($_.Value) [$($_.Suspicious)]"
        }
    }

    $MyExitStatus = 0
    #endregion main

    #region finalization
    if ($logFileFolderPath -ne "") {
        Write-Output "`nScript $scriptName ended at $(Get-TimeStamp)"
        $elapsedTime = $(Get-Date) - $StartTime
        Write-Output "Elapsed time (seconds): $($elapsedTime.TotalSeconds)"
        Stop-Transcript
        if (($emailServer -ne "") -and ($emailUsername -ne "") -and ($emailPassword -ne "") -and ($emailFrom -ne "") -and ($emailTo -ne "")) {
            Send-MailMessage -SmtpServer "$emailServer" -Port $emailPort -From "$emailFrom" -To "$emailTo" -Subject "$scriptName - $ComputerName - $MyExitStatus - Log File" -Body "$logFilePath" -UseSsl -Credential (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$emailUsername", (ConvertTo-SecureString -String "$emailPassword" -AsPlainText -Force)) -Attachments $logFilePath, $ReportPath
        }
        if (($shareLocation -ne "") -and ($shareUsername -ne "") -and ($sharePassword -ne "")) {
            [securestring]$secStringPassword = ConvertTo-SecureString $sharePassword -AsPlainText -Force
            [pscredential]$shareCred = New-Object System.Management.Automation.PSCredential ($shareUsername, $secStringPassword)
            New-PSDrive -Name LogStore -PSProvider FileSystem -Root "$shareLocation" -Description "Log Store" -Credential $shareCred
            Copy-Item -LiteralPath "$logFilePath" -Destination "LogStore:\" -Force -ErrorAction Continue
            Copy-Item -LiteralPath "$ReportPath" -Destination "LogStore:\" -Force -ErrorAction Continue
            Remove-PSDrive -Name LogStore
        } elseif ($shareLocation -ne "") {
            Copy-Item -LiteralPath $LogFilePath -Destination $ShareLocation  -Force -ErrorAction Continue
        }
    }
    Set-PSDebug -Trace 0
    exit $MyExitStatus
    #endregion finalization
}
