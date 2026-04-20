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
# Set-AppNotification.ps1 - By Bitpusher/The Digital Fox
# v2.0 last updated 2026-04-19
# Script to enable/disable Windows notifications for an application by name for all users.
#
# Modifies the per-user wpndatabase.db SQLite database to set the toast notification
# setting for matching application handlers. Iterates through all user profiles.
#
# Usage:
# powershell -executionpolicy bypass -f .\Set-AppNotification.ps1 -AppName "firefox" -Action "0"
#
# Run as administrator to access other user profile directories.
#
# Requires PSSQLite module - will be installed automatically if not present.
#
# To set up as a scheduled task (runs daily at 6 AM):
# schtasks /create /tn "Set-AppNotification" /tr "powershell -executionpolicy bypass -f C:\Utility\Set-AppNotification.ps1 -AppName 'firefox' -Action '0'" /sc daily /st 06:00 /ru SYSTEM /rl HIGHEST
#
# To undo/re-enable notifications:
# powershell -executionpolicy bypass -f .\Set-AppNotification.ps1 -AppName "firefox" -Action "1"
#
# Email/share parameters can be configured to forward logs after execution.
#
#script #powershell #application #notification #enable #disable #windows #toast

#Requires -Version 5.1

param(
    # --- script-specific params ---
    [string]$AppName = "firefox",
    [string]$Action = "0", # 0 to disable notifications, 1 to enable notifications
    # --- standard infrastructure params ---
    [string]$scriptName = "Set-AppNotification",
    [string]$Priority = "Normal",
    [int]$RandMax = "500",
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

    function Test-FileLock {
        param([Parameter(Mandatory = $true)] [string]$Path)
        $oFile = New-Object System.IO.FileInfo $Path
        if ((Test-Path -Path $Path) -eq $false) { return $false }
        try {
            $oStream = $oFile.Open([System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            if ($oStream) { $oStream.Close() }
            return $false
        } catch { return $true }
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

    #region install-modules
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $modules = @("PSSQLite")
    foreach ($module in $modules) {
        if (Get-Module -ListAvailable -Name $module) {
            Write-Verbose "$(Get-TimeStamp) $module already installed"
        } else {
            Install-Module $module -Force -SkipPublisherCheck -Scope CurrentUser -ErrorAction Stop | Out-Null
            Import-Module $module -Force -Scope Local | Out-Null
        }
    }
    #endregion install-modules

    #region main
    Set-PSDebug -Trace 0
    [int]$MyExitStatus = 1
    $StartTime = $(Get-Date)
    Write-Output "Script $scriptName started at $(Get-TimeStamp)"
    Write-Output "ISO8601:$(Get-Date (Get-Date).ToUniversalTime() -UFormat '+%Y%m%dT%H%M%S.000Z')`n"
    $RandSeconds = Get-Random -Minimum 1 -Maximum $RandMax
    Write-Output "Waiting $RandSeconds seconds to stagger execution`n"
    Start-Sleep -Seconds $RandSeconds

    Import-Module PSSQLite

    $ActionLabel = if ($Action -eq "0") { "Disabling" } else { "Enabling" }
    Write-Output "$ActionLabel notifications for applications matching '$AppName'..."

    $DatabasePaths = Get-ChildItem "C:\Users\*\AppData\Local\Microsoft\Windows\Notifications\wpndatabase.db" -ErrorAction SilentlyContinue
    if (-not $DatabasePaths) {
        Write-Output "No notification databases found under C:\Users\*."
    }

    $TotalUpdated = 0
    $TotalSkipped = 0
    $TotalDbProcessed = 0

    foreach ($DBPath in $DatabasePaths.FullName) {
        $TotalDbProcessed++
        $UserFolder = ($DBPath -split '\\')[2]
        Write-Output "`nProcessing database for user: $UserFolder"
        Write-Output "  Database: $DBPath"

        # Check if the database file is locked by the user's session
        if (Test-FileLock -Path $DBPath) {
            Write-Warning "$(Get-TimeStamp) Database is locked (user may be logged in): $DBPath - Skipping."
            continue
        }

        $SelectQuery = @"
            SELECT *
            FROM NotificationHandler AS NH
            INNER JOIN HandlerSettings AS HS ON NH.RecordId = HS.HandlerID
            WHERE NH.PrimaryId LIKE '%$AppName%'
            AND HS.SettingKey = 's:toast'
"@

        try {
            $NotificationSettings = Invoke-SqliteQuery -DataSource $DBPath -Query $SelectQuery -ErrorAction Stop
        } catch {
            Write-Warning "$(Get-TimeStamp) Failed to query database $DBPath : $($_.Exception.Message)"
            continue
        }

        if (-not $NotificationSettings) {
            Write-Output "  No notification handlers matching '$AppName' found in this database."
            continue
        }

        Write-Output "  Found $($NotificationSettings.Count) matching handler(s)."

        foreach ($Setting in $NotificationSettings) {
            Write-Output "    Handler: $($Setting.PrimaryId) - Current value: $($Setting.Value)"
            if ($Setting.Value -ne $Action) {
                $UpdateQuery = @"
                    UPDATE HandlerSettings
                    SET Value = $Action
                    WHERE HandlerId = '$($Setting.HandlerId)' AND SettingKey = 's:toast'
"@
                try {
                    Invoke-SqliteQuery -DataSource $DBPath -Query $UpdateQuery -ErrorAction Stop
                    Write-Output "    Updated to: $Action"
                    $TotalUpdated++
                } catch {
                    Write-Warning "$(Get-TimeStamp) Failed to update handler $($Setting.HandlerId) in $DBPath : $($_.Exception.Message)"
                }
            } else {
                Write-Output "    Already set to $Action - No change needed."
                $TotalSkipped++
            }
        }

        # Verify changes
        try {
            $VerifySettings = Invoke-SqliteQuery -DataSource $DBPath -Query $SelectQuery -ErrorAction Stop
            foreach ($Setting in $VerifySettings) {
                Write-Output "    Verified: $($Setting.PrimaryId) = $($Setting.Value)"
            }
        } catch {
            Write-Warning "$(Get-TimeStamp) Failed to verify changes in $DBPath : $($_.Exception.Message)"
        }
    }

    Write-Output "`n--- Summary ---"
    Write-Output "Databases processed: $TotalDbProcessed"
    Write-Output "Handlers updated: $TotalUpdated"
    Write-Output "Handlers already correct: $TotalSkipped"

    $MyExitStatus = 0
    #endregion main

    #region finalization
    if ($logFileFolderPath -ne "") {
        Write-Output "`nScript $scriptName ended at $(Get-TimeStamp)"
        $elapsedTime = $(Get-Date) - $StartTime
        Write-Output "Elapsed time (seconds): $($elapsedTime.TotalSeconds)"
        Stop-Transcript
        if (($emailServer -ne "") -and ($emailUsername -ne "") -and ($emailPassword -ne "") -and ($emailFrom -ne "") -and ($emailTo -ne "")) {
            Send-MailMessage -SmtpServer "$emailServer" -Port $emailPort -From "$emailFrom" -To "$emailTo" `
                -Subject "$scriptName - $ComputerName - $TotalUpdated handlers updated" -Body "$logFilePath" -UseSsl `
                -Credential (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$emailUsername", (ConvertTo-SecureString -String "$emailPassword" -AsPlainText -Force)) `
                -Attachments $logFilePath
        }
        if (($shareLocation -ne "") -and ($shareUsername -ne "") -and ($sharePassword -ne "")) {
            [securestring]$secStringPassword = ConvertTo-SecureString $sharePassword -AsPlainText -Force
            [pscredential]$shareCred = New-Object System.Management.Automation.PSCredential ($shareUsername, $secStringPassword)
            New-PSDrive -Name LogStore -PSProvider FileSystem -Root "$shareLocation" -Description "Log Store" -Credential $shareCred
            Copy-Item -LiteralPath "$logFilePath" -Destination "LogStore:\" -Force -ErrorAction Continue
            Remove-PSDrive -Name LogStore
        } elseif ($shareLocation -ne "") {
            Copy-Item -LiteralPath $LogFilePath -Destination $ShareLocation -Force -ErrorAction Continue
        }
    }
    Set-PSDebug -Trace 0
    exit $MyExitStatus
    #endregion finalization
}
