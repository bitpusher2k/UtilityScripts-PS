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
# Deploy-Sysmon.ps1 - By Bitpusher/The Digital Fox
# v1.0 last updated 2026-04-19
# Script to deploy, upgrade, or update Sysmon configuration on an
# endpoint using the SwiftOnSecurity sysmon-config ruleset.
#
# Downloads the latest Sysmon binary from Microsoft Sysinternals and the
# latest SwiftOnSecurity export config from GitHub, then:
#   - Installs Sysmon if not already present (with retry logic)
#   - Upgrades Sysmon if a newer version is available
#   - Updates the running config if Sysmon is already current
#
# Usage:
# powershell -executionpolicy bypass -f ./Deploy-Sysmon.ps1
# powershell -executionpolicy bypass -f ./Deploy-Sysmon.ps1 -StagingPath "D:\staging\Sysmon"
# powershell -executionpolicy bypass -f ./Deploy-Sysmon.ps1 -ConfigUrl "https://example.com/custom-sysmon.xml"
#
# Run as administrator - Sysmon installation requires elevated privileges.
#
# References:
#   Sysmon - https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
#   SwiftOnSecurity sysmon-config - https://github.com/SwiftOnSecurity/sysmon-config
#   Sysmon usage guide - https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#usage
#
#comp #security #sysmon #deployment #powershell

#Requires -Version 5.1
#Requires -RunAsAdministrator

param(
    # --- script-specific params ---
    [string]$StagingPath = "C:\temp\SysmonDeploy",
    [string]$SysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip",
    [string]$ConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml",
    [int]$InstallRetries = 3,
    [int]$RetrySleepSeconds = 3,

    # --- standard infrastructure params ---
    [string]$scriptName = "Deploy-Sysmon",
    [string]$Priority = "Normal",
    [int]$RandMax = "2",
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
    [string]$Encoding = "utf8bom"
)

Process {
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
    }

    $process = Get-Process -Id $pid
    $process.PriorityClass = $Priority
    #endregion initialization

    #region main
    Set-PSDebug -Trace 0
    [int]$MyExitStatus = 1
    $StartTime = $(Get-Date)
    Write-Output "Script $scriptName started at $(Get-TimeStamp)" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "ISO8601:$(Get-Date (Get-Date).ToUniversalTime() -UFormat '+%Y%m%dT%H%M%S.000Z')`n" | Tee-Object -FilePath $logFilePath -Append
    $RandSeconds = Get-Random -Minimum 1 -Maximum $RandMax
    Write-Output "Waiting $RandSeconds seconds to stagger execution`n" | Tee-Object -FilePath $logFilePath -Append
    Start-Sleep -Seconds $RandSeconds

    # === Sysmon Deploy/Update Logic ===

    try {
        # --- Stage files ---
        Write-Output "$(Get-TimeStamp) Creating staging directory: $StagingPath" | Tee-Object -FilePath $logFilePath -Append
        New-Item -Path $StagingPath -ItemType Directory -Force | Out-Null

        $sysmonZipPath = Join-Path $StagingPath "Sysmon.zip"
        $configPath = Join-Path $StagingPath "sysmonconfig.xml"
        $sysmon64StagedPath = Join-Path $StagingPath "Sysmon64.exe"

        Write-Output "$(Get-TimeStamp) Downloading Sysmon from: $SysmonUrl" | Tee-Object -FilePath $logFilePath -Append
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $SysmonUrl -OutFile $sysmonZipPath -UseBasicParsing -ErrorAction Stop

        Write-Output "$(Get-TimeStamp) Extracting Sysmon archive" | Tee-Object -FilePath $logFilePath -Append
        Expand-Archive -Path $sysmonZipPath -DestinationPath $StagingPath -Force

        if (-not (Test-Path $sysmon64StagedPath)) {
            Write-Output "$(Get-TimeStamp) ERROR: Sysmon64.exe not found in archive at $sysmon64StagedPath" | Tee-Object -FilePath $logFilePath -Append
            throw "Sysmon64.exe not found after extraction"
        }

        Write-Output "$(Get-TimeStamp) Downloading SwiftOnSecurity config from: $ConfigUrl" | Tee-Object -FilePath $logFilePath -Append
        Invoke-WebRequest -Uri $ConfigUrl -OutFile $configPath -UseBasicParsing -ErrorAction Stop

        # --- Determine versions ---
        $newVersion = (Get-Item $sysmon64StagedPath).VersionInfo.FileVersion
        Write-Output "$(Get-TimeStamp) Downloaded Sysmon version: $newVersion" | Tee-Object -FilePath $logFilePath -Append

        $installedFile = Get-Item "C:\Windows\Sysmon64.exe", "C:\Windows\Sysmon.exe" -ErrorAction SilentlyContinue |
            Sort-Object { [version]$_.VersionInfo.FileVersion } -Descending |
            Select-Object -First 1
        $installedVersion = $installedFile.VersionInfo.FileVersion

        if ($installedVersion) {
            Write-Output "$(Get-TimeStamp) Installed Sysmon version: $installedVersion" | Tee-Object -FilePath $logFilePath -Append
        } else {
            Write-Output "$(Get-TimeStamp) No installed Sysmon binary found in C:\Windows" | Tee-Object -FilePath $logFilePath -Append
        }

        # --- Determine action: Install / Upgrade / Config-only ---
        $svc = Get-Service Sysmon* -ErrorAction SilentlyContinue

        if (-not $svc) {
            # --- Fresh install with retry ---
            Write-Output "$(Get-TimeStamp) Sysmon service not found - installing with retry (max $InstallRetries attempts)" | Tee-Object -FilePath $logFilePath -Append
            $attempt = 0
            while ($attempt -lt $InstallRetries -and -not (Get-Service Sysmon64 -ErrorAction SilentlyContinue)) {
                $attempt++
                Write-Output "$(Get-TimeStamp) Install attempt $attempt of $InstallRetries" | Tee-Object -FilePath $logFilePath -Append
                # Clean up any residual manifest registration
                Start-Process -FilePath "wevtutil" -ArgumentList "um", "C:\Windows\Sysmon64.exe" -Wait -NoNewWindow -ErrorAction SilentlyContinue
                Start-Process -FilePath $sysmon64StagedPath -ArgumentList "-accepteula", "-i", $configPath -Wait -NoNewWindow
                Start-Sleep -Seconds $RetrySleepSeconds
            }
            if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {
                Write-Output "$(Get-TimeStamp) Sysmon installed successfully after $attempt attempt(s)" | Tee-Object -FilePath $logFilePath -Append
            } else {
                Write-Output "$(Get-TimeStamp) ERROR: Sysmon installation failed after $InstallRetries attempts" | Tee-Object -FilePath $logFilePath -Append
                throw "Sysmon installation failed"
            }

        } elseif ($installedVersion -and [version]$newVersion -gt [version]$installedVersion) {
            # --- Upgrade ---
            Write-Output "$(Get-TimeStamp) Upgrading Sysmon from $installedVersion to $newVersion" | Tee-Object -FilePath $logFilePath -Append
            # Uninstall existing (try both 32-bit and 64-bit)
            $sysmonStaged32 = Join-Path $StagingPath "Sysmon.exe"
            if (Test-Path $sysmonStaged32) {
                Start-Process -FilePath $sysmonStaged32 -ArgumentList "-accepteula", "-u" -Wait -NoNewWindow -ErrorAction SilentlyContinue
            }
            Start-Process -FilePath $sysmon64StagedPath -ArgumentList "-accepteula", "-u" -Wait -NoNewWindow -ErrorAction SilentlyContinue
            # Clean up event manifest
            Start-Process -FilePath "wevtutil" -ArgumentList "um", "C:\Windows\Sysmon64.exe" -Wait -NoNewWindow -ErrorAction SilentlyContinue
            # Install new version
            Start-Process -FilePath $sysmon64StagedPath -ArgumentList "-accepteula", "-i", $configPath -Wait -NoNewWindow
            Write-Output "$(Get-TimeStamp) Sysmon upgrade complete" | Tee-Object -FilePath $logFilePath -Append

        } else {
            # --- Config update only ---
            Write-Output "$(Get-TimeStamp) Sysmon already installed at version $installedVersion - updating config only" | Tee-Object -FilePath $logFilePath -Append
            Start-Process -FilePath $sysmon64StagedPath -ArgumentList "-c", $configPath -Wait -NoNewWindow
            Write-Output "$(Get-TimeStamp) Sysmon config updated" | Tee-Object -FilePath $logFilePath -Append
        }

        # --- Verification ---
        Write-Output "`n$(Get-TimeStamp) === Verification ===" | Tee-Object -FilePath $logFilePath -Append

        $sysmonServices = Get-Service Sysmon* -ErrorAction SilentlyContinue
        if ($sysmonServices) {
            foreach ($s in $sysmonServices) {
                Write-Output "$(Get-TimeStamp) Service: $($s.Name) - Status: $($s.Status)" | Tee-Object -FilePath $logFilePath -Append
            }
        } else {
            Write-Output "$(Get-TimeStamp) WARNING: No Sysmon service found after deployment" | Tee-Object -FilePath $logFilePath -Append
        }

        try {
            $latestEvent = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 -ErrorAction Stop
            Write-Output "$(Get-TimeStamp) Latest Sysmon event: ID=$($latestEvent.Id) Time=$($latestEvent.TimeCreated)" | Tee-Object -FilePath $logFilePath -Append
        } catch {
            Write-Output "$(Get-TimeStamp) WARNING: Unable to read Sysmon event log - $($_.Exception.Message)" | Tee-Object -FilePath $logFilePath -Append
        }

        $MyExitStatus = 0

    } catch {
        Write-Output "$(Get-TimeStamp) ERROR: $($_.Exception.Message)" | Tee-Object -FilePath $logFilePath -Append
        Write-Output "$(Get-TimeStamp) Stack trace: $($_.ScriptStackTrace)" | Tee-Object -FilePath $logFilePath -Append
    }
    #endregion main

    #region finalization
    if ($logFileFolderPath -ne "") {
        Write-Output "`nScript $scriptName ended at $(Get-TimeStamp)" | Tee-Object -FilePath $logFilePath -Append
        $elapsedTime = $(Get-Date) - $StartTime
        Write-Output "Elapsed time (seconds): $($elapsedTime.TotalSeconds)" | Tee-Object -FilePath $logFilePath -Append
        if (($emailFrom -ne "") -and ($emailTo -ne "")) {
            Send-MailMessage -SmtpServer "$emailServer" -Port $emailPort -From "$emailFrom" -To "$emailTo" `
                -Subject "$scriptName - $ComputerName - $MyExitStatus - Log File" -Body "$logFilePath" -UseSsl `
                -Credential (New-Object PSCredential "$emailUsername", (ConvertTo-SecureString "$emailPassword" -AsPlainText -Force)) `
                -Attachments $logFilePath
        }
        if (($shareLocation -ne "") -and ($shareUsername -ne "") -and ($sharePassword -ne "")) {
            $shareCred = New-Object PSCredential ($shareUsername, (ConvertTo-SecureString $sharePassword -AsPlainText -Force))
            New-PSDrive -Name LogStore -PSProvider FileSystem -Root "$shareLocation" -Credential $shareCred
            Copy-Item -LiteralPath "$logFilePath" -Destination "LogStore:\" -Force -ErrorAction Continue
            Remove-PSDrive -Name LogStore
        } elseif ($shareLocation -ne "") {
            Copy-Item -LiteralPath $LogFilePath -Destination $ShareLocation  -Force -ErrorAction Continue
        }
    }
    Set-PSDebug -Trace 0
    exit $MyExitStatus
    #endregion finalization
}

# --------------------------------------------------------------------------
# One-liner version:
# --------------------------------------------------------------------------
# New-Item C:\temp\SysmonDeploy -ItemType Directory -Force >$null; Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile C:\temp\SysmonDeploy\Sysmon.zip; Expand-Archive 'C:\temp\SysmonDeploy\Sysmon.zip' -DestinationPath C:\temp\SysmonDeploy -Force; Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml' -OutFile 'C:\temp\SysmonDeploy\sysmonconfig.xml'; $new=(Get-Item C:\temp\SysmonDeploy\Sysmon64.exe).VersionInfo.FileVersion; $installed = (Get-Item C:\Windows\Sysmon64.exe,C:\Windows\Sysmon.exe -ErrorAction SilentlyContinue | Sort-Object {[version]$_.VersionInfo.FileVersion} -Descending | Select-Object -First 1).VersionInfo.FileVersion; Write-Output $new; $svc=Get-Service Sysmon* -EA 0; if (-not $svc) { Write-Output 'Sysmon not found - installing with retry'; $attempt=0; while ($attempt -lt 3 -and -not (Get-Service Sysmon64 -EA 0)) { $attempt++; Write-Output ('Attempt ' + $attempt); Start-Process wevtutil -ArgumentList 'um','C:\Windows\Sysmon64.exe' -Wait -NoNewWindow -EA 0; Start-Process C:\temp\SysmonDeploy\Sysmon64.exe -ArgumentList '-accepteula','-i','C:\temp\SysmonDeploy\sysmonconfig.xml' -Wait -NoNewWindow; Start-Sleep -Seconds 3 } } elseif ($installed -and [version]$new -gt [version]$installed) { Write-Output 'Upgrading Sysmon'; Start-Process C:\temp\SysmonDeploy\Sysmon.exe -ArgumentList '-accepteula','-u' -Wait -NoNewWindow; Start-Process C:\temp\SysmonDeploy\Sysmon64.exe -ArgumentList '-accepteula','-u' -Wait -NoNewWindow; Start-Process wevtutil -ArgumentList 'um','C:\Windows\Sysmon64.exe' -Wait -NoNewWindow -EA 0; Start-Process C:\temp\SysmonDeploy\Sysmon64.exe -ArgumentList '-accepteula','-i','C:\temp\SysmonDeploy\sysmonconfig.xml' -Wait -NoNewWindow } else { Write-Output 'Sysmon already installed - updating config only'; Start-Process C:\temp\SysmonDeploy\Sysmon64.exe -ArgumentList '-c','C:\temp\SysmonDeploy\sysmonconfig.xml' -Wait -NoNewWindow } ; Get-Service Sysmon64; Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 1 ; get-service sysmon*
