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
# Get-SyInfoSnapshot.ps1 - By Bitpusher/The Digital Fox
# v1.4 last updated 2026-04-19
# Endpoint profile collection script. Collects OS version, hardware, network, patch status,
# pending reboot state, antivirus products, firewall status, and key service states.
# Outputs a structured CSV report and prints a human-readable summary to the console/transcript.
# Designed to be run from RMM/PsExec/PS remoting as a "first look" triage script
# or for scheduled inventory runs.
#
# Run with admin privileges for full coverage (patch history, WMI security center).
#
# Usage:
# powershell -executionpolicy bypass -f .\Get-SyInfoSnapshot.ps1
# powershell -executionpolicy bypass -f .\Get-SyInfoSnapshot.ps1 -OutputPath "C:\temp"
#
# Email report to yourself by including the emailServer, emailFrom, emailTo,
# emailUsername, and emailPassword parameters.
#
# To run as a scheduled task:
# C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.exe -Command "& 'C:\Utility\Get-SyInfoSnapshot.ps1'"
#
#comp #inventory #snapshot #hardware #patch #reboot #antivirus #firewall #script #powershell

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$OutputPath = "C:\temp",               # Folder for CSV report output
    [string]$scriptName = "Get-SyInfoSnapshot",
    [string]$Priority = "Normal",
    [int]$RandMax = "30",
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

    New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
    $ReportPath = "$OutputPath\$ComputerName-SyInfoSnapshot-$($(Get-Date).ToString('yyyyMMddHHmm')).csv"

    $Snapshot = [ordered]@{ ComputerName = $ComputerName; SnapshotTime = (Get-Date -Format "o") }

    # ----------------------------------------------------------------
    # OS Information
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Collecting OS information..."
    try {
        $OS = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $Snapshot.OSCaption         = $OS.Caption
        $Snapshot.OSVersion         = $OS.Version
        $Snapshot.OSBuildNumber     = $OS.BuildNumber
        $Snapshot.OSArchitecture    = $OS.OSArchitecture
        $Snapshot.InstallDate       = $OS.InstallDate.ToString("o")
        $Snapshot.LastBootTime      = $OS.LastBootUpTime.ToString("o")
        $Snapshot.UptimeDays        = [math]::Round(((Get-Date) - $OS.LastBootUpTime).TotalDays, 1)
        $Snapshot.RegisteredUser    = $OS.RegisteredUser
        $Snapshot.SystemDrive       = $OS.SystemDrive
        $Snapshot.TotalVisibleMemGB = [math]::Round($OS.TotalVisibleMemorySize / 1MB, 2)
        $Snapshot.FreeMemGB         = [math]::Round($OS.FreePhysicalMemory / 1MB, 2)
        $Snapshot.MemUsedPct        = [math]::Round((($OS.TotalVisibleMemorySize - $OS.FreePhysicalMemory) / $OS.TotalVisibleMemorySize) * 100, 1)
    } catch {
        Write-Warning "$(Get-TimeStamp) Error collecting OS info: $($_.Exception.Message)"
    }

    # ----------------------------------------------------------------
    # Computer System / Hardware
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Collecting hardware information..."
    try {
        $CS = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $Snapshot.Manufacturer     = $CS.Manufacturer
        $Snapshot.Model            = $CS.Model
        $Snapshot.Domain           = $CS.Domain
        $Snapshot.PartOfDomain     = $CS.PartOfDomain
        $Snapshot.NumberOfCPUs     = $CS.NumberOfProcessors
        $Snapshot.NumberOfCores    = $CS.NumberOfLogicalProcessors
        $Snapshot.TotalPhysicalGB  = [math]::Round($CS.TotalPhysicalMemory / 1GB, 2)
    } catch {
        Write-Warning "$(Get-TimeStamp) Error collecting hardware info: $($_.Exception.Message)"
    }
    try {
        $CPU = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1
        $Snapshot.CPUName          = $CPU.Name
        $Snapshot.CPUMaxClockMHz   = $CPU.MaxClockSpeed
    } catch {}

    # ----------------------------------------------------------------
    # BIOS / Serial
    # ----------------------------------------------------------------
    try {
        $BIOS = Get-CimInstance Win32_BIOS -ErrorAction Stop
        $Snapshot.BIOSVersion      = $BIOS.SMBIOSBIOSVersion
        $Snapshot.SerialNumber     = $BIOS.SerialNumber
    } catch {}

    # ----------------------------------------------------------------
    # Disk Drives
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Collecting disk information..."
    try {
        $Disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop
        $diskSummary = $Disks | ForEach-Object {
            "$($_.DeviceID) $([math]::Round($_.Size/1GB,1))GB total $([math]::Round($_.FreeSpace/1GB,1))GB free ($([math]::Round($_.FreeSpace/$_.Size*100,1))%)"
        }
        $Snapshot.Disks = $diskSummary -join " | "
        # Flag any drive below 10% free
        $lowDisks = $Disks | Where-Object { $_.Size -gt 0 -and ($_.FreeSpace / $_.Size) -lt 0.10 }
        $Snapshot.LowDiskAlert = if ($lowDisks) { ($lowDisks.DeviceID -join ", ") + " below 10% free" } else { "None" }
    } catch {
        Write-Warning "$(Get-TimeStamp) Error collecting disk info: $($_.Exception.Message)"
    }

    # ----------------------------------------------------------------
    # Network Adapters
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Collecting network information..."
    try {
        $NetAdapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction Stop
        $netSummary = $NetAdapters | ForEach-Object {
            $ips = $_.IPAddress -join ","
            "[$($_.Description)] MAC:$($_.MACAddress) IP:$ips GW:$($_.DefaultIPGateway -join ',') DNS:$($_.DNSServerSearchOrder -join ',')"
        }
        $Snapshot.NetworkAdapters = $netSummary -join " || "
    } catch {
        Write-Warning "$(Get-TimeStamp) Error collecting network info: $($_.Exception.Message)"
    }

    # ----------------------------------------------------------------
    # Windows Update / Patch Status
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Collecting patch status..."
    try {
        $WUService = New-Object -ComObject Microsoft.Update.AutoUpdate -ErrorAction Stop
        $WUResults = $WUService.Results
        $Snapshot.WULastSearchSuccess  = if ($WUResults.LastSearchSuccessDate) { $WUResults.LastSearchSuccessDate.ToString("o") } else { "Never" }
        $Snapshot.WULastInstallSuccess = if ($WUResults.LastInstallationSuccessDate) { $WUResults.LastInstallationSuccessDate.ToString("o") } else { "Never" }
    } catch {
        $Snapshot.WULastSearchSuccess  = "Error: $($_.Exception.Message)"
        $Snapshot.WULastInstallSuccess = "Unknown"
    }

    # Count available (not yet installed) updates
    try {
        $searcher = New-Object -ComObject Microsoft.Update.Searcher -ErrorAction Stop
        $searchResult = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
        $Snapshot.PendingUpdateCount = $searchResult.Updates.Count
        $Snapshot.PendingUpdates = ($searchResult.Updates | ForEach-Object { $_.Title } | Select-Object -First 10) -join " | "
    } catch {
        $Snapshot.PendingUpdateCount = "Error"
        $Snapshot.PendingUpdates = $_.Exception.Message
    }

    # ----------------------------------------------------------------
    # Pending Reboot Detection
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Checking pending reboot state..."
    $RebootReasons = [System.Collections.Generic.List[string]]::new()
    # Windows Update reboot flag
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") { $RebootReasons.Add("WindowsUpdate") }
    # Component Based Servicing
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") { $RebootReasons.Add("CBS-RebootPending") }
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootInProgress") { $RebootReasons.Add("CBS-RebootInProgress") }
    # PendingFileRenameOperations
    $pfro = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if ($pfro) { $RebootReasons.Add("PendingFileRenameOperations") }
    # SCCM / ConfigMgr client
    try {
        $sccm = Invoke-CimMethod -Namespace root\ccm\clientsdk -ClassName CCM_ClientUtilities -MethodName DetermineIfRebootPending -ErrorAction Stop
        if ($sccm.RebootPending -or $sccm.IsHardRebootPending) { $RebootReasons.Add("SCCM") }
    } catch {}
    $Snapshot.PendingReboot = if ($RebootReasons.Count -gt 0) { "YES: " + ($RebootReasons -join ", ") } else { "No" }

    # ----------------------------------------------------------------
    # Antivirus Products (WMI SecurityCenter2 - works on workstation OS)
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Checking antivirus products..."
    try {
        $AVProducts = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop
        $avSummary = $AVProducts | ForEach-Object {
            $state = switch ($_.productState.ToString().Substring(0,2)) {
                "19" { "Enabled/UpToDate" }
                "11" { "Enabled/OutOfDate" }
                "39" { "Enabled/UpToDate" }
                default { "State:$($_.productState)" }
            }
            "$($_.displayName) [$state]"
        }
        $Snapshot.AntivirusProducts = $avSummary -join " | "
    } catch {
        $Snapshot.AntivirusProducts = "SecurityCenter2 unavailable (may be server OS): $($_.Exception.Message)"
    }

    # Windows Defender status separately
    try {
        $DefenderStatus = Get-MpComputerStatus -ErrorAction Stop
        $Snapshot.DefenderEnabled           = $DefenderStatus.AntivirusEnabled
        $Snapshot.DefenderRTPEnabled        = $DefenderStatus.RealTimeProtectionEnabled
        $Snapshot.DefenderSignatureAge      = $DefenderStatus.AntivirusSignatureAge
        $Snapshot.DefenderLastQuickScan     = if ($DefenderStatus.QuickScanEndTime) { $DefenderStatus.QuickScanEndTime.ToString("o") } else { "Never" }
        $Snapshot.DefenderLastFullScan      = if ($DefenderStatus.FullScanEndTime) { $DefenderStatus.FullScanEndTime.ToString("o") } else { "Never" }
    } catch {
        $Snapshot.DefenderEnabled = "Module unavailable"
    }

    # ----------------------------------------------------------------
    # Windows Firewall Status
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Checking firewall status..."
    try {
        $FWProfiles = Get-NetFirewallProfile -ErrorAction Stop
        $fwSummary = $FWProfiles | ForEach-Object { "$($_.Name):$($_.Enabled)" }
        $Snapshot.FirewallProfiles = $fwSummary -join " | "
    } catch {
        $Snapshot.FirewallProfiles = "Error: $($_.Exception.Message)"
    }

    # ----------------------------------------------------------------
    # Key Services Status
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Checking key service states..."
    $KeyServices = @("wuauserv", "WinDefend", "MpsSvc", "EventLog", "Spooler", "W32Time", "Dnscache", "BITS", "CryptSvc")
    $svcStatus = foreach ($svcName in $KeyServices) {
        $s = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($s) { "$svcName`:$($s.Status)" } else { "$svcName`:NotFound" }
    }
    $Snapshot.KeyServices = $svcStatus -join " | "

    # ----------------------------------------------------------------
    # PowerShell Version & Execution Policy
    # ----------------------------------------------------------------
    $Snapshot.PSVersion        = $PSVersionTable.PSVersion.ToString()
    $Snapshot.ExecutionPolicy  = (Get-ExecutionPolicy -Scope LocalMachine -ErrorAction SilentlyContinue).ToString()

    # ----------------------------------------------------------------
    # Local Admin Account Status
    # ----------------------------------------------------------------
    try {
        $adminAcct = Get-LocalUser -Name "Administrator" -ErrorAction Stop
        $Snapshot.BuiltinAdminEnabled = $adminAcct.Enabled
    } catch {
        $Snapshot.BuiltinAdminEnabled = "Unknown"
    }

    # ----------------------------------------------------------------
    # Export and Summary
    # ----------------------------------------------------------------
    [PSCustomObject]$Snapshot | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding $Encoding
    Write-Output "`n=== SYSTEM INFORMATION: $ComputerName ==="
    Write-Output "  OS:              $($Snapshot.OSCaption) (Build $($Snapshot.OSBuildNumber))"
    Write-Output "  Model:           $($Snapshot.Manufacturer) $($Snapshot.Model)"
    Write-Output "  CPU:             $($Snapshot.CPUName)"
    Write-Output "  RAM:             $($Snapshot.TotalPhysicalGB) GB (Used: $($Snapshot.MemUsedPct)%)"
    Write-Output "  Disks:           $($Snapshot.Disks)"
    Write-Output "  Uptime:          $($Snapshot.UptimeDays) days (last boot: $($Snapshot.LastBootTime))"
    Write-Output "  Pending Reboot:  $($Snapshot.PendingReboot)"
    Write-Output "  Pending Updates: $($Snapshot.PendingUpdateCount)"
    Write-Output "  WU Last Install: $($Snapshot.WULastInstallSuccess)"
    Write-Output "  Antivirus:       $($Snapshot.AntivirusProducts)"
    Write-Output "  Defender RTP:    $($Snapshot.DefenderRTPEnabled)"
    Write-Output "  Firewall:        $($Snapshot.FirewallProfiles)"
    Write-Output "  Key Services:    $($Snapshot.KeyServices)"
    Write-Output "`nReport saved to: $ReportPath"

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
