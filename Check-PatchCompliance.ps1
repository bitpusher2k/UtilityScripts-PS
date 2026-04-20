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
# Check-PatchCompliance.ps1 - By Bitpusher/The Digital Fox
# v1.2 last updated 2026-04-19
#
# Checks Windows Update status via the WU COM API. Reports:
#  - Last successful scan date
#  - Last successful installation date
#  - Number of missing (not yet installed) updates
#  - List of missing update titles
#  - Pending reboot state (from multiple detection sources)
# Outputs a CSV report suitable for aggregation across many endpoints via RMM.
#
# Run with admin privileges for accurate WU COM access.
#
# Usage:
# powershell -executionpolicy bypass -f .\Check-PatchCompliance.ps1
# powershell -executionpolicy bypass -f .\Check-PatchCompliance.ps1 -OutputPath "C:\temp" -IncludeDrivers 1
#
# Email report to yourself by including the emailServer, emailFrom, emailTo,
# emailUsername, and emailPassword parameters.
#
# To run as a scheduled task:
# C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.exe -Command "& 'C:\Utility\Check-PatchCompliance.ps1'"
#
#comp #patch #windows #update #compliance #reboot #script #powershell

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$OutputPath = "C:\temp",               # Folder for CSV output
    [int]$IncludeDrivers = 0,                      # 1 = also check for driver updates
    [int]$StaleThresholdDays = 30,                 # Flag if last install was more than N days ago
    [string]$scriptName = "Check-PatchCompliance",
    [string]$Priority = "Normal",
    [int]$RandMax = "60",
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
    $ReportPath = "$OutputPath\$ComputerName-PatchCompliance-$($(Get-Date).ToString('yyyyMMddHHmm')).csv"

    # Collect OS info for context
    $OS = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $OSCaption   = $OS.Caption
    $OSBuild     = $OS.BuildNumber
    $OSVersion   = $OS.Version

    # ----------------------------------------------------------------
    # Windows Update COM API - last scan/install dates
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Querying Windows Update auto-update results..."
    $WULastSearch  = "Unknown"
    $WULastInstall = "Unknown"
    try {
        $AutoUpdate = New-Object -ComObject Microsoft.Update.AutoUpdate -ErrorAction Stop
        $Results    = $AutoUpdate.Results
        $WULastSearch  = if ($Results.LastSearchSuccessDate -and $Results.LastSearchSuccessDate -gt [datetime]"1970-01-01") { $Results.LastSearchSuccessDate.ToString("o") } else { "Never/Unknown" }
        $WULastInstall = if ($Results.LastInstallationSuccessDate -and $Results.LastInstallationSuccessDate -gt [datetime]"1970-01-01") { $Results.LastInstallationSuccessDate.ToString("o") } else { "Never/Unknown" }
    } catch {
        Write-Warning "$(Get-TimeStamp) Could not query AutoUpdate COM object: $($_.Exception.Message)"
    }

    # Days since last install
    $DaysSinceLastInstall = "Unknown"
    if ($WULastInstall -ne "Never/Unknown" -and $WULastInstall -ne "Unknown") {
        try {
            $DaysSinceLastInstall = [math]::Round(((Get-Date) - [datetime]$WULastInstall).TotalDays, 1)
        } catch {}
    }
    $InstallStale = $DaysSinceLastInstall -ne "Unknown" -and [double]$DaysSinceLastInstall -gt $StaleThresholdDays

    # ----------------------------------------------------------------
    # Scan for missing updates via WU Searcher
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Searching for missing updates (this may take a moment)..."
    $MissingUpdateCount = "Error"
    $MissingUpdateTitles = "Error"
    $MissingSecurityCount = 0
    $MissingCriticalCount = 0
    $MissingUpdateDetails = @()
    try {
        $Searcher = New-Object -ComObject Microsoft.Update.Searcher -ErrorAction Stop
        $SearchQuery = if ($IncludeDrivers -eq 1) {
            "IsInstalled=0 and IsHidden=0"
        } else {
            "IsInstalled=0 and Type='Software' and IsHidden=0"
        }
        $SearchResult = $Searcher.Search($SearchQuery)
        $MissingUpdateCount = $SearchResult.Updates.Count
        $MissingUpdateDetails = $SearchResult.Updates | ForEach-Object {
            $cats = ($_.Categories | ForEach-Object { $_.Name }) -join ","
            [PSCustomObject]@{
                Title      = $_.Title
                KBArticle  = ($_.KBArticleIDs -join ",")
                Categories = $cats
                Severity   = $_.MsrcSeverity
                SizeMB     = [math]::Round($_.MaxDownloadSize / 1MB, 1)
            }
        }
        $MissingUpdateTitles    = ($MissingUpdateDetails | Select-Object -ExpandProperty Title | Select-Object -First 20) -join " | "
        $MissingSecurityCount   = ($MissingUpdateDetails | Where-Object { $_.Categories -like "*Security*" }).Count
        $MissingCriticalCount   = ($MissingUpdateDetails | Where-Object { $_.Severity -eq "Critical" }).Count
    } catch {
        Write-Warning "$(Get-TimeStamp) Error searching for updates: $($_.Exception.Message)"
        $MissingUpdateTitles = $_.Exception.Message
    }

    # ----------------------------------------------------------------
    # Pending Reboot Detection (multiple sources)
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Checking pending reboot state..."
    $RebootReasons = [System.Collections.Generic.List[string]]::new()
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") { $RebootReasons.Add("WindowsUpdate") }
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") { $RebootReasons.Add("CBS-RebootPending") }
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootInProgress") { $RebootReasons.Add("CBS-InProgress") }
    $pfro = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if ($pfro) { $RebootReasons.Add("PendingFileRename") }
    try {
        $sccm = Invoke-CimMethod -Namespace root\ccm\clientsdk -ClassName CCM_ClientUtilities -MethodName DetermineIfRebootPending -ErrorAction Stop
        if ($sccm.RebootPending -or $sccm.IsHardRebootPending) { $RebootReasons.Add("SCCM") }
    } catch {}
    $PendingReboot = if ($RebootReasons.Count -gt 0) { "YES: " + ($RebootReasons -join ", ") } else { "No" }

    # ----------------------------------------------------------------
    # Get recently installed updates (last 30 days) for context
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Getting recently installed updates..."
    $RecentUpdates = "None"
    try {
        $Searcher2 = New-Object -ComObject Microsoft.Update.Searcher -ErrorAction Stop
        $TotalInstalled = $Searcher2.GetTotalHistoryCount()
        if ($TotalInstalled -gt 0) {
            $History = $Searcher2.QueryHistory(0, [Math]::Min($TotalInstalled, 50))
            $CutoffDate = (Get-Date).AddDays(-30)
            $RecentList = $History | Where-Object { $_.Date -gt $CutoffDate -and $_.ResultCode -eq 2 } |
                Sort-Object Date -Descending |
                Select-Object -First 10 |
                ForEach-Object { "[$($_.Date.ToString('yyyy-MM-dd'))] $($_.Title)" }
            $RecentUpdates = if ($RecentList) { $RecentList -join " | " } else { "None in past 30 days" }
        }
    } catch {
        $RecentUpdates = "Error: $($_.Exception.Message)"
    }

    # ----------------------------------------------------------------
    # Build result and export
    # ----------------------------------------------------------------
    $Report = [PSCustomObject]@{
        ComputerName            = $ComputerName
        ScanTime                = (Get-Date -Format "o")
        OSCaption               = $OSCaption
        OSBuild                 = $OSBuild
        OSVersion               = $OSVersion
        WULastSearchSuccess     = $WULastSearch
        WULastInstallSuccess    = $WULastInstall
        DaysSinceLastInstall    = $DaysSinceLastInstall
        InstallStale            = $InstallStale
        PendingUpdateCount      = $MissingUpdateCount
        PendingSecurityCount    = $MissingSecurityCount
        PendingCriticalCount    = $MissingCriticalCount
        PendingUpdateTitles     = $MissingUpdateTitles
        PendingReboot           = $PendingReboot
        RecentUpdates           = $RecentUpdates
    }

    $Report | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding $Encoding

    # Console summary
    Write-Output "`n=== PATCH COMPLIANCE SUMMARY: $ComputerName ==="
    Write-Output "  OS:                     $OSCaption (Build $OSBuild)"
    Write-Output "  WU Last Scan:           $WULastSearch"
    Write-Output "  WU Last Install:        $WULastInstall"
    Write-Output "  Days Since Last Install:$DaysSinceLastInstall $(if($InstallStale){'[!STALE]'})"
    Write-Output "  Missing Updates:        $MissingUpdateCount (Security: $MissingSecurityCount, Critical: $MissingCriticalCount)"
    Write-Output "  Pending Reboot:         $PendingReboot"
    if ($MissingUpdateDetails) {
        Write-Output "`n  Missing updates:"
        $MissingUpdateDetails | Select-Object -First 15 | ForEach-Object {
            Write-Output "    [KB$($_.KBArticle)] $($_.Title) [$($_.Severity)]"
        }
        if ($MissingUpdateCount -gt 15) { Write-Output "    ... and $($MissingUpdateCount - 15) more" }
    }
    Write-Output "`n  Recently installed (last 30 days): $RecentUpdates"
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
            Copy-Item -LiteralPath "$ReportPath"  -Destination "LogStore:\" -Force -ErrorAction Continue
            Remove-PSDrive -Name LogStore
        } elseif ($shareLocation -ne "") {
            Copy-Item -LiteralPath $LogFilePath -Destination $ShareLocation  -Force -ErrorAction Continue
        }
    }
    Set-PSDebug -Trace 0
    exit $MyExitStatus
    #endregion finalization
}
