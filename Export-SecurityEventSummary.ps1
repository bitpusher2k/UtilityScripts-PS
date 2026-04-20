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
# Export-SecurityEventSummary.ps1 - By Bitpusher/The Digital Fox
# v1.4 last updated 2026-04-19
# Queries the Windows Security event log for key incident-response event IDs,
# produces a grouped summary by EventID, and exports full event detail records to CSV.
# Designed for rapid IR triage - run on a suspicious endpoint to quickly surface
# failed logons, new accounts, scheduled task creation, new services, and more.
#
# Covers event IDs:
#  4624 - Successful logon            4625 - Failed logon
#  4648 - Explicit credential logon   4688 - Process creation (if audited)
#  4698 - Scheduled task created      4699 - Scheduled task deleted
#  4702 - Scheduled task modified     4720 - User account created
#  4722 - User account enabled        4724 - Password reset attempt
#  4725 - User account disabled       4726 - User account deleted
#  4732 - Member added to local group 4756 - Member added to universal group
#  4771 - Kerberos pre-auth failed    7034 - Service crashed
#  7045 - New service installed
#
# Run with admin privileges for access to Security event log.
#
# Usage:
# powershell -executionpolicy bypass -f .\Export-SecurityEventSummary.ps1
# powershell -executionpolicy bypass -f .\Export-SecurityEventSummary.ps1 -HoursBack 48 -OutputPath "C:\temp"
#
# Email report to yourself by including the emailServer, emailFrom, emailTo,
# emailUsername, and emailPassword parameters.
#
#comp #ad #security #incident #eventlog #logon #audit #script #powershell

#Requires -Version 5.1

[CmdletBinding()]
param(
    [int]$HoursBack = 24,                          # How many hours back to search the event log
    [string]$OutputPath = "C:\temp",               # Folder for CSV output
    [string]$scriptName = "Export-SecurityEventSummary",
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

    New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
    $ReportPath   = "$OutputPath\$ComputerName-SecurityEvents-$($(Get-Date).ToString('yyyyMMddHHmm')).csv"
    $SummaryPath  = "$OutputPath\$ComputerName-SecurityEventSummary-$($(Get-Date).ToString('yyyyMMddHHmm')).csv"

    # Event ID descriptors
    $EventDescriptions = @{
        4624 = "Successful logon"
        4625 = "Failed logon"
        4648 = "Logon with explicit credentials"
        4688 = "Process creation"
        4698 = "Scheduled task created"
        4699 = "Scheduled task deleted"
        4702 = "Scheduled task modified"
        4720 = "User account created"
        4722 = "User account enabled"
        4724 = "Password reset attempt"
        4725 = "User account disabled"
        4726 = "User account deleted"
        4732 = "Member added to local security group"
        4756 = "Member added to universal group"
        4771 = "Kerberos pre-authentication failed"
        7034 = "Service crashed unexpectedly"
        7045 = "New service installed"
    }

    $TargetEventIDs = $EventDescriptions.Keys
    $StartDate = (Get-Date).AddHours(-$HoursBack)

    Write-Output "$(Get-TimeStamp) Querying Security + System event log for $(($TargetEventIDs | Measure-Object).Count) event IDs going back $HoursBack hours..."
    Write-Output "$(Get-TimeStamp) Search start time: $($StartDate.ToString('o'))"

    $AllEvents = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Query Security log for most events
    $SecurityEventIDs = $TargetEventIDs | Where-Object { $_ -lt 7000 }
    $SystemEventIDs   = $TargetEventIDs | Where-Object { $_ -ge 7000 }

    function Get-EventDetails {
        param($Event, $Description)
        # Extract the most useful fields from the event message
        $msg = $Event.Message
        $subject = if ($msg -match "Subject:\s*\n\s*Account Name:\s*(.+)") { $Matches[1].Trim() } else { "" }
        $targetAccount = if ($msg -match "(?:New Logon|Target Account|New Account):\s*\n\s*Account Name:\s*(.+)") { $Matches[1].Trim() } else { "" }
        $logonType = if ($msg -match "Logon Type:\s*(\d+)") { $Matches[1] } else { "" }
        $ipAddress = if ($msg -match "Source Network Address:\s*(.+)") { $Matches[1].Trim() } else { "" }
        $processName = if ($msg -match "(?:New Process Name|Process Name):\s*(.+)") { $Matches[1].Trim() } else { "" }
        $taskName = if ($msg -match "Task Name:\s*(.+)") { $Matches[1].Trim() } else { "" }
        $serviceName = if ($msg -match "Service Name:\s*(.+)") { $Matches[1].Trim() } else { "" }
        $serviceFile = if ($msg -match "Service File Name:\s*(.+)") { $Matches[1].Trim() } else { "" }
        $groupName = if ($msg -match "Group:\s*\n\s*Group Name:\s*(.+)") { $Matches[1].Trim() } else { "" }

        [PSCustomObject]@{
            ComputerName   = $Event.MachineName
            TimeCreated    = $Event.TimeCreated.ToString("o")
            EventID        = $Event.Id
            Description    = $Description
            SubjectAccount = $subject
            TargetAccount  = $targetAccount
            LogonType      = $logonType
            SourceIP       = $ipAddress
            ProcessName    = $processName
            TaskName       = $taskName
            ServiceName    = $serviceName
            ServiceFile    = $serviceFile
            GroupName      = $groupName
            ProviderName   = $Event.ProviderName
            RecordId       = $Event.RecordId
            Message        = ($msg -replace "\r?\n", " ") -replace "\s{2,}", " "
        }
    }

    # Query Security log
    try {
        Write-Output "$(Get-TimeStamp) Querying Security event log..."
        foreach ($evtId in $SecurityEventIDs) {
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = 'Security'
                Id        = $evtId
                StartTime = $StartDate
            } -ErrorAction SilentlyContinue
            foreach ($evt in $events) {
                $AllEvents.Add((Get-EventDetails -Event $evt -Description $EventDescriptions[$evtId]))
            }
        }
    } catch {
        Write-Warning "$(Get-TimeStamp) Error querying Security log (requires admin): $($_.Exception.Message)"
    }

    # Query System log for service events
    try {
        Write-Output "$(Get-TimeStamp) Querying System event log..."
        foreach ($evtId in $SystemEventIDs) {
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = 'System'
                Id        = $evtId
                StartTime = $StartDate
            } -ErrorAction SilentlyContinue
            foreach ($evt in $events) {
                $AllEvents.Add((Get-EventDetails -Event $evt -Description $EventDescriptions[$evtId]))
            }
        }
    } catch {
        Write-Warning "$(Get-TimeStamp) Error querying System log: $($_.Exception.Message)"
    }

    Write-Output "$(Get-TimeStamp) Total events collected: $($AllEvents.Count)"

    # Export full event details
    if ($AllEvents.Count -gt 0) {
        $AllEvents | Sort-Object TimeCreated -Descending | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding $Encoding
        Write-Output "$(Get-TimeStamp) Full event detail exported to: $ReportPath"
    } else {
        Write-Output "$(Get-TimeStamp) No matching events found in the specified time range."
    }

    # Build and export summary grouped by EventID
    $Summary = $AllEvents | Group-Object EventID | Sort-Object Name | ForEach-Object {
        $id = [int]$_.Name
        [PSCustomObject]@{
            EventID     = $id
            Description = $EventDescriptions[$id]
            Count       = $_.Count
            FirstSeen   = ($_.Group | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
            LastSeen    = ($_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
            UniqueSourceIPs = ($_.Group.SourceIP | Where-Object { $_ -and $_ -ne "-" } | Sort-Object -Unique | Select-Object -First 10) -join ", "
            UniqueAccounts  = ($_.Group.TargetAccount | Where-Object { $_ } | Sort-Object -Unique | Select-Object -First 10) -join ", "
        }
    }

    if ($Summary) {
        $Summary | Export-Csv -Path $SummaryPath -NoTypeInformation -Encoding $Encoding
    }

    # Console summary output
    Write-Output "`n=== SECURITY EVENT SUMMARY: $ComputerName (past $HoursBack hours) ==="
    Write-Output ("  {0,-6} {1,-40} {2,-8}" -f "EvtID", "Description", "Count")
    Write-Output ("  {0,-6} {1,-40} {2,-8}" -f "------", "---------------------------------------- ", "--------")
    foreach ($row in $Summary) {
        Write-Output ("  {0,-6} {1,-40} {2,-8}" -f $row.EventID, $row.Description, $row.Count)
    }

    # Highlight high-risk events
    $HighRiskIds = @(4720, 4726, 4732, 7045, 4698, 4771)
    $HighRiskEvents = $AllEvents | Where-Object { $_.EventID -in $HighRiskIds }
    if ($HighRiskEvents) {
        Write-Output "`n=== HIGH-RISK EVENTS (review immediately) ==="
        $HighRiskEvents | Sort-Object TimeCreated -Descending | Select-Object -First 20 | ForEach-Object {
            Write-Output "  [$($_.TimeCreated)] ID:$($_.EventID) $($_.Description) - Target:$($_.TargetAccount) Service:$($_.ServiceName)$($_.TaskName) IP:$($_.SourceIP)"
        }
    }

    Write-Output "`nSummary CSV: $SummaryPath"
    Write-Output "Detail CSV:  $ReportPath"

    $MyExitStatus = 0
    #endregion main

    #region finalization
    if ($logFileFolderPath -ne "") {
        Write-Output "`nScript $scriptName ended at $(Get-TimeStamp)"
        $elapsedTime = $(Get-Date) - $StartTime
        Write-Output "Elapsed time (seconds): $($elapsedTime.TotalSeconds)"
        Stop-Transcript
        if (($emailServer -ne "") -and ($emailUsername -ne "") -and ($emailPassword -ne "") -and ($emailFrom -ne "") -and ($emailTo -ne "")) {
            Send-MailMessage -SmtpServer "$emailServer" -Port $emailPort -From "$emailFrom" -To "$emailTo" -Subject "$scriptName - $ComputerName - $MyExitStatus - Log File" -Body "$logFilePath" -UseSsl -Credential (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$emailUsername", (ConvertTo-SecureString -String "$emailPassword" -AsPlainText -Force)) -Attachments $logFilePath, $ReportPath, $SummaryPath
        }
        if (($shareLocation -ne "") -and ($shareUsername -ne "") -and ($sharePassword -ne "")) {
            [securestring]$secStringPassword = ConvertTo-SecureString $sharePassword -AsPlainText -Force
            [pscredential]$shareCred = New-Object System.Management.Automation.PSCredential ($shareUsername, $secStringPassword)
            New-PSDrive -Name LogStore -PSProvider FileSystem -Root "$shareLocation" -Description "Log Store" -Credential $shareCred
            Copy-Item -LiteralPath "$logFilePath" -Destination "LogStore:\" -Force -ErrorAction Continue
            Copy-Item -LiteralPath "$ReportPath"  -Destination "LogStore:\" -Force -ErrorAction Continue
            Copy-Item -LiteralPath "$SummaryPath" -Destination "LogStore:\" -Force -ErrorAction Continue
            Remove-PSDrive -Name LogStore
        } elseif ($shareLocation -ne "") {
            Copy-Item -LiteralPath $LogFilePath -Destination $ShareLocation  -Force -ErrorAction Continue
        }
    }
    Set-PSDebug -Trace 0
    exit $MyExitStatus
    #endregion finalization
}
