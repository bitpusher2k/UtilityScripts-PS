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
# Check-AdAdminGroups.ps1 - By Bitpusher/The Digital Fox
# v1.0 last updated 2026-04-01
# Run on an Active Directory Domain Controller to report on membership of all
# privileged AD groups. Recursively resolves nested group membership.
# Cross-references each member with last logon data to flag stale privileged accounts.
# Also flags accounts that are disabled but still in privileged groups.
# Outputs a CSV report sorted by group and account name.
#
# Privileged groups checked:
#   Domain Admins, Schema Admins, Enterprise Admins, Account Operators,
#   Backup Operators, Print Operators, Server Operators, DnsAdmins,
#   Group Policy Creator Owners, Protected Users, Administrators,
#   Remote Desktop Users, Remote Management Users
#
# Usage:
# powershell -executionpolicy bypass -f .\Check-AdAdminGroups.ps1
# powershell -executionpolicy bypass -f .\Check-AdAdminGroups.ps1 -OutputPath "C:\temp" -StaleThresholdDays 60
#
# Email report to yourself by including the emailServer, emailFrom, emailTo,
# emailUsername, and emailPassword parameters.
#
#comp #ad #security #incident #active #directory #admin #privileged #groups #audit #script #powershell

#Requires -Version 4

[CmdletBinding()]
param(
    [string]$OutputPath = "C:\temp",               # Folder for CSV output
    [int]$StaleThresholdDays = 90,                 # Flag members not logged on in this many days
    [string[]]$AdditionalGroups = @(),             # Extra group names to check beyond the defaults
    [string]$scriptName = "Check-AdAdminGroups",
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

    Import-Module ActiveDirectory -ErrorAction Stop
    New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
    $ReportPath = "$OutputPath\$($env:computername)_AD_AdminGroupMembership_$($(Get-Date).ToString('yyyyMMddHHmm')).csv"

    # Default privileged groups to check
    $PrivilegedGroups = @(
        "Domain Admins",
        "Schema Admins",
        "Enterprise Admins",
        "Account Operators",
        "Backup Operators",
        "Print Operators",
        "Server Operators",
        "DnsAdmins",
        "Group Policy Creator Owners",
        "Protected Users",
        "Administrators",
        "Remote Desktop Users",
        "Remote Management Users"
    ) + $AdditionalGroups

    $Results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $Now = Get-Date
    $StaleCutoff = $Now.AddDays(-$StaleThresholdDays)

    # Cache all AD users with relevant properties to avoid repeated queries
    Write-Output "$(Get-TimeStamp) Loading AD user data..."
    $AllUsers = @{}
    Get-ADUser -Filter * -Properties SamAccountName, Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, mail, Description, WhenCreated, MemberOf -ErrorAction SilentlyContinue |
        ForEach-Object { $AllUsers[$_.DistinguishedName] = $_ }
    Write-Output "$(Get-TimeStamp) Loaded $($AllUsers.Count) AD user objects."

    foreach ($GroupName in $PrivilegedGroups) {
        Write-Output "$(Get-TimeStamp) Checking group: $GroupName"
        try {
            $Group = Get-ADGroup -Identity $GroupName -Properties Description, WhenCreated -ErrorAction Stop
        } catch {
            Write-Warning "$(Get-TimeStamp) Group '$GroupName' not found or error: $($_.Exception.Message)"
            continue
        }

        $Members = @()
        try {
            # -Recursive resolves nested group memberships
            $Members = Get-ADGroupMember -Identity $GroupName -Recursive -ErrorAction Stop
        } catch {
            Write-Warning "$(Get-TimeStamp) Error getting members of '$GroupName': $($_.Exception.Message)"
        }

        if ($Members.Count -eq 0) {
            $Results.Add([PSCustomObject]@{
                GroupName       = $GroupName
                GroupDesc       = $Group.Description
                MemberSAM       = "(empty group)"
                MemberName      = ""
                MemberType      = ""
                MemberEmail     = ""
                MemberEnabled   = ""
                LastLogonDate   = ""
                LastLogonDateISO = ""
                DaysSinceLogon  = ""
                PasswordLastSet = ""
                PasswordNeverExpires = ""
                IsStale         = $false
                IsDisabled      = $false
                WhenCreated     = ""
                DistinguishedName = ""
                Notes           = ""
            })
            continue
        }

        foreach ($member in $Members) {
            $userObj = $AllUsers[$member.DistinguishedName]

            $lastLogon   = if ($userObj) { $userObj.LastLogonDate } else { $null }
            $lastLogonISO = if ($lastLogon) { $lastLogon.ToString("o") } else { "" }
            $daysSince   = if ($lastLogon) { [math]::Round(($Now - $lastLogon).TotalDays, 0) } else { $null }
            $isStale     = $lastLogon -ne $null -and $lastLogon -lt $StaleCutoff
            $isDisabled  = if ($userObj) { -not $userObj.Enabled } else { $false }
            $pwdLastSet  = if ($userObj -and $userObj.PasswordLastSet) { $userObj.PasswordLastSet.ToString("o") } else { "" }
            $pwdNeverExp = if ($userObj) { $userObj.PasswordNeverExpires } else { "" }

            $notes = @()
            if ($isDisabled) { $notes += "AccountDisabled" }
            if ($isStale) { $notes += "StaleAccount(>$StaleThresholdDays days)" }
            if ($pwdNeverExp -eq $true) { $notes += "PasswordNeverExpires" }
            if ($member.objectClass -eq "group") { $notes += "NestedGroupMember" }

            $Results.Add([PSCustomObject]@{
                GroupName        = $GroupName
                GroupDesc        = $Group.Description
                MemberSAM        = $member.SamAccountName
                MemberName       = $member.Name
                MemberType       = $member.objectClass
                MemberEmail      = if ($userObj) { $userObj.mail } else { "" }
                MemberEnabled    = if ($userObj) { $userObj.Enabled } else { "" }
                LastLogonDate    = $lastLogon
                LastLogonDateISO = $lastLogonISO
                DaysSinceLogon   = $daysSince
                PasswordLastSet  = $pwdLastSet
                PasswordNeverExpires = $pwdNeverExp
                IsStale          = $isStale
                IsDisabled       = $isDisabled
                WhenCreated      = if ($userObj -and $userObj.WhenCreated) { $userObj.WhenCreated.ToString("o") } else { "" }
                DistinguishedName = $member.DistinguishedName
                Notes            = $notes -join "; "
            })
        }
    }

    # Export
    $Results | Sort-Object GroupName, MemberSAM | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding $Encoding
    Write-Output "`n$(Get-TimeStamp) Report saved to: $ReportPath"

    # Console summary
    Write-Output "`n=== PRIVILEGED AD GROUP REPORT ==="
    Write-Output ("  {0,-35} {1,-8} {2,-8} {3,-8}" -f "Group Name", "Members", "Disabled", "Stale")
    Write-Output ("  {0,-35} {1,-8} {2,-8} {3,-8}" -f "-" * 35, "-------", "-------", "------")
    $Results | Where-Object { $_.MemberSAM -ne "(empty group)" } | Group-Object GroupName | Sort-Object Name | ForEach-Object {
        $disabled = ($_.Group | Where-Object { $_.IsDisabled -eq $true }).Count
        $stale    = ($_.Group | Where-Object { $_.IsStale -eq $true }).Count
        Write-Output ("  {0,-35} {1,-8} {2,-8} {3,-8}" -f $_.Name, $_.Count, $disabled, $stale)
    }

    $FlaggedCount = ($Results | Where-Object { $_.Notes -ne "" }).Count
    if ($FlaggedCount -gt 0) {
        Write-Output "`nFlagged members requiring review ($FlaggedCount total):"
        $Results | Where-Object { $_.Notes -ne "" } | Sort-Object GroupName, MemberSAM | ForEach-Object {
            Write-Output "  [$($_.GroupName)] $($_.MemberSAM) ($($_.MemberName)) - $($_.Notes)"
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
