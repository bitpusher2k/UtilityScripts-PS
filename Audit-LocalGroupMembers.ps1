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
# Audit-LocalGroupMembers.ps1 - By Bitpusher/The Digital Fox
# v1.1 last updated 2026-04-19
# Enumerates all local groups and their members on the endpoint.
# Flags unexpected domain accounts or unknown principals in the Administrators group.
# Particularly useful for answering "who has local admin?" during security audits and IR.
# Also reports membership of Remote Desktop Users, Remote Management Users, and all other groups.
# Outputs CSV report with one row per group/member combination.
#
# Run with admin privileges for complete results.
#
# Usage:
# powershell -executionpolicy bypass -f .\Audit-LocalGroupMembers.ps1
# powershell -executionpolicy bypass -f .\Audit-LocalGroupMembers.ps1 -OutputPath "C:\temp"
#
# Email report to yourself by including the emailServer, emailFrom, emailTo,
# emailUsername, and emailPassword parameters.
#
# To run as a scheduled task:
# C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.exe -Command "& 'C:\Utility\Audit-LocalGroupMembers.ps1'"
#
#comp #security #incident #local #group #admin #members #audit #script #powershell

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$OutputPath = "C:\temp",               # Folder for CSV report output
    [string[]]$HighPrivGroups = @("Administrators", "Remote Desktop Users", "Remote Management Users", "Backup Operators", "Network Configuration Operators"),
    [string]$scriptName = "Audit-LocalGroupMembers",
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
    $ReportPath = "$OutputPath\$ComputerName-LocalGroupMembers-$($(Get-Date).ToString('yyyyMMddHHmm')).csv"

    $Results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Get all local groups
    Write-Output "$(Get-TimeStamp) Enumerating local groups..."
    $LocalGroups = Get-LocalGroup -ErrorAction SilentlyContinue
    Write-Output "$(Get-TimeStamp) Found $($LocalGroups.Count) local groups."

    foreach ($Group in $LocalGroups) {
        Write-Output "$(Get-TimeStamp) Processing group: $($Group.Name)"
        $IsHighPriv = $Group.Name -in $HighPrivGroups
        $members = @()
        try {
            $members = Get-LocalGroupMember -Group $Group.Name -ErrorAction Stop
        } catch {
            Write-Warning "$(Get-TimeStamp) Could not enumerate members of '$($Group.Name)': $($_.Exception.Message)"
            # Add an entry to note the error
            $Results.Add([PSCustomObject]@{
                ComputerName  = $ComputerName
                GroupName     = $Group.Name
                GroupDesc     = $Group.Description
                IsHighPriv    = $IsHighPriv
                MemberName    = "(ERROR: $($_.Exception.Message))"
                MemberSID     = ""
                ObjectClass   = ""
                PrincipalSource = ""
                IsDomainAccount = $false
                IsDisabled    = ""
                LastLogon     = ""
                Notes         = "Error enumerating members"
            })
            continue
        }

        if ($members.Count -eq 0) {
            $Results.Add([PSCustomObject]@{
                ComputerName  = $ComputerName
                GroupName     = $Group.Name
                GroupDesc     = $Group.Description
                IsHighPriv    = $IsHighPriv
                MemberName    = "(empty group)"
                MemberSID     = ""
                ObjectClass   = ""
                PrincipalSource = ""
                IsDomainAccount = $false
                IsDisabled    = ""
                LastLogon     = ""
                Notes         = ""
            })
            continue
        }

        foreach ($member in $members) {
            $isDomain = $member.PrincipalSource -eq "ActiveDirectory" -or ($member.Name -like "*\*" -and $member.Name -notlike "$ComputerName\*")
            $isDisabled = ""
            $lastLogon = ""

            # For local accounts, check if they're disabled and get last logon
            if ($member.PrincipalSource -eq "Local" -or $member.ObjectClass -eq "User") {
                try {
                    $localUser = Get-LocalUser -SID $member.SID -ErrorAction Stop
                    $isDisabled = -not $localUser.Enabled
                    $lastLogon = if ($localUser.LastLogon) { $localUser.LastLogon.ToString("o") } else { "Never" }
                } catch {}
            }

            # Flag: domain account in Administrators, or unknown SID, or disabled account in group
            $notes = @()
            if ($IsHighPriv -and $isDomain) { $notes += "DomainAccountInPrivGroup" }
            if ($member.Name -match "S-1-5-\d+-\d+" -and $member.Name -notmatch "\\") { $notes += "UnresolvedSID" }
            if ($isDisabled -eq $true) { $notes += "AccountDisabled" }
            if ($IsHighPriv -and $isDisabled -eq $true) { $notes += "DisabledInPrivGroup" }

            $Results.Add([PSCustomObject]@{
                ComputerName    = $ComputerName
                GroupName       = $Group.Name
                GroupDesc       = $Group.Description
                IsHighPriv      = $IsHighPriv
                MemberName      = $member.Name
                MemberSID       = $member.SID
                ObjectClass     = $member.ObjectClass
                PrincipalSource = $member.PrincipalSource
                IsDomainAccount = $isDomain
                IsDisabled      = $isDisabled
                LastLogon       = $lastLogon
                Notes           = $notes -join "; "
            })
        }
    }

    # Export to CSV
    $Results | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding $Encoding
    Write-Output "`n$(Get-TimeStamp) Report saved to: $ReportPath"

    # Console summary
    Write-Output "`n=== LOCAL GROUP MEMBERSHIP SUMMARY: $ComputerName ==="
    Write-Output "`nHigh-Privilege Group Members:"
    $Results | Where-Object { $_.IsHighPriv -and $_.MemberName -notlike "(empty*)" -and $_.MemberName -notlike "(ERROR*)" } | ForEach-Object {
        $flag = if ($_.Notes) { " [!$($_.Notes)]" } else { "" }
        Write-Output "  [$($_.GroupName)] $($_.MemberName) ($($_.PrincipalSource))$flag"
    }

    $flagged = $Results | Where-Object { $_.Notes -ne "" -and $_.Notes -ne $null }
    if ($flagged) {
        Write-Output "`nFlagged entries requiring review:"
        $flagged | ForEach-Object {
            Write-Output "  [$($_.GroupName)] $($_.MemberName) - $($_.Notes)"
        }
    }

    Write-Output "`nGroup membership counts:"
    $Results | Where-Object { $_.MemberName -notlike "(empty*)" -and $_.MemberName -notlike "(ERROR*)" } | Group-Object GroupName | Sort-Object Count -Descending | ForEach-Object {
        Write-Output "  $($_.Name): $($_.Count) member(s)"
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
