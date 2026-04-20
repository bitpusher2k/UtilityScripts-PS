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
# Set-AuditPolicyStronger.ps1 - By Bitpusher/The Digital Fox
# v1.0 last updated 2026-04-19
# Script to configure Windows Advanced Audit Policy based on the
# "Stronger Recommendations" from Microsoft's audit policy guidance.
#
# Sets 21 audit subcategories covering Account Logon, Account Management,
# Detailed Tracking, Logon/Logoff, Policy Change, and System categories.
# All subcategories are set to audit Success; most also audit Failure
# (Account Lockout, Logoff, and MPSSVC Rule-Level Policy Change audit
# Success only per Microsoft's stronger recommendation).
#
# For Active Directory environments this should be managed through GPO
# using Advanced Audit Policy Configuration rather than running locally:
#   https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration
#
# Important: When using Advanced Audit Policy subcategories, enable the
# "Audit: Force audit policy subcategory settings (Windows Vista or later)
# to override audit policy category settings" security option to prevent
# top-level category policies from overriding subcategory settings.
#
# Usage:
# powershell -executionpolicy bypass -f ./Set-AuditPolicyStronger.ps1
# powershell -executionpolicy bypass -f ./Set-AuditPolicyStronger.ps1 -ReportOnly
#
# Run as administrator - auditpol requires elevated privileges.
#
# To revert to defaults (disable all auditing):
#   auditpol /clear /y
#
# References:
#   Microsoft Audit Policy Recommendations (Stronger):
#     https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations?tabs=winclient
#   Advanced Audit Policy Configuration for AD:
#     https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration
#   Auditing Constants (Subcategory GUIDs - Ntsecapi.h):
#     https://learn.microsoft.com/en-us/windows/win32/secauthz/auditing-constants
#   Auditpol command reference:
#     https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-set
#   Splunk data-driven audit policy guide:
#     https://www.splunk.com/en_us/blog/security/windows-audit-policy-guide.html
#
#security #audit #hardening #compliance #powershell

#Requires -Version 5.1
#Requires -RunAsAdministrator

param(
    # --- script-specific params ---
    [switch]$ReportOnly,           # Only report current audit policy without making changes

    # --- standard infrastructure params ---
    [string]$scriptName = "Set-AuditPolicyStronger",
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

    # === Audit Policy Configuration ===
    #
    # Microsoft "Stronger Recommendations" audit subcategories.
    # GUID references: https://learn.microsoft.com/en-us/windows/win32/secauthz/auditing-constants
    # Policy source:   https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations
    #
    # Format: GUID = @(SuccessSetting, FailureSetting, FriendlyName, Category)
    #
    $auditPolicy = [ordered]@{
        # --- Account Logon ---
        '{0CCE923F-69AE-11D9-BED3-505054503030}' = @('enable', 'enable', 'Credential Validation',              'Account Logon')
        '{0CCE9242-69AE-11D9-BED3-505054503030}' = @('enable', 'enable', 'Kerberos Authentication Service',     'Account Logon')
        '{0CCE9240-69AE-11D9-BED3-505054503030}' = @('enable', 'enable', 'Kerberos Service Ticket Operations',  'Account Logon')
        '{0CCE9241-69AE-11D9-BED3-505054503030}' = @('enable', 'enable', 'Other Account Logon Events',          'Account Logon')

        # --- Account Management ---
        '{0CCE9236-69AE-11D9-BED3-505054503030}' = @('enable', 'enable', 'Computer Account Management',         'Account Management')
        '{0CCE923A-69AE-11D9-BED3-505054503030}' = @('enable', 'enable', 'Other Account Management Events',     'Account Management')
        '{0CCE9237-69AE-11D9-BED3-505054503030}' = @('enable', 'enable', 'Security Group Management',           'Account Management')
        '{0CCE9235-69AE-11D9-BED3-505054503030}' = @('enable', 'enable', 'User Account Management',             'Account Management')

        # --- Detailed Tracking ---
        '{0CCE922D-69AE-11D9-BED3-505054503030}' = @('enable', 'enable', 'DPAPI Activity',                      'Detailed Tracking')
        '{0CCE922B-69AE-11D9-BED3-505054503030}' = @('enable', 'enable', 'Process Creation',                    'Detailed Tracking')

        # --- Logon/Logoff ---
        '{0CCE9217-69AE-11D9-BED3-505054503030}' = @('enable', 'disable', 'Account Lockout',                    'Logon/Logoff')
        '{0CCE9216-69AE-11D9-BED3-505054503030}' = @('enable', 'disable', 'Logoff',                             'Logon/Logoff')
        '{0CCE9215-69AE-11D9-BED3-505054503030}' = @('enable', 'enable',  'Logon',                              'Logon/Logoff')
        '{0CCE921B-69AE-11D9-BED3-505054503030}' = @('enable', 'enable',  'Special Logon',                      'Logon/Logoff')

        # --- Policy Change ---
        '{0CCE922F-69AE-11D9-BED3-505054503030}' = @('enable', 'enable',  'Audit Policy Change',                'Policy Change')
        '{0CCE9230-69AE-11D9-BED3-505054503030}' = @('enable', 'enable',  'Authentication Policy Change',       'Policy Change')
        '{0CCE9232-69AE-11D9-BED3-505054503030}' = @('enable', 'disable', 'MPSSVC Rule-Level Policy Change',    'Policy Change')

        # --- System ---
        '{0CCE9213-69AE-11D9-BED3-505054503030}' = @('enable', 'enable', 'IPsec Driver',                        'System')
        '{0CCE9210-69AE-11D9-BED3-505054503030}' = @('enable', 'enable', 'Security State Change',               'System')
        '{0CCE9211-69AE-11D9-BED3-505054503030}' = @('enable', 'enable', 'Security System Extension',           'System')
        '{0CCE9212-69AE-11D9-BED3-505054503030}' = @('enable', 'enable', 'System Integrity',                    'System')
    }

    try {
        if ($ReportOnly) {
            Write-Output "$(Get-TimeStamp) ReportOnly mode - displaying current audit policy without making changes" | Tee-Object -FilePath $logFilePath -Append
        } else {
            Write-Output "$(Get-TimeStamp) Applying Microsoft 'Stronger Recommendations' audit policy ($($auditPolicy.Count) subcategories)" | Tee-Object -FilePath $logFilePath -Append
            Write-Output "" | Tee-Object -FilePath $logFilePath -Append

            $successCount = 0
            $failCount = 0
            $currentCategory = ""

            foreach ($entry in $auditPolicy.GetEnumerator()) {
                $guid = $entry.Key
                $success = $entry.Value[0]
                $failure = $entry.Value[1]
                $friendlyName = $entry.Value[2]
                $category = $entry.Value[3]

                # Print category header when it changes
                if ($category -ne $currentCategory) {
                    $currentCategory = $category
                    Write-Output "$(Get-TimeStamp) --- $category ---" | Tee-Object -FilePath $logFilePath -Append
                }

                $settingDesc = "Success:$success / Failure:$failure"
                Write-Output "$(Get-TimeStamp)   Setting: $friendlyName ($guid) -> $settingDesc" | Tee-Object -FilePath $logFilePath -Append

                $result = & auditpol /set /subcategory:$guid /success:$success /failure:$failure 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $successCount++
                } else {
                    $failCount++
                    Write-Output "$(Get-TimeStamp)   WARNING: auditpol returned exit code $LASTEXITCODE for $friendlyName" | Tee-Object -FilePath $logFilePath -Append
                    Write-Output "$(Get-TimeStamp)   Output: $result" | Tee-Object -FilePath $logFilePath -Append
                }
            }

            Write-Output "" | Tee-Object -FilePath $logFilePath -Append
            Write-Output "$(Get-TimeStamp) Configuration complete: $successCount succeeded, $failCount failed out of $($auditPolicy.Count) subcategories" | Tee-Object -FilePath $logFilePath -Append
        }

        # --- Report current effective audit policy ---
        Write-Output "" | Tee-Object -FilePath $logFilePath -Append
        Write-Output "$(Get-TimeStamp) === Current Audit Policy (non-default settings) ===" | Tee-Object -FilePath $logFilePath -Append

        $auditReport = auditpol /get /category:* /r 2>&1
        if ($LASTEXITCODE -eq 0) {
            $parsed = $auditReport | ConvertFrom-Csv |
                Where-Object { $_.'Inclusion Setting' -ne 'No Auditing' } |
                Select-Object Subcategory, 'Inclusion Setting'

            if ($parsed) {
                $tableOutput = ($parsed | Format-Table -AutoSize | Out-String).Trim()
                Write-Output $tableOutput | Tee-Object -FilePath $logFilePath -Append
            } else {
                Write-Output "$(Get-TimeStamp) No subcategories are currently configured for auditing" | Tee-Object -FilePath $logFilePath -Append
            }
        } else {
            Write-Output "$(Get-TimeStamp) WARNING: Unable to retrieve audit policy report (exit code: $LASTEXITCODE)" | Tee-Object -FilePath $logFilePath -Append
        }

        if ($ReportOnly -or $failCount -eq 0) {
            $MyExitStatus = 0
        }

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
# One-liner version to set audit policy based on "Stronger Recommendations" from Microsoft -
# https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations?tabs=winclient
# For AD environments this can be managed through GPO -
# https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration
#
# @{'{0CCE923F-69AE-11D9-BED3-505054503030}'='enable','enable';'{0CCE9242-69AE-11D9-BED3-505054503030}'='enable','enable';'{0CCE9240-69AE-11D9-BED3-505054503030}'='enable','enable';'{0CCE9241-69AE-11D9-BED3-505054503030}'='enable','enable';'{0CCE9236-69AE-11D9-BED3-505054503030}'='enable','enable';'{0CCE923A-69AE-11D9-BED3-505054503030}'='enable','enable';'{0CCE9237-69AE-11D9-BED3-505054503030}'='enable','enable';'{0CCE9235-69AE-11D9-BED3-505054503030}'='enable','enable';'{0CCE922D-69AE-11D9-BED3-505054503030}'='enable','enable';'{0CCE922B-69AE-11D9-BED3-505054503030}'='enable','enable';'{0CCE9217-69AE-11D9-BED3-505054503030}'='enable','disable';'{0CCE9216-69AE-11D9-BED3-505054503030}'='enable','disable';'{0CCE9215-69AE-11D9-BED3-505054503030}'='enable','enable';'{0CCE921B-69AE-11D9-BED3-505054503030}'='enable','enable';'{0CCE922F-69AE-11D9-BED3-505054503030}'='enable','enable';'{0CCE9230-69AE-11D9-BED3-505054503030}'='enable','enable';'{0CCE9232-69AE-11D9-BED3-505054503030}'='enable','disable';'{0CCE9213-69AE-11D9-BED3-505054503030}'='enable','enable';'{0CCE9210-69AE-11D9-BED3-505054503030}'='enable','enable';'{0CCE9211-69AE-11D9-BED3-505054503030}'='enable','enable';'{0CCE9212-69AE-11D9-BED3-505054503030}'='enable','enable'}.GetEnumerator()|%{auditpol /set /subcategory:$($_.Key) /success:$($_.Value[0]) /failure:$($_.Value[1])} ; auditpol /get /category:* /r | ConvertFrom-Csv | Where-Object {$_.'Inclusion Setting' -ne 'No Auditing'} | Select-Object Subcategory,'Inclusion Setting' | Format-Table -AutoSize
