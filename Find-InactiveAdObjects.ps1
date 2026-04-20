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
# Find-InactiveAdObjects.ps1 - By Bitpusher/The Digital Fox
# v1.1 last updated 2026-04-18
# Run on an Active Directory Domain Controller to identify stale, orphaned, or misconfigured
# AD objects. Reports on:
#  - Enabled user accounts with no logon in N days (stale users)
#  - Enabled computer accounts with no logon in N days (stale computers)
#  - Disabled accounts NOT in an OU containing "disabled" or "inactive" in its name
#    (i.e., disabled but not properly staged for removal)
#  - Enabled user accounts with a past expiration date (expired but not disabled)
#  - Enabled user accounts with PasswordNeverExpires set
#  - Enabled user accounts with no password set (PasswordNotRequired)
# Outputs separate CSVs for each category, plus a combined summary.
# Designed to complement GenerateAdUserReport.ps1 for AD hygiene reviews.
#
# Usage:
# powershell -executionpolicy bypass -f .\Find-InactiveAdObjects.ps1
# powershell -executionpolicy bypass -f .\Find-InactiveAdObjects.ps1 -UserInactiveDays 90 -ComputerInactiveDays 60 -OutputPath "C:\temp"
#
# Email report to yourself by including the emailServer, emailFrom, emailTo,
# emailUsername, and emailPassword parameters.
#
#comp #ad #security #incident #active #directory #stale #inactive #disabled #expired #script #powershell

#Requires -Version 4

[CmdletBinding()]
param(
    [int]$UserInactiveDays = 90,                   # Flag users with no logon in this many days
    [int]$ComputerInactiveDays = 90,               # Flag computers with no logon in this many days
    [string]$OutputPath = "C:\temp",               # Folder for CSV output
    [string]$scriptName = "Find-InactiveAdObjects",
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

    $DateStamp = $(Get-Date).ToString("yyyyMMddHHmm")
    $UserCutoff     = (Get-Date).AddDays(-$UserInactiveDays)
    $ComputerCutoff = (Get-Date).AddDays(-$ComputerInactiveDays)
    $Now            = Get-Date

    # Common AD property sets
    $UserProps     = @("Name","SamAccountName","mail","Enabled","LastLogonDate","PasswordLastSet","PasswordNeverExpires","PasswordNotRequired","AccountExpirationDate","DistinguishedName","Description","WhenCreated","WhenChanged","MemberOf")
    $ComputerProps = @("Name","SamAccountName","Enabled","LastLogonDate","OperatingSystem","OperatingSystemVersion","DistinguishedName","WhenCreated","WhenChanged","Description")

    # ----------------------------------------------------------------
    # 1. Stale Enabled Users
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Finding enabled users with no logon in $UserInactiveDays days..."
    $StaleUsers = Get-ADUser -Filter { Enabled -eq $true } -Properties $UserProps -ErrorAction Stop |
        Where-Object { $_.LastLogonDate -ne $null -and $_.LastLogonDate -lt $UserCutoff -and $_.SamAccountName -notlike "krbtgt" -and $_.SamAccountName -notlike "Guest" } |
        Select-Object Name, SamAccountName, mail, Enabled,
            LastLogonDate,
            @{ N = "LastLogonDateISO"; E = { ($_.LastLogonDate).ToString("o") } },
            @{ N = "DaysSinceLogon"; E = { [math]::Round(($Now - $_.LastLogonDate).TotalDays, 0) } },
            PasswordLastSet,
            PasswordNeverExpires,
            AccountExpirationDate,
            DistinguishedName, Description, WhenCreated
    $StaleUsersPath = "$OutputPath\$($env:computername)_AD_StaleUsers_$DateStamp.csv"
    $StaleUsers | Export-Csv $StaleUsersPath -NoTypeInformation -Encoding $Encoding
    Write-Output "$(Get-TimeStamp) Stale enabled users (no logon in $UserInactiveDays days): $($StaleUsers | Measure-Object | Select-Object -ExpandProperty Count)"

    # ----------------------------------------------------------------
    # 2. Stale Enabled Computers
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Finding enabled computers with no logon in $ComputerInactiveDays days..."
    $StaleComputers = Get-ADComputer -Filter { Enabled -eq $true } -Properties $ComputerProps -ErrorAction Stop |
        Where-Object { $_.LastLogonDate -ne $null -and $_.LastLogonDate -lt $ComputerCutoff } |
        Select-Object Name, SamAccountName, Enabled,
            LastLogonDate,
            @{ N = "LastLogonDateISO"; E = { ($_.LastLogonDate).ToString("o") } },
            @{ N = "DaysSinceLogon"; E = { [math]::Round(($Now - $_.LastLogonDate).TotalDays, 0) } },
            OperatingSystem, OperatingSystemVersion,
            DistinguishedName, Description, WhenCreated
    $StaleComputersPath = "$OutputPath\$($env:computername)_AD_StaleComputers_$DateStamp.csv"
    $StaleComputers | Export-Csv $StaleComputersPath -NoTypeInformation -Encoding $Encoding
    Write-Output "$(Get-TimeStamp) Stale enabled computers (no logon in $ComputerInactiveDays days): $($StaleComputers | Measure-Object | Select-Object -ExpandProperty Count)"

    # ----------------------------------------------------------------
    # 3. Disabled accounts NOT in a "disabled/inactive" OU
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Finding disabled accounts NOT in a staging OU..."
    $DisabledNotStaged = Get-ADUser -Filter { Enabled -eq $false } -Properties $UserProps -ErrorAction Stop |
        Where-Object { $_.DistinguishedName -notmatch "(?i)disabled|inactive|offboard|termed|terminated|deactivat|archive" } |
        Select-Object Name, SamAccountName, mail, Enabled, LastLogonDate, PasswordLastSet,
            AccountExpirationDate, DistinguishedName, Description, WhenChanged
    $DisabledNotStagedPath = "$OutputPath\$($env:computername)_AD_DisabledNotStaged_$DateStamp.csv"
    $DisabledNotStaged | Export-Csv $DisabledNotStagedPath -NoTypeInformation -Encoding $Encoding
    Write-Output "$(Get-TimeStamp) Disabled users NOT in a staging OU: $($DisabledNotStaged | Measure-Object | Select-Object -ExpandProperty Count)"

    # ----------------------------------------------------------------
    # 4. Enabled users with past expiration date
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Finding enabled users with expired accounts..."
    $ExpiredEnabled = Get-ADUser -Filter { Enabled -eq $true -and AccountExpirationDate -lt $Now -and AccountExpirationDate -ne "00:00:00" } -Properties $UserProps -ErrorAction Stop |
        Where-Object { $_.AccountExpirationDate -ne $null -and $_.AccountExpirationDate -lt $Now } |
        Select-Object Name, SamAccountName, mail, Enabled, LastLogonDate,
            AccountExpirationDate,
            @{ N = "DaysExpired"; E = { [math]::Round(($Now - $_.AccountExpirationDate).TotalDays, 0) } },
            DistinguishedName, Description
    $ExpiredEnabledPath = "$OutputPath\$($env:computername)_AD_ExpiredStillEnabled_$DateStamp.csv"
    $ExpiredEnabled | Export-Csv $ExpiredEnabledPath -NoTypeInformation -Encoding $Encoding
    Write-Output "$(Get-TimeStamp) Enabled accounts with past expiration date: $($ExpiredEnabled | Measure-Object | Select-Object -ExpandProperty Count)"

    # ----------------------------------------------------------------
    # 5. Enabled users with PasswordNeverExpires
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Finding enabled users with PasswordNeverExpires..."
    $PwdNeverExpires = Get-ADUser -Filter { Enabled -eq $true -and PasswordNeverExpires -eq $true } -Properties $UserProps -ErrorAction Stop |
        Where-Object { $_.SamAccountName -notlike "krbtgt" } |
        Select-Object Name, SamAccountName, mail, Enabled, LastLogonDate, PasswordLastSet,
            PasswordNeverExpires, DistinguishedName, Description
    $PwdNeverExpiresPath = "$OutputPath\$($env:computername)_AD_PwdNeverExpires_$DateStamp.csv"
    $PwdNeverExpires | Export-Csv $PwdNeverExpiresPath -NoTypeInformation -Encoding $Encoding
    Write-Output "$(Get-TimeStamp) Enabled users with PasswordNeverExpires: $($PwdNeverExpires | Measure-Object | Select-Object -ExpandProperty Count)"

    # ----------------------------------------------------------------
    # 6. Enabled users with PasswordNotRequired
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Finding enabled users with PasswordNotRequired..."
    $PwdNotRequired = Get-ADUser -Filter { Enabled -eq $true -and PasswordNotRequired -eq $true } -Properties $UserProps -ErrorAction Stop |
        Select-Object Name, SamAccountName, mail, Enabled, LastLogonDate, PasswordLastSet, DistinguishedName, Description
    $PwdNotRequiredPath = "$OutputPath\$($env:computername)_AD_PwdNotRequired_$DateStamp.csv"
    $PwdNotRequired | Export-Csv $PwdNotRequiredPath -NoTypeInformation -Encoding $Encoding
    Write-Output "$(Get-TimeStamp) Enabled users with PasswordNotRequired: $($PwdNotRequired | Measure-Object | Select-Object -ExpandProperty Count)"

    # ----------------------------------------------------------------
    # Console Summary
    # ----------------------------------------------------------------
    Write-Output "`n=== AD HYGIENE SUMMARY ==="
    Write-Output "  Stale enabled users (>$UserInactiveDays days):    $($StaleUsers | Measure-Object | Select-Object -ExpandProperty Count) -- $StaleUsersPath"
    Write-Output "  Stale enabled computers (>$ComputerInactiveDays days): $($StaleComputers | Measure-Object | Select-Object -ExpandProperty Count) -- $StaleComputersPath"
    Write-Output "  Disabled not in staging OU:       $($DisabledNotStaged | Measure-Object | Select-Object -ExpandProperty Count) -- $DisabledNotStagedPath"
    Write-Output "  Expired but still enabled:        $($ExpiredEnabled | Measure-Object | Select-Object -ExpandProperty Count) -- $ExpiredEnabledPath"
    Write-Output "  PasswordNeverExpires (enabled):   $($PwdNeverExpires | Measure-Object | Select-Object -ExpandProperty Count) -- $PwdNeverExpiresPath"
    Write-Output "  PasswordNotRequired (enabled):    $($PwdNotRequired | Measure-Object | Select-Object -ExpandProperty Count) -- $PwdNotRequiredPath"

    $MyExitStatus = 0
    #endregion main

    #region finalization
    if ($logFileFolderPath -ne "") {
        Write-Output "`nScript $scriptName ended at $(Get-TimeStamp)"
        $elapsedTime = $(Get-Date) - $StartTime
        Write-Output "Elapsed time (seconds): $($elapsedTime.TotalSeconds)"
        Stop-Transcript
        if (($emailServer -ne "") -and ($emailUsername -ne "") -and ($emailPassword -ne "") -and ($emailFrom -ne "") -and ($emailTo -ne "")) {
            $attachments = @($logFilePath, $StaleUsersPath, $StaleComputersPath, $DisabledNotStagedPath, $ExpiredEnabledPath, $PwdNeverExpiresPath, $PwdNotRequiredPath)
            Send-MailMessage -SmtpServer "$emailServer" -Port $emailPort -From "$emailFrom" -To "$emailTo" -Subject "$scriptName - $ComputerName - $MyExitStatus - Log File" -Body "$logFilePath" -UseSsl -Credential (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$emailUsername", (ConvertTo-SecureString -String "$emailPassword" -AsPlainText -Force)) -Attachments $attachments
        }
        if (($shareLocation -ne "") -and ($shareUsername -ne "") -and ($sharePassword -ne "")) {
            [securestring]$secStringPassword = ConvertTo-SecureString $sharePassword -AsPlainText -Force
            [pscredential]$shareCred = New-Object System.Management.Automation.PSCredential ($shareUsername, $secStringPassword)
            New-PSDrive -Name LogStore -PSProvider FileSystem -Root "$shareLocation" -Description "Log Store" -Credential $shareCred
            foreach ($f in @($logFilePath, $StaleUsersPath, $StaleComputersPath, $DisabledNotStagedPath, $ExpiredEnabledPath, $PwdNeverExpiresPath, $PwdNotRequiredPath)) {
                Copy-Item -LiteralPath $f -Destination "LogStore:\" -Force -ErrorAction Continue
            }
            Remove-PSDrive -Name LogStore
        } elseif ($shareLocation -ne "") {
            Copy-Item -LiteralPath $LogFilePath -Destination $ShareLocation  -Force -ErrorAction Continue
        }
    }
    Set-PSDebug -Trace 0
    exit $MyExitStatus
    #endregion finalization
}
