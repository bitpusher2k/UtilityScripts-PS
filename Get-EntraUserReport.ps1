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
# Get-EntraUserReport.ps1 - By Bitpusher/The Digital Fox
# v1.3 last updated 2026-04-19
# Queries Microsoft Entra ID (Azure AD) via the Microsoft.Graph PowerShell module to generate
# a security-focused user report. Designed as a cloud complement to GenerateAdUserReport.ps1
# for hybrid environments.
#
# See https://github.com/bitpusher2k/M365IRScripts for additional M365 security scripts.
#
# Reports on:
#  - User account status (enabled/disabled, account type, licenses)
#  - MFA registration status (registered methods, default method)
#  - Per-user MFA state (enabled/disabled/enforced via legacy per-user setting)
#  - Authentication methods registered (TOTP, FIDO2 key, phone, email, etc.)
#  - Sign-in activity (last successful sign-in, last non-interactive sign-in)
#  - Whether the account is synced from on-premises AD
#  - Conditional Access / risky sign-in status
#  - Licensed vs. unlicensed users
#
# Requires: Microsoft.Graph PowerShell module (installed automatically if not present)
# Authentication: Uses device code flow or service principal (ClientID/ClientSecret/DirectoryID)
# Minimum permissions needed: User.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All
#
# Usage (interactive - prompts for login):
# powershell -executionpolicy bypass -f .\Get-EntraUserReport.ps1
#
# Usage (service principal / app registration - for automation):
# powershell -executionpolicy bypass -f .\Get-EntraUserReport.ps1 -ClientID "xxxx" -DirectoryID "xxxx" -ClientSecret "xxxx"
#
# Email report to yourself by including the emailServer, emailFrom, emailTo,
# emailUsername, and emailPassword parameters.
#
#comp #ad #azure #entra #mfa #security #incident #script #powershell #graph #m365

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$OutputPath = "C:\temp",               # Folder for CSV output
    [int]$IncludeGuests = 0,                       # 1 = include guest (B2B) accounts
    [int]$IncludeServicePrincipals = 0,            # 1 = include service accounts
    [string]$ClientID = "",                        # App registration client ID (for non-interactive auth)
    [string]$DirectoryID = "",                     # Azure AD tenant ID
    [string]$ClientSecret = "",                    # App registration client secret
    [string]$scriptName = "Get-EntraUserReport",
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

    #region install-modules
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $requiredModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Users", "Microsoft.Graph.Identity.SignIns", "Microsoft.Graph.Reports")
    foreach ($module in $requiredModules) {
        if (!(Get-Module -ListAvailable -Name $module)) {
            Write-Output "$(Get-TimeStamp) Installing module: $module"
            Install-Module $module -Force -SkipPublisherCheck -Scope CurrentUser -ErrorAction Stop | Out-Null
        }
        Import-Module $module -Force -ErrorAction Stop | Out-Null
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

    New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
    $DateStamp  = $(Get-Date).ToString("yyyyMMddHHmm")
    $ReportPath = "$OutputPath\EntraUserReport_$DateStamp.csv"

    # ----------------------------------------------------------------
    # Connect to Microsoft Graph
    # ----------------------------------------------------------------
    $Scopes = @("User.Read.All", "AuditLog.Read.All", "UserAuthenticationMethod.Read.All", "Reports.Read.All")

    Write-Output "$(Get-TimeStamp) Connecting to Microsoft Graph..."
    if ($ClientID -ne "" -and $DirectoryID -ne "" -and $ClientSecret -ne "") {
        Write-Output "$(Get-TimeStamp) Using service principal authentication (ClientID: $ClientID)"
        $SecureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
        $ClientSecretCredential = New-Object System.Management.Automation.PSCredential ($ClientID, $SecureSecret)
        Connect-MgGraph -TenantId $DirectoryID -ClientSecretCredential $ClientSecretCredential -NoWelcome -ErrorAction Stop
    } else {
        Write-Output "$(Get-TimeStamp) Using interactive device code authentication (browser login required)."
        Connect-MgGraph -Scopes $Scopes -NoWelcome -ErrorAction Stop
    }
    Write-Output "$(Get-TimeStamp) Connected to Graph. Tenant: $((Get-MgContext).TenantId)"

    # ----------------------------------------------------------------
    # Get all users
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Retrieving user list..."
    $UserFilter = if ($IncludeGuests -eq 0) { "userType eq 'Member'" } else { $null }
    $UserProperties = @(
        "Id","DisplayName","GivenName","Surname","UserPrincipalName","Mail","UserType",
        "AccountEnabled","CreatedDateTime","SignInActivity","OnPremisesSyncEnabled",
        "OnPremisesLastSyncDateTime","AssignedLicenses","PasswordPolicies","JobTitle","Department"
    )
    $AllUsers = if ($UserFilter) {
        Get-MgUser -Filter $UserFilter -Property $UserProperties -All -ErrorAction Stop
    } else {
        Get-MgUser -Property $UserProperties -All -ErrorAction Stop
    }
    Write-Output "$(Get-TimeStamp) Retrieved $($AllUsers.Count) user accounts."

    # ----------------------------------------------------------------
    # Get MFA registration report (requires Reports.Read.All)
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Retrieving MFA registration data..."
    $MFARegistrations = @{}
    try {
        $RegDetails = Get-MgReportAuthenticationMethodUserRegistrationDetail -All -ErrorAction Stop
        foreach ($reg in $RegDetails) {
            $MFARegistrations[$reg.UserPrincipalName] = $reg
        }
        Write-Output "$(Get-TimeStamp) Got MFA registration details for $($MFARegistrations.Count) users."
    } catch {
        Write-Warning "$(Get-TimeStamp) Could not retrieve MFA registration report: $($_.Exception.Message)"
        Write-Warning "$(Get-TimeStamp) This usually means the Reports.Read.All permission is missing or the license does not include Entra ID P1."
    }

    # ----------------------------------------------------------------
    # Build report
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Building report rows..."
    $Results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($user in $AllUsers) {
        $mfa = $MFARegistrations[$user.UserPrincipalName]

        # Sign-in activity
        $lastSignIn = if ($user.SignInActivity.LastSignInDateTime) { $user.SignInActivity.LastSignInDateTime.ToString("o") } else { "Never/Unknown" }
        $lastNonInteractive = if ($user.SignInActivity.LastNonInteractiveSignInDateTime) { $user.SignInActivity.LastNonInteractiveSignInDateTime.ToString("o") } else { "Never/Unknown" }

        # Days since last sign-in
        $daysSince = "Unknown"
        if ($user.SignInActivity.LastSignInDateTime) {
            $daysSince = [math]::Round(((Get-Date) - $user.SignInActivity.LastSignInDateTime).TotalDays, 0)
        }

        # MFA data
        $mfaRegistered        = if ($mfa) { $mfa.IsMfaRegistered } else { "Unknown" }
        $mfaCapable           = if ($mfa) { $mfa.IsMfaCapable } else { "Unknown" }
        $mfaDefaultMethod     = if ($mfa) { $mfa.DefaultMfaMethod } else { "Unknown" }
        $mfaMethods           = if ($mfa) { ($mfa.MethodsRegistered -join ", ") } else { "Unknown" }
        $sspr                 = if ($mfa) { $mfa.IsSsprRegistered } else { "Unknown" }

        # License status
        $isLicensed = $user.AssignedLicenses.Count -gt 0

        # Password policies (check for DisablePasswordExpiration = cloud password never expires)
        $pwdNeverExpires = $user.PasswordPolicies -like "*DisablePasswordExpiration*"

        # On-premises sync status
        $isSynced = $user.OnPremisesSyncEnabled -eq $true

        # Flags
        $flags = [System.Collections.Generic.List[string]]::new()
        if (-not $user.AccountEnabled) { $flags.Add("AccountDisabled") }
        if ($mfaRegistered -eq $false) { $flags.Add("MFANotRegistered") }
        if ($mfaCapable -eq $false) { $flags.Add("MFANotCapable") }
        if ($pwdNeverExpires) { $flags.Add("PasswordNeverExpires") }
        if ($daysSince -ne "Unknown" -and [int]$daysSince -gt 90) { $flags.Add("NoSignIn90Days") }
        if (-not $isLicensed) { $flags.Add("Unlicensed") }

        $Results.Add([PSCustomObject]@{
            DisplayName              = $user.DisplayName
            GivenName                = $user.GivenName
            Surname                  = $user.Surname
            UserPrincipalName        = $user.UserPrincipalName
            Mail                     = $user.Mail
            UserType                 = $user.UserType
            AccountEnabled           = $user.AccountEnabled
            CreatedDateTime          = if ($user.CreatedDateTime) { $user.CreatedDateTime.ToString("o") } else { "" }
            LastSignInDateTime       = $lastSignIn
            LastNonInteractiveSignIn = $lastNonInteractive
            DaysSinceSignIn          = $daysSince
            OnPremisesSynced         = $isSynced
            OnPremLastSyncDate       = if ($user.OnPremisesLastSyncDateTime) { $user.OnPremisesLastSyncDateTime.ToString("o") } else { "" }
            IsLicensed               = $isLicensed
            PasswordNeverExpires     = $pwdNeverExpires
            MFARegistered            = $mfaRegistered
            MFACapable               = $mfaCapable
            MFADefaultMethod         = $mfaDefaultMethod
            MFAMethodsRegistered     = $mfaMethods
            SSPRRegistered           = $sspr
            JobTitle                 = $user.JobTitle
            Department               = $user.Department
            Flags                    = $flags -join "; "
        })
    }

    # ----------------------------------------------------------------
    # Export and summary
    # ----------------------------------------------------------------
    $Results | Sort-Object UserPrincipalName | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding $Encoding
    Write-Output "`n$(Get-TimeStamp) Report saved to: $ReportPath"

    $TotalUsers         = $Results.Count
    $EnabledCount       = ($Results | Where-Object { $_.AccountEnabled -eq $true }).Count
    $DisabledCount      = ($Results | Where-Object { $_.AccountEnabled -eq $false }).Count
    $MFANotRegCount     = ($Results | Where-Object { $_.MFARegistered -eq $false }).Count
    $MFAUnknownCount    = ($Results | Where-Object { $_.MFARegistered -eq "Unknown" }).Count
    $NoSignIn90Count    = ($Results | Where-Object { $_.Flags -like "*NoSignIn90Days*" }).Count
    $SyncedCount        = ($Results | Where-Object { $_.OnPremisesSynced -eq $true }).Count

    Write-Output "`n=== ENTRA ID USER REPORT SUMMARY ==="
    Write-Output "  Total users:           $TotalUsers"
    Write-Output "  Enabled:               $EnabledCount"
    Write-Output "  Disabled:              $DisabledCount"
    Write-Output "  MFA not registered:    $MFANotRegCount"
    Write-Output "  MFA data unavailable:  $MFAUnknownCount"
    Write-Output "  No sign-in in 90 days: $NoSignIn90Count"
    Write-Output "  On-premises synced:    $SyncedCount"

    if ($MFANotRegCount -gt 0) {
        Write-Output "`n  Users WITHOUT MFA registered:"
        $Results | Where-Object { $_.MFARegistered -eq $false -and $_.AccountEnabled -eq $true } | Sort-Object UserPrincipalName | Select-Object -First 20 | ForEach-Object {
            Write-Output "    $($_.UserPrincipalName) - $($_.DisplayName) [Last sign-in: $($_.LastSignInDateTime)]"
        }
    }

    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

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
