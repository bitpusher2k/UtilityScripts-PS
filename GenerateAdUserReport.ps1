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
# GenerateAdUserReport.ps1 - By Bitpusher/The Digital Fox
# v2.3 last updated 2025-03-15
# Run on Active Directory Domain Controller to generate CSV report of AD users
# which includes:
# * Name (string)
# * GivenNameSurname (string)
# * SamAccountName (string)
# * mail (string)
# * Enabled (TRUE/FALSE)
# * PasswordExpired (TRUE/FALSE)
# * PasswordLastSet (date)
# * passwordlastsetISO (ISO 8601 formatted date for easy sorting)
# * PasswordNeverExpires (TRUE/FALSE)
# * CannotChangePassword (TRUE/FALSE)
# * Created (date)
# * CreatedISO (ISO 8601 formatted date for easy sorting)
# * WhenChanged (date)
# * WhenCreated (date)
# * accountExpires (Windows NT time - set to max value for "never expires")
# * AccountExpirationDate (date/Never Expires)
# * LastBadPasswordAttempt (date)
# * LastBadPasswordAttemptISO (ISO 8601 formatted date for easy sorting)
# * badPasswordTime (Windows NT time)
# * badPwdCount (integer)
# * LockedOut (TRUE/FALSE)
# * lockoutTime (date)
# * LastLogonDate (date)
# * LastLogonDateISO (ISO 8601 formatted date for easy sorting)
# * LogonCount (integer)
# * LastLogonTimeStamp (Windows NT time)
# * LastLogonOver30DaysAgo (TRUE/FALSE)
# * Description (string)
# * HomeDirectory (string)
# * HomeDrive (string)
# * TrustedForDelegation (TRUE/FALSE)
# * TrustedToAuthForDelegation (TRUE/FALSE)
# * MemberOf (direct group membership of account)
#
# Appends domain password/lockout policy information at bottom of CSV
#
# Run GenerateTepmPassForAdList script after to generate CSV from this report
# which contains the "SamAccountName" of each user and a NewPassword column
# containing a new temporary passwords to facilitate bulk reset of account passwords.
#
# Usage examples:
# powershell -executionpolicy bypass -f .\GenerateAdUserReport.ps1
#
# powershell -executionpolicy bypass -f .\GenerateAdUserReport.ps1 -Report "Before" -OutputPath "C:\temp"
#
# Use simplified and minified one-liner versions at the bottom to easily
# copy/paste into console of remote system (remote tools don't generally handle
# input with line breaks well).
#
#comp #ad #security #incident #script #active #directory #samaccountname #password #report #powershell

#Requires -Version 4

param(
    [string]$Report = "Before",
    [string]$OutputPath = 'c:\temp'
)

# Ensure output path exists - safe to use if path already exists
New-Item -ItemType Directory -Force -Path $OutputPath

# Get data for Active Directory user account report
Import-Module -Name ActiveDirectory

$AdUserProperties = @(
    "Name",
    "mail",
    "Enabled",
    "PasswordExpired",
    "PasswordLastSet",
    "PasswordNeverExpires",
    "CannotChangePassword",
    "Created",
    "createTimeStamp",
    "accountExpires",
    "LastBadPasswordAttempt",
    "badPasswordTime",
    "badPwdCount",
    "LockedOut",
    "lockoutTime",
    "LastLogonDate",
    "LastLogonTimeStamp",
    "MemberOf",
    "GivenName",
    "Surname",
    "LogonCount",
    "SamAccountName",
    "TrustedForDelegation",
    "TrustedToAuthForDelegation",
    "WhenChanged",
    "WhenCreated",
    "Description",
    "HomeDirectory",
    "HomeDrive"
)

$AdInfo = Get-ADUser -Filter * -properties $AdUserProperties

# Create report columns, adding ISO 8601 time columns and looking up account group membership
$AdReport = $AdInfo |
    Select-Object Name,
    GivenName,
    Surname,
    SamAccountName,
    mail,
    Enabled,
    PasswordExpired,
    PasswordLastSet,
    @{ Name = "passwordlastsetISO"; Expression = { ($_.passwordlastset).ToString("o") } },
    PasswordNeverExpires,
    CannotChangePassword,
    Created,
    @{ Name = "CreatedISO"; Expression = { ($_.Created).ToString("o") } },
    WhenChanged,
    WhenCreated,
    accountExpires,
    @{ Name = 'AccountExpirationDate'; Expression = { if ($_.accountExpires -gt 0 -and $_.accountExpires -ne 9223372036854775807) { ([datetime]::FromFileTime($_.accountExpires)).ToString("o") } else { 'Never Expires' } } },
    LastBadPasswordAttempt,
    @{ Name = "LastBadPasswordAttemptISO"; Expression = { ($_.LastBadPasswordAttempt).ToString("o") } },
    badPasswordTime,
    badPwdCount,
    LockedOut,
    lockoutTime,
    LastLogonDate,
    @{ Name = "LastLogonDateISO"; Expression = { ($_.LastLogonDate).ToString("o") } },
    LogonCount,
    LastLogonTimeStamp,
    @{ Name = "LastLogonOver30DaysAgo"; Expression = { $_.LastLogonDate -lt (Get-Date).AddDays(-30) } },
    Description,
    HomeDirectory,
    HomeDrive,
    TrustedForDelegation,
    TrustedToAuthForDelegation,
    @{ Name = "MemberOf"; Expression = { ($_.memberof | Get-ADGroup | Select-Object -ExpandProperty name | Sort-Object) -join ", " } }

# Get domain password policy to append at end of report
$AdPwPolicy = Get-ADDefaultDomainPasswordPolicy

$TempPasswordsGenerated = $(Get-ChildItem c:\temp -Filter "temppasswords.csv")

if ($Report -eq "After" -or $TempPasswordsGenerated.LastWriteTime -gt (Get-Date).AddHours(-1)) {
    $OutputFile = $OutputPath + "\$($env:computername)_account_report_after_reset-$($(Get-Date).ToString("yyyyMMddHHmm")).csv"
    $AdReport | Export-Csv $OutputFile -NoTypeInformation -Encoding utf8
    $AdPwPolicy | Out-File -FilePath $OutputFile -Append
    Write-Output "`nReport generated and saved to: $OutputFile"
    Write-Output "Be sure to remove temporary password list from server and review account report."
} else {
    $OutputFile = $OutputPath + "\$($env:computername)_account_report_before_reset-$($(Get-Date).ToString("yyyyMMddHHmm")).csv"
    $AdReport | Export-Csv $OutputFile -NoTypeInformation -Encoding utf8
    $AdPwPolicy | Out-File -FilePath $OutputFile -Append
    Write-Output "`nReport generated and saved to: $OutputFile"
    Write-Output "Run GenerateTepmPassForAdList.ps1 to create account name and temporary password list for bulk reset."
}


# Minified bare-bones one-liner version of script for copy/paste into console:
$ReportBeforeReset = @'
Get-ADUser -filter * -properties Name, mail, Enabled, PasswordExpired, PasswordLastSet, PasswordNeverExpires, CannotChangePassword, Created, createTimeStamp, accountExpires, LastBadPasswordAttempt, badPasswordTime, badPwdCount, LockedOut, lockoutTime, LastLogonDate, LastLogonTimeStamp, MemberOf, GivenName, Surname, LogonCount, SamAccountName, TrustedForDelegation, TrustedToAuthForDelegation, WhenChanged, WhenCreated, Description, HomeDirectory, HomeDrive | Select Name, GivenName, Surname, SamAccountName, mail, Enabled, PasswordExpired, PasswordLastSet, @{Name="passwordlastsetISO";Expression={($_.passwordlastset).ToString("o")}}, PasswordNeverExpires, CannotChangePassword, Created, @{Name="CreatedISO";Expression={($_.Created).ToString("o")}}, WhenChanged, WhenCreated, accountExpires, @{Name = 'AccountExpirationDate';Expression = {if ($_.accountExpires -gt 0 -and $_.accountExpires -ne 9223372036854775807) { ([datetime]::FromFileTime($_.accountExpires)).ToString("o") } else { 'Never Expires' } }}, LastBadPasswordAttempt, @{Name="LastBadPasswordAttemptISO";Expression={($_.LastBadPasswordAttempt).ToString("o")}}, badPasswordTime, badPwdCount, LockedOut, lockoutTime, LastLogonDate, @{Name="LastLogonDateISO";Expression={($_.LastLogonDate).ToString("o")}}, LogonCount, LastLogonTimeStamp, @{Name="LastLogonOver30DaysAgo";Expression={$_.LastLogonDate -lt (Get-Date).AddDays(-30)}}, Description, HomeDirectory, HomeDrive, TrustedForDelegation, TrustedToAuthForDelegation, @{Name="MemberOf";Expression={($_.memberof | Get-ADGroup | Select -expandproperty name | Sort) -join ", "}} | epcsv c:\temp\$($env:computername)_account_report_before_reset-$($(Get-Date).ToString("yyyyMMddHHmm")).csv -NTI -Encoding utf8 ; Get-ADDefaultDomainPasswordPolicy | Out-File -FilePath c:\temp\$($env:computername)_account_report_before_reset-$($(Get-Date).ToString("yyyyMMddHHmm")).csv -append
'@
# Version to run after running GenerateTepmPassForAdList.ps1 and using the list to reset AD accounts:
$ReportAfterReset = @'
Get-ADUser -filter * -properties Name, mail, Enabled, PasswordExpired, PasswordLastSet, PasswordNeverExpires, CannotChangePassword, Created, createTimeStamp, accountExpires, LastBadPasswordAttempt, badPasswordTime, badPwdCount, LockedOut, lockoutTime, LastLogonDate, LastLogonTimeStamp, MemberOf, GivenName, Surname, LogonCount, SamAccountName, TrustedForDelegation, TrustedToAuthForDelegation, WhenChanged, WhenCreated, Description, HomeDirectory, HomeDrive | Select Name, GivenName, Surname, SamAccountName, mail, Enabled, PasswordExpired, PasswordLastSet, @{Name="passwordlastsetISO";Expression={($_.passwordlastset).ToString("o")}}, PasswordNeverExpires, CannotChangePassword, Created, @{Name="CreatedISO";Expression={($_.Created).ToString("o")}}, WhenChanged, WhenCreated, accountExpires, @{Name = 'AccountExpirationDate';Expression = {if ($_.accountExpires -gt 0 -and $_.accountExpires -ne 9223372036854775807) { ([datetime]::FromFileTime($_.accountExpires)).ToString("o") } else { 'Never Expires' } }}, LastBadPasswordAttempt, @{Name="LastBadPasswordAttemptISO";Expression={($_.LastBadPasswordAttempt).ToString("o")}}, badPasswordTime, badPwdCount, LockedOut, lockoutTime, LastLogonDate, @{Name="LastLogonDateISO";Expression={($_.LastLogonDate).ToString("o")}}, LogonCount, LastLogonTimeStamp, @{Name="LastLogonOver30DaysAgo";Expression={$_.LastLogonDate -lt (Get-Date).AddDays(-30)}}, Description, HomeDirectory, HomeDrive, TrustedForDelegation, TrustedToAuthForDelegation, @{Name="MemberOf";Expression={($_.memberof | Get-ADGroup | Select -expandproperty name | Sort) -join ", "}} | epcsv c:\temp\$($env:computername)_account_report_after_reset-$($(Get-Date).ToString("yyyyMMddHHmm")).csv -NTI -Encoding utf8 ; Get-ADDefaultDomainPasswordPolicy | Out-File -FilePath c:\temp\$($env:computername)_account_report_after_reset-$($(Get-Date).ToString("yyyyMMddHHmm")).csv -append
'@
