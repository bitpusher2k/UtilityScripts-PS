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
# Get-ADComputerInventory.ps1 - By Bitpusher/The Digital Fox
# v1.1 last updated 2026-04-19
# Script to generate an Active Directory computer inventory report
# with details including name, OU, OS, last logon, and staleness flags.
#
# Queries all computer objects from AD (or a specified SearchBase OU)
# and exports a CSV report with the following fields:
#   Name, DNSHostName, Enabled, OU, OperatingSystem, OperatingSystemVersion,
#   OperatingSystemServicePack, LastLogonDate, PasswordLastSet, WhenCreated,
#   WhenChanged, DaysSinceLastLogon, DaysSincePasswordSet, IPv4Address,
#   Description, ManagedBy, IsStale, DistinguishedName
#
# The "IsStale" flag marks computers that have not logged in within
# the configured $StaleDays threshold (default 90 days).
#
# Requires the ActiveDirectory PowerShell module (RSAT-AD-PowerShell).
# Run from a domain-joined machine with appropriate read access to AD.
#
# Usage:
# powershell -executionpolicy bypass -f ./Get-ADComputerInventory.ps1
# powershell -executionpolicy bypass -f ./Get-ADComputerInventory.ps1 -SearchBase "OU=Workstations,DC=contoso,DC=com"
# powershell -executionpolicy bypass -f ./Get-ADComputerInventory.ps1 -StaleDays 60 -OutputPath "C:\Reports"
# powershell -executionpolicy bypass -f ./Get-ADComputerInventory.ps1 -IncludeDisabled:$false
#
# References:
#   Get-ADComputer cmdlet:
#     https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adcomputer
#   AD computer object attributes:
#     https://learn.microsoft.com/en-us/windows/win32/adschema/c-computer
#   LastLogonTimestamp replication behavior (12-14 day default lag):
#     https://learn.microsoft.com/en-us/archive/blogs/askds/the-lastlogontimestamp-attribute-what-it-was-designed-for-and-how-it-works
#   Finding stale AD objects:
#     https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/information-stale-ad-objects
#   RSAT installation:
#     https://learn.microsoft.com/en-us/windows-server/remote/remote-server-administration-tools
#
#ad #inventory #reporting #comp #powershell

#Requires -Version 5.1
#Requires -Modules ActiveDirectory

param(
    # --- script-specific params ---
    [string]$SearchBase = "",                # OU to search; blank = entire domain
    [string]$Server = "",                    # Target a specific DC; blank = auto
    [int]$StaleDays = 90,                    # Days since last logon to flag as stale
    [switch]$IncludeDisabled = $true,        # Include disabled computer accounts
    [string]$OutputPath = "C:\Utility\reports",  # Folder for CSV output
    [string]$Filter = "*",                   # AD filter expression

    # --- standard infrastructure params ---
    [string]$scriptName = "Get-ADComputerInventory",
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

    # === AD Computer Inventory Report ===

    try {
        # --- Verify AD module availability ---
        if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
            Import-Module ActiveDirectory -ErrorAction Stop
        }
        Write-Output "$(Get-TimeStamp) ActiveDirectory module loaded" | Tee-Object -FilePath $logFilePath -Append

        # --- Resolve domain info ---
        $domainInfo = Get-ADDomain -ErrorAction Stop
        $domainDN = $domainInfo.DistinguishedName
        $domainName = $domainInfo.DNSRoot
        Write-Output "$(Get-TimeStamp) Target domain: $domainName ($domainDN)" | Tee-Object -FilePath $logFilePath -Append

        if ($SearchBase -eq "") {
            $SearchBase = $domainDN
            Write-Output "$(Get-TimeStamp) SearchBase: entire domain ($SearchBase)" | Tee-Object -FilePath $logFilePath -Append
        } else {
            Write-Output "$(Get-TimeStamp) SearchBase: $SearchBase" | Tee-Object -FilePath $logFilePath -Append
        }

        # --- Properties to retrieve ---
        # LastLogonTimestamp is replicated across DCs (with 9-14 day lag by default).
        # LastLogon is per-DC and not replicated - we use LastLogonTimestamp/LastLogonDate
        # for inventory purposes as it's more practical across large environments.
        # Ref: https://learn.microsoft.com/en-us/archive/blogs/askds/the-lastlogontimestamp-attribute-what-it-was-designed-for-and-how-it-works
        $adProperties = @(
            'Name'
            'DNSHostName'
            'Enabled'
            'OperatingSystem'
            'OperatingSystemVersion'
            'OperatingSystemServicePack'
            'LastLogonTimestamp'
            'LastLogonDate'
            'PasswordLastSet'
            'WhenCreated'
            'WhenChanged'
            'IPv4Address'
            'Description'
            'ManagedBy'
            'DistinguishedName'
            'SID'
            'ServicePrincipalNames'
        )

        # --- Build Get-ADComputer splat ---
        $adParams = @{
            Filter     = $Filter
            Properties = $adProperties
            SearchBase = $SearchBase
            ErrorAction = 'Stop'
        }
        if ($Server -ne "") {
            $adParams['Server'] = $Server
            Write-Output "$(Get-TimeStamp) Targeting DC: $Server" | Tee-Object -FilePath $logFilePath -Append
        }

        Write-Output "$(Get-TimeStamp) Querying AD for computer objects (Filter: $Filter, IncludeDisabled: $IncludeDisabled)..." | Tee-Object -FilePath $logFilePath -Append

        $computers = Get-ADComputer @adParams

        if (-not $IncludeDisabled) {
            $beforeCount = ($computers | Measure-Object).Count
            $computers = $computers | Where-Object { $_.Enabled -eq $true }
            $afterCount = ($computers | Measure-Object).Count
            Write-Output "$(Get-TimeStamp) Filtered out $($beforeCount - $afterCount) disabled accounts" | Tee-Object -FilePath $logFilePath -Append
        }

        $totalCount = ($computers | Measure-Object).Count
        Write-Output "$(Get-TimeStamp) Retrieved $totalCount computer objects" | Tee-Object -FilePath $logFilePath -Append

        if ($totalCount -eq 0) {
            Write-Output "$(Get-TimeStamp) WARNING: No computer objects found - report will be empty" | Tee-Object -FilePath $logFilePath -Append
        }

        # --- Transform results ---
        $now = Get-Date
        $staleThreshold = $now.AddDays(-$StaleDays)

        $report = $computers | ForEach-Object {
            # Extract OU from DistinguishedName by removing the CN=ComputerName, prefix
            $dn = $_.DistinguishedName
            $ou = if ($dn -match ',(.+)$') { $Matches[1] } else { $dn }

            # Resolve ManagedBy DN to a friendly name
            $managedByName = ""
            if ($_.ManagedBy) {
                try {
                    $managedByName = (Get-ADObject $_.ManagedBy -Properties DisplayName -ErrorAction SilentlyContinue).DisplayName
                    if (-not $managedByName) { $managedByName = $_.ManagedBy }
                } catch {
                    $managedByName = $_.ManagedBy
                }
            }

            # Calculate days since last logon
            $daysSinceLogon = if ($_.LastLogonDate) {
                [math]::Round(($now - $_.LastLogonDate).TotalDays, 1)
            } else { "Never" }

            # Calculate days since password last set
            $daysSincePassword = if ($_.PasswordLastSet) {
                [math]::Round(($now - $_.PasswordLastSet).TotalDays, 1)
            } else { "Never" }

            # Stale determination
            $isStale = if (-not $_.LastLogonDate) {
                "NoLogonRecorded"
            } elseif ($_.LastLogonDate -lt $staleThreshold) {
                "Stale"
            } else {
                "Active"
            }

            # Detect if computer has SPN entries suggesting it's a server role
            $spnHint = ""
            if ($_.ServicePrincipalNames) {
                $spns = $_.ServicePrincipalNames -join ","
                $roles = @()
                if ($spns -match 'MSSQL')           { $roles += 'SQL' }
                if ($spns -match 'exchangeMDB|SMTP') { $roles += 'Exchange' }
                if ($spns -match 'HTTP/')            { $roles += 'Web/IIS' }
                if ($spns -match 'GC/')              { $roles += 'GC' }
                if ($spns -match 'ldap/')            { $roles += 'DC' }
                if ($spns -match 'DNS/')             { $roles += 'DNS' }
                if ($spns -match 'FTP/')             { $roles += 'FTP' }
                if ($roles.Count -gt 0) { $spnHint = $roles -join '; ' }
            }

            [PSCustomObject]@{
                Name                       = $_.Name
                DNSHostName                = $_.DNSHostName
                Enabled                    = $_.Enabled
                OU                         = $ou
                OperatingSystem            = $_.OperatingSystem
                OperatingSystemVersion     = $_.OperatingSystemVersion
                OperatingSystemServicePack = $_.OperatingSystemServicePack
                LastLogonDate              = $_.LastLogonDate
                PasswordLastSet            = $_.PasswordLastSet
                WhenCreated                = $_.WhenCreated
                WhenChanged                = $_.WhenChanged
                DaysSinceLastLogon         = $daysSinceLogon
                DaysSincePasswordSet       = $daysSincePassword
                IPv4Address                = $_.IPv4Address
                Description                = $_.Description
                ManagedBy                  = $managedByName
                DetectedRoles              = $spnHint
                IsStale                    = $isStale
                DistinguishedName          = $_.DistinguishedName
            }
        } | Sort-Object -Property OperatingSystem, Name

        # --- Summary statistics ---
        Write-Output "" | Tee-Object -FilePath $logFilePath -Append
        Write-Output "$(Get-TimeStamp) === Inventory Summary ===" | Tee-Object -FilePath $logFilePath -Append
        Write-Output "$(Get-TimeStamp) Total computer objects:  $totalCount" | Tee-Object -FilePath $logFilePath -Append

        $enabledCount = ($report | Where-Object { $_.Enabled -eq $true } | Measure-Object).Count
        $disabledCount = ($report | Where-Object { $_.Enabled -eq $false } | Measure-Object).Count
        Write-Output "$(Get-TimeStamp) Enabled:                $enabledCount" | Tee-Object -FilePath $logFilePath -Append
        Write-Output "$(Get-TimeStamp) Disabled:               $disabledCount" | Tee-Object -FilePath $logFilePath -Append

        $staleCount = ($report | Where-Object { $_.IsStale -eq 'Stale' } | Measure-Object).Count
        $noLogonCount = ($report | Where-Object { $_.IsStale -eq 'NoLogonRecorded' } | Measure-Object).Count
        Write-Output "$(Get-TimeStamp) Stale (>$StaleDays days): $staleCount" | Tee-Object -FilePath $logFilePath -Append
        Write-Output "$(Get-TimeStamp) No logon recorded:      $noLogonCount" | Tee-Object -FilePath $logFilePath -Append

        # --- OS breakdown ---
        Write-Output "" | Tee-Object -FilePath $logFilePath -Append
        Write-Output "$(Get-TimeStamp) --- OS Distribution ---" | Tee-Object -FilePath $logFilePath -Append
        $osGroups = $report | Group-Object -Property OperatingSystem | Sort-Object -Property Count -Descending
        foreach ($os in $osGroups) {
            $osName = if ($os.Name) { $os.Name } else { "(Not Set)" }
            Write-Output "$(Get-TimeStamp)   $osName : $($os.Count)" | Tee-Object -FilePath $logFilePath -Append
        }

        # --- OU breakdown (top 15) ---
        Write-Output "" | Tee-Object -FilePath $logFilePath -Append
        Write-Output "$(Get-TimeStamp) --- Top OUs by Computer Count ---" | Tee-Object -FilePath $logFilePath -Append
        $ouGroups = $report | Group-Object -Property OU | Sort-Object -Property Count -Descending | Select-Object -First 15
        foreach ($ouGroup in $ouGroups) {
            Write-Output "$(Get-TimeStamp)   $($ouGroup.Name) : $($ouGroup.Count)" | Tee-Object -FilePath $logFilePath -Append
        }

        # --- Export CSV ---
        if (!(Test-Path -PathType Container -Path $OutputPath)) {
            New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
        }
        $csvFileName = "ADComputerInventory_${domainName}_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $csvFilePath = Join-Path $OutputPath $csvFileName

        $report | Export-Csv -Path $csvFilePath -NoTypeInformation -Encoding $Encoding -ErrorAction Stop
        Write-Output "" | Tee-Object -FilePath $logFilePath -Append
        Write-Output "$(Get-TimeStamp) Report exported to: $csvFilePath" | Tee-Object -FilePath $logFilePath -Append
        Write-Output "$(Get-TimeStamp) Report contains $totalCount rows" | Tee-Object -FilePath $logFilePath -Append

        $MyExitStatus = 0

    } catch {
        Write-Output "$(Get-TimeStamp) ERROR: $($_.Exception.Message)" | Tee-Object -FilePath $logFilePath -Append
        Write-Output "$(Get-TimeStamp) Stack trace: $($_.ScriptStackTrace)" | Tee-Object -FilePath $logFilePath -Append
        if ($_.Exception.Message -match "Unable to find a default server") {
            Write-Output "$(Get-TimeStamp) HINT: This machine may not be domain-joined or cannot reach a domain controller." | Tee-Object -FilePath $logFilePath -Append
            Write-Output "$(Get-TimeStamp) HINT: Try specifying -Server 'dc01.contoso.com' to target a specific DC." | Tee-Object -FilePath $logFilePath -Append
        }
        if ($_.Exception.Message -match "is not recognized as the name of a cmdlet") {
            Write-Output "$(Get-TimeStamp) HINT: Install RSAT AD tools: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" | Tee-Object -FilePath $logFilePath -Append
            Write-Output "$(Get-TimeStamp) Ref: https://learn.microsoft.com/en-us/windows-server/remote/remote-server-administration-tools" | Tee-Object -FilePath $logFilePath -Append
        }
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
