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
# FindFailedRdwebLogin.ps1 - By Bitpusher/The Digital Fox
# v1.8 last updated 2026-04-19
# Search through the IIS log files and find IPs with failed logins
# going back specified number of hours, then list all IPs
# associated with more than specified threshold of failed logins.
#
# Function for creating Windows firewall rule based on this list is
# included - set "blockips" to 1 to automatically create/update
# firewall rule blocking identified IP addresses. Create a
# scheduled task which runs this script regularly to automate
# blocking of brute-forcing IP addresses.
#
# One-liner for searching through Windows event logs for failed
# logins also included - run on DC and move resulting blockIP.txt
# file to RDP server in order to use firewall rule creation
# command.
#
# Adjust parameters threshold, hoursago, output, and whitelist as appropriate.
#
# Usage:
# powershell -executionpolicy bypass -f .\FindFailedRdwebLogin.ps1 -threshold 100 -hoursago 24 -output "C:\temp" -whitelist "1.1.1.1","8.8.8.8" -blockips 1
#
# Use simplified and minified one-liner versions at the bottom to easily
# copy/paste into console of remote system (remote tools don't generally handle
# input with line breaks well).
#
#comp #ad #security #incident #script #rdweb #rds #gateway #terminalservices #password #reset #powershell #brute #force #firewall #rdp #mstsc

#Requires -Version 5.1

param(
    [int]$threshold = 5, # Threshold of number of failed attempts found within a single log file to include IP in block list.
    [int]$hoursago = 72, # Hours ago to search IIS log files.
    [string]$output = "c:\temp", # Report & blocklist output folder.
    [string[]]$whitelist = @("1.1.1.1", "8.8.8.8"), # Whitelist of public IP addresses to never include in blocklist (with placeholder values).
    [int]$blockips = 0, # Do not create/update firewall rule by default.
    [int]$debug = 0, # Do not show progress for every IP address by default.
    [string]$FirewallRuleName = "BlockRDPandRDWEBBruteForce",  # Name of the firewall rule to create/update
    [string]$scriptName = "FindFailedRdwebLogin",
    [string]$Priority = "Normal",
    [int]$RandMax = 5,
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

    New-Item -ItemType Directory -Force -Path $output | Out-Null


    Write-Output "Search in IIS logs for public IP addresses with failed sign-in count greater than threshold of $threshold which occurred in the past $hoursago hours starting..."
    Import-Module WebAdministration
    $outputCSV = "$($output)\$($env:computername)-RdsFailedSignInIps-$($threshold)-or-more-in-past-$($hoursago)-hours-from-$($(Get-Date).ToString('yyyyMMddHHmm')).csv"
    "IPAddress,Count" | out-file $outputCSV 

    foreach($WebSite in $(get-website)) {
        $logFolderPath = "$($Website.logFile.directory)\w3svc$($website.id)".replace("%SystemDrive%",$env:SystemDrive)
        Write-Output "$($WebSite.name) [$logFolderPath]"

        # foreach($WebSite in $(get-website)) { $logFile="$($Website.logFile.directory)\w3svc$($website.id)".replace("%SystemDrive%",$env:SystemDrive) ; $WebSite | FL ; $Website.logFile | fl ; Write-Output "$($WebSite.name) - $logfile" } 

        # IIS log files usually located at C:\inetpub\logs\LogFiles\W3SVC1

        # Set the time range to filter log entries (if you grab only the latest log file it will only include entries from current day)
        $startTime = (Get-Date).AddHours(-$hoursago) # Past three days by default

        # Get the latest log file in the folder
        # $currentLogFile = Get-ChildItem -Path $logFolderPath -Filter "*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        $logFileList = Get-ChildItem -Path $logFolderPath -Filter "*.log" -Recurse -File | Where-Object { $_.LastWriteTime -ge $startTime }
        Write-Output "Found $($logFileList.count) log files within time frame specified. Parsing..." 

        $LogFile = @()
        foreach($currentLogFile in $logFileList) {
            Write-Output "Loading content of log file $($currentLogFile.FullName)"
            $LogFile = $LogFile + $(Get-Content -Path $currentLogFile.FullName)
            Write-Output "Total number of lines read: $($LogFile.count)"
        }

        # Search for lines with HTTP code 200 and 'POST' method
        $IpTable = @{}
        $LogFile | Where-Object {
            # Only process lines with HTTP code 200 and 'POST' method that occurred after specified start time
            $_ -match 'POST' -and $_ -match ' 200 \d+ \d+ \d+$' -and [DateTime]::ParseExact($_.Substring(0, 19), 'yyyy-MM-dd HH:mm:ss', $null) -ge $startTime
        } | ForEach-Object {
            $line = $_
            # $line | out-file "$($output)\logLines.txt" -append
            # $IpAddress = ($line -split ' ')[-1]
            # $line = $line.split(' - ')[2] ; $IpAddress = $($line -split ' ')[0]
            if ($line) {
                $regexIP = '\d+\.\d+\.\d+\.\d+'
                $ipMatches = $line | Select-String -pattern $regexIP -allmatches
                $IpAddress = $ipMatches.matches[1].value
            }
            # IP Filtering
            $regexPattern = "^(?:10|127|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\..*"
            # Check if IP is private or public
            if (!$IpAddress) {
                if ($debug -eq 1) {Write-Output "Skipping blank IP value"}
            } elseif ($IpAddress -match $regexPattern) {
                # Debugging output
                if ($debug -eq 1) {Write-Output "Skipping private address $IpAddress"}
            } else {
                # Count the occurrences of the IP address
                if ($IpTable.ContainsKey($IpAddress)) {
                    $IpTable[$IpAddress]++
                } else {
                    $IpTable.add($IpAddress, 1)
                }
            }
        }

        # Save IPs that occur more than a defined number of times - default threshold is 5
        $ipcount = 0
        $IpTable.getenumerator() | Sort-Object -Property Value -Descending | Where-Object { $_.value -gt $threshold } | ForEach-Object {
            $IpAddress = $_.name
            $count = $_.value
            $ipcount = $ipcount + 1
            # Debugging output
            if ($debug -eq 1) {Write-Output "Adding $IpAddress with failed sign-in count of $count"}
            "$IpAddress,$count" | out-file $outputCSV -append
            $IpAddress | out-file "$($output)\blockIP.txt" -append
        }

        if ($ipcount) {
            Write-Output "Found $ipcount public IP addresses with failed sign-in count greater than threshold of $threshold."
        }
        Write-Output "See $outputCSV for full report."
    }



    # Create/update firewall rule to block the IP list generated above:
    if ($blockips -eq 1 -and $ipcount) {
        Write-Output "Firewall rule creation/update starting..."
        $newIps = Get-Content "$($output)\blockIP.txt" | Sort-Object | Select-Object -Unique
        $newIps = Compare-Object -ReferenceObject ($whitelist) -DifferenceObject ($newIps) -IncludeEqual | Where-Object { $_.SideIndicator -eq '=>' } | Select-Object -ExpandProperty InputObject | Sort-Object
        $rule = (Get-NetFirewallRule | Where-Object { $_.DisplayName -eq $FirewallRuleName } | Get-NetFirewallAddressFilter).RemoteAddress
        if ($null -ne $rule -and $null -ne $newIps) {
            $new = Compare-Object -ReferenceObject ($rule) -DifferenceObject ($newIps) -IncludeEqual | Where-Object { $_.SideIndicator -eq '=>' } | Select-Object -ExpandProperty InputObject | Sort-Object
            $updated = Compare-Object -ReferenceObject ($rule) -DifferenceObject ($newIps) -IncludeEqual | Select-Object -ExpandProperty InputObject | Sort-Object
            $updated = Compare-Object -ReferenceObject ($whitelist) -DifferenceObject ($updated) -IncludeEqual | Where-Object { $_.SideIndicator -eq '=>' } | Select-Object -ExpandProperty InputObject | Sort-Object
            Set-NetFirewallRule -DisplayName $FirewallRuleName -Action Block -Direction Inbound -Protocol TCP -LocalPort 443,3389 -Profile Any -Enabled True -RemoteAddress $updated
            Set-NetFirewallRule -DisplayName "$($FirewallRuleName)UDP" -Action Block -Direction Inbound -Protocol UDP -LocalPort 443,3389 -Profile Any -Enabled True -RemoteAddress $updated
            Write-Output "Using raw list of list of $($newIps.Count) addresses, firewall rule $FirewallRuleName has been updated to block $($new.Count) additional IP addresses - Now blocking $($updated.Count) addresses in total."
        } elseif ($null -ne $newIps) {
            $newIps = Compare-Object -ReferenceObject ($whitelist) -DifferenceObject ($newIps) -IncludeEqual | Where-Object { $_.SideIndicator -eq '=>' } | Select-Object -ExpandProperty InputObject | Sort-Object
            New-NetFirewallRule -DisplayName "$FirewallRuleName" -Action Block -Direction Inbound -Protocol TCP -LocalPort 443,3389 -Profile Any -Enabled True -RemoteAddress $newIps
            New-NetFirewallRule -DisplayName "$($FirewallRuleName)UDP" -Action Block -Direction Inbound -Protocol UDP -LocalPort 443,3389 -Profile Any -Enabled True -RemoteAddress $newIps
            Write-Output "Created firewall rule $FirewallRuleName from IP address list to block $($newIps.Count) IP addresses."
        } elseif ($null -ne $rule) {
            Write-Output "No new IPs found to update firewall rule. Rule $FirewallRuleName is blocking $($rule.Count) IP addresses."
        } else {
            Write-Output "No IP address lists found. Firewall rule not created."
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
            $atts = @($logFilePath) + $(if (Test-Path $outputCSV) { $outputCSV })
            Send-MailMessage -SmtpServer "$emailServer" -Port $emailPort -From "$emailFrom" -To "$emailTo" -Subject "$scriptName - $ComputerName - $ipcount IPs blocked" -Body "$logFilePath" -UseSsl -Credential (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$emailUsername", (ConvertTo-SecureString -String "$emailPassword" -AsPlainText -Force)) -Attachments $atts
        }
        if (($shareLocation -ne "") -and ($shareUsername -ne "") -and ($sharePassword -ne "")) {
            [securestring]$secStringPassword = ConvertTo-SecureString $sharePassword -AsPlainText -Force
            [pscredential]$shareCred = New-Object System.Management.Automation.PSCredential ($shareUsername, $secStringPassword)
            New-PSDrive -Name LogStore -PSProvider FileSystem -Root "$shareLocation" -Description "Log Store" -Credential $shareCred
            Copy-Item -LiteralPath "$logFilePath" -Destination "LogStore:\" -Force -ErrorAction Continue
            if (Test-Path $outputCSV) { Copy-Item -LiteralPath "$outputCSV" -Destination "LogStore:\" -Force -ErrorAction Continue }
            Remove-PSDrive -Name LogStore
        } elseif ($shareLocation -ne "") {
            Copy-Item -LiteralPath $LogFilePath -Destination $ShareLocation  -Force -ErrorAction Continue
        }
    }
    Set-PSDebug -Trace 0
    exit $MyExitStatus
    #endregion finalization
}



# One-liner version to generate report & IP blocklist (for ease of remote execution):
$ListFailedRDSWebSigninsFromPastThreeDaysOneLine = @'
Import-Module WebAdministration ; $threshold = 5 ; $hoursago = 72 ; $output = "c:\temp" ; $debug = 0 ; Write-Output "Search in IIS logs for public IP addresses with failed sign-in count greater than threshold of $threshold which occurred in the past $hoursago hours starting..." ; $outputCSV = "$($output)\$($env:computername)-RdsFailedSignInIps-$($threshold)-or-more-in-past-$($hoursago)-hours-from-$($(Get-Date).ToString('yyyyMMddHHmm')).csv" ; "IPAddress,Count" | out-file $outputCSV ; foreach($WebSite in $(get-website)) { $logFolderPath = "$($Website.logFile.directory)\w3svc$($website.id)".replace("%SystemDrive%",$env:SystemDrive) ; Write-Output "$($WebSite.name) [$logFolderPath]" ; $startTime = (Get-Date).AddHours(-$hoursago) ; $logFileList = Get-ChildItem -Path $logFolderPath -Filter "*.log" -Recurse -File | Where-Object { $_.LastWriteTime -ge $startTime } ; Write-Output "Found $($logFileList.count) log files within time frame specified. Parsing..." ; $LogFile = @() ; foreach($currentLogFile in $logFileList) { Write-Output "Loading content of log file $($currentLogFile.FullName)" ; $LogFile = $LogFile + $(Get-Content -Path $currentLogFile.FullName) ; Write-Output "Total number of lines read: $($LogFile.count)" } ; $IpTable = @{} ; $LogFile | Where-Object { $_ -match 'POST' -and $_ -match ' 200 \d+ \d+ \d+$' -and [DateTime]::ParseExact($_.Substring(0, 19), 'yyyy-MM-dd HH:mm:ss', $null) -ge $startTime } | ForEach-Object { $line = $_ ; if ($line) { $regexIP = '\d+\.\d+\.\d+\.\d+' ; $ipMatches = $line | Select-String -pattern $regexIP -allmatches ; $IpAddress = $ipMatches.matches[1].value } ; $regexPattern = "^(?:10|127|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\..*" ; if (!$IpAddress) { if ($debug -eq 1) {Write-Output "Skipping blank IP value"} } elseif ($IpAddress -match $regexPattern) { if ($debug -eq 1) {Write-Output "Skipping private address $IpAddress"} } else { if ($IpTable.ContainsKey($IpAddress)) { $IpTable[$IpAddress]++ } else { $IpTable.add($IpAddress, 1) } } } ; $ipcount = 0 ; $IpTable.getenumerator() | Sort-Object -Property Value -Descending | Where-Object { $_.value -gt $threshold } | ForEach-Object { $IpAddress = $_.name ; $count = $_.value ; $ipcount = $ipcount + 1 ; if ($debug -eq 1) {Write-Output "Adding $IpAddress with failed sign-in count of $count"} ; "$IpAddress,$count" | out-file $outputCSV -append ; $IpAddress | out-file "C:\Temp\blockIP.txt" -append } ; if ($ipcount) { Write-Output "Found $ipcount public IP addresses with failed sign-in count greater than threshold of $threshold." } Write-Output "See $outputCSV for full report." }
'@


# One-liner version to generate report & IP blocklist from Windows Event logs. This includes direct RDP to 3389. Run on the DC, and blockIP.txt will need to be manually transferred to RDP server to use:
$ListFaildRDPSigninsFromPastThreeDaysOneLine = @'
$threshold = 5 ; $hoursago = 72 ; $output = "c:\temp" ; Write-Output "Search in Event Logs for public IP addresses with failed sign-in count greater than threshold of $threshold which occurred in the past $hoursago hours starting..." ; $outputCSV = "$($output)\$($env:computername)-RdpFailedSignInIps-$($threshold)-or-more-in-past-$($hoursago)-hours-from-$($(Get-Date).ToString('yyyyMMddHHmm')).csv" ; "IPAddress,Count" | out-file $outputCSV ; $FailedRDP = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$(Get-Date).AddHours(-$hoursago); Id=4625} | Select-Object TimeCreated, ID, LogName, ProviderName, LevelDisplayName, @{ n='Message';e={$_.Message -replace '\s+', " "} }, @{ n="logontype";e={(($_ | select -expand properties).value[8])} }, @{ n="accountname";e={($_ | select -expand properties).value[5]} }, @{ n='SourceIP';e={$($_.Properties | Where-Object { $_.Value -match '(\d{1,3}\.){3}\d{1,3}' }).Value} } ; $IpTable = @{} ; $FailedRDP | ForEach-Object { $line = $_ ; if ($line) { $regexIP = '\d+\.\d+\.\d+\.\d+' ; $ipMatches = $line | Select-String -pattern $regexIP -allmatches ; $IpAddress = $line.SourceIP } ; $regexPattern = "^(?:10|127|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\..*" ; if (!$IpAddress) { if ($debug -eq 1) {Write-Output "Skipping blank IP value"} } elseif ($IpAddress -match $regexPattern) { if ($debug -eq 1) {Write-Output "Skipping private address $IpAddress"} } else { if ($IpTable.ContainsKey($IpAddress)) { $IpTable[$IpAddress]++ } else { $IpTable.add($IpAddress, 1) } } } ; $IpTable = $IpTable.GetEnumerator() | Sort-Object Value -Descending ; $IpTable.GetEnumerator() | Where-Object { $_.Value -ge $threshold } | Select-Object @{ n="IPAddress";e={$_.Name} }, @{ n="Count";e={$_.Value} } | Export-Csv $outputCSV -nti ; $blockIP = $IpTable.GetEnumerator() | Where-Object { $_.Value -ge $threshold } | Select-Object @{ n="IPAddress";e={$_.Name} } | Select-Object -ExpandProperty IPAddress ; $blockIP | out-file "$($output)\blockIP.txt" -append ; if ($blockIP) { Write-Output "Found $($blockIP.count) public IP addresses with failed sign-in count greater than threshold of $threshold." } ; Write-Output "See $outputCSV for full report."
'@
# SourceIP alternative selection expression - {($_ | select -expand properties).value[19]}



# One-liner version to create/update firewall rule (for ease of remote execution):
$BlockIpAddressesFromListOneLine = @'
Write-Output "Firewall rule creation/update starting..." ; $whitelist = "1.1.1.1", "8.8.8.8" ; $newIps = Get-Content "C:\Temp\blockIP.txt" | Sort-Object | Select-Object -Unique ; $rule = (Get-NetFirewallRule | Where-Object { $_.DisplayName -eq 'BlockRDPandRDWEBBruteForce' } | Get-NetFirewallAddressFilter).RemoteAddress ; if ($null -ne $rule -and $null -ne $newIps) { $new = Compare-Object -ReferenceObject ($rule) -DifferenceObject ($newIps) -IncludeEqual | Where-Object { $_.SideIndicator -eq '=>' } | Select-Object -ExpandProperty InputObject | Sort-Object ; $updated = Compare-Object -ReferenceObject ($rule) -DifferenceObject ($newIps) -IncludeEqual | Select-Object -ExpandProperty InputObject | Sort-Object ; $updated = Compare-Object -ReferenceObject ($whitelist) -DifferenceObject ($updated) -IncludeEqual | Where-Object { $_.SideIndicator -eq '=>' } | Select-Object -ExpandProperty InputObject | Sort-Object ; Set-NetFirewallRule -DisplayName 'BlockRDPandRDWEBBruteForce' -Action Block -Direction Inbound -Protocol TCP -LocalPort 443,3389 -Profile Any -Enabled True -RemoteAddress $updated ; Set-NetFirewallRule -DisplayName 'BlockRDPandRDWEBBruteForceUDP' -Action Block -Direction Inbound -Protocol UDP -LocalPort 443,3389 -Profile Any -Enabled True -RemoteAddress $updated ; Write-Output "Using raw list of list of $($newIps.Count) addresses, firewall rule 'BlockRDPandRDWEBBruteForce' has been updated to block $($new.Count) additional IP addresses - Now blocking $($updated.Count) addresses in total." } elseif ($null -ne $newIps) { $newIps = Compare-Object -ReferenceObject ($whitelist) -DifferenceObject ($newIps) -IncludeEqual | Where-Object { $_.SideIndicator -eq '=>' } | Select-Object -ExpandProperty InputObject | Sort-Object ; New-NetFirewallRule -DisplayName "BlockRDPandRDWEBBruteForce" -Action Block -Direction Inbound -Protocol TCP -LocalPort 443,3389 -Profile Any -Enabled True -RemoteAddress $newIps ; New-NetFirewallRule -DisplayName "BlockRDPandRDWEBBruteForceUDP" -Action Block -Direction Inbound -Protocol UDP -LocalPort 443,3389 -Profile Any -Enabled True -RemoteAddress $newIps ; Write-Output "Created firewall rule 'BlockRDPandRDWEBBruteForce' from IP address list to block $($newIps.Count) IP addresses." } elseif ($null -ne $rule) { Write-Output "No new IPs found to update firewall rule. Rule 'BlockRDPandRDWEBBruteForce' is blocking $($rule.Count) IP addresses." } else { Write-Output "No IP address lists found. Firewall rule not created." }
'@

# One-liner version to create/update firewall rule blocking all protocols and ports:
$BlockIpAddressesFromListOneLine = @'
Write-Output "Firewall rule creation/update starting..." ; $whitelist = "1.1.1.1", "8.8.8.8" ; $newIps = Get-Content "C:\Temp\blockIP.txt" | Sort-Object | Select-Object -Unique ; $rule = (Get-NetFirewallRule | Where-Object { $_.DisplayName -eq 'BlockRDPandRDWEBBruteForce' } | Get-NetFirewallAddressFilter).RemoteAddress ; if ($null -ne $rule -and $null -ne $newIps) { $new = Compare-Object -ReferenceObject ($rule) -DifferenceObject ($newIps) -IncludeEqual | Where-Object { $_.SideIndicator -eq '=>' } | Select-Object -ExpandProperty InputObject | Sort-Object ; $updated = Compare-Object -ReferenceObject ($rule) -DifferenceObject ($newIps) -IncludeEqual | Select-Object -ExpandProperty InputObject | Sort-Object ; $updated = Compare-Object -ReferenceObject ($whitelist) -DifferenceObject ($updated) -IncludeEqual | Where-Object { $_.SideIndicator -eq '=>' } | Select-Object -ExpandProperty InputObject | Sort-Object ; Set-NetFirewallRule -DisplayName 'BlockRDPandRDWEBBruteForce' -Action Block -Direction Inbound -Protocol Any -Profile Any -Enabled True -RemoteAddress $updated ; Write-Output "Using raw list of list of $($newIps.Count) addresses, firewall rule 'BlockRDPandRDWEBBruteForce' has been updated to block $($new.Count) additional IP addresses - Now blocking $($updated.Count) addresses in total." } elseif ($null -ne $newIps) { $newIps = Compare-Object -ReferenceObject ($whitelist) -DifferenceObject ($newIps) -IncludeEqual | Where-Object { $_.SideIndicator -eq '=>' } | Select-Object -ExpandProperty InputObject | Sort-Object ; New-NetFirewallRule -DisplayName "BlockRDPandRDWEBBruteForce" -Action Block -Direction Inbound -Protocol Any -Profile Any -Enabled True -RemoteAddress $newIps ; Write-Output "Created firewall rule 'BlockRDPandRDWEBBruteForce' from IP address list to block $($newIps.Count) IP addresses." } elseif ($null -ne $rule) { Write-Output "No new IPs found to update firewall rule. Rule 'BlockRDPandRDWEBBruteForce' is blocking $($rule.Count) IP addresses." } else { Write-Output "No IP address lists found. Firewall rule not created." }
'@

# Delete specific rules, reset rules to Windows defaults:
$BlockIpAddressesFromListOneLine = @'
Get-NetFirewallRule | Where-Object { $_.DisplayName -eq 'BlockRDPandRDWEBBruteForce' } | Remove-NetFirewallRule ; Get-NetFirewallRule | Where-Object { $_.DisplayName -eq 'BlockRDPandRDWEBBruteForceUDP' } | Remove-NetFirewallRule
netsh advfirewall reset
'@




# Additional useful report generation snippets:
$SignInReportsFromEventLog = @'
$LogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
$Results = @()
$Events = Get-WinEvent -LogName $LogName
foreach ($Event in $Events) {
    $EventXml = [xml]$Event.ToXML()
    $ResultHash = @{
        Time        = $Event.TimeCreated.ToString()
        'Event ID'  = $Event.Id
        'Desc'      = ($Event.Message -split "`n")[0]
        Username    = $EventXml.Event.UserData.EventXML.User
        'Source IP' = $EventXml.Event.UserData.EventXML.Address
        'Details'   = $Event.Message
    }
    $Results += (New-Object PSObject -Property $ResultHash)
}
$Results | Export-Csv 'C:\Successful_Remote_Desktop_Sign-ins.csv'

Get-Eventlog -LogName Security | where {$_.EventId -eq "4624"} | select-object @{Name="User";Expression={$_.ReplacementStrings[5]}} | sort-object User -unique | Export-Csv 'C:\Successful_Sign-ins.csv'

Get-Eventlog -LogName Security | where {$_.EventId -eq "4625"} | select-object @{Name="User";Expression={$_.ReplacementStrings[5]}} | sort-object User -unique | Export-Csv 'C:\Failed_Sign-ins.csv'

Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4625
    StartTime=(Get-Date).AddDays(-1)
} | Select-Object TimeCreated, Id, Message | Export-Csv 'C:\Failed_Sign-ins.csv'
'@

