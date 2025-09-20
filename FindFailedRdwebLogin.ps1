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
# v1.6 last updated 2025-09-19
# Search through the IIS log files and find accounts with
# a failed login, then list all IPs associated with more than
# five failed logins.
#
# Function for creating a firewall rule based on this list is
# included - set "blockips" to 1 to automatically create/update
# a firewall rule blocking identified IP addresses. Create a
# scheduled task which runs this script regularly to automate
# blocking of brute-forcing IP addresses.
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
#comp #ad #security #incident #script #rdweb #rds #gateway #terminalservices #password #reset #powershell #brute #force #firewall

#Requires -Version 5.1

param(
    [int]$threshold = 5, # Threshold of number of failed attempts found within a single log file to include IP in block list.
    [int]$hoursago = 72, # Hours ago to search IIS log files.
    [string]$output = "c:\temp", # Report & blocklist output folder.
    [string[]]$whitelist = "1.1.1.1", "8.8.8.8", # Whitelist of public IP addresses to never include in blocklist (with placeholder values).
    [int]$blockips = 0 # Do not create/update firewall rule by default.
    [int]$debug = 0 # Do not show progress for every IP address by default.
)

Write-Output "Search for public IP addresses with failed sign-in count greater than threshold of $threshold which occurred in the past $hoursago hours starting..."
Import-Module WebAdministration
$outputCSV = "$($output)\$($env:computername)-RdsFailedSignInIps-$($(Get-Date).ToString('yyyyMMddHHmm')).csv"
"IPAddress,Count" | out-file $outputCSV 

foreach($WebSite in $(get-website)) {
    $logFolderPath = "$($Website.logFile.directory)\w3svc$($website.id)".replace("%SystemDrive%",$env:SystemDrive)
    Write-Output "$($WebSite.name) [$logFolderPath]"

    # foreach($WebSite in $(get-website)) { $logFile="$($Website.logFile.directory)\w3svc$($website.id)".replace("%SystemDrive%",$env:SystemDrive) ; $WebSite | FL ; $Website.logFile | fl ; Write-Output "$($WebSite.name) - $logfile" } 

    # IIS log files usually located at C:\inetpub\logs\LogFiles\W3SVC1

    # Set the time range to filter log entries (when grabbing only latest log file it will only include entries from current day)
    $startTime = (Get-Date).AddHours(-$hoursago) # Past three days by default

    # Get the latest log file in the folder
    $currentLogFile = Get-ChildItem -Path $logFolderPath -Filter "*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $logFileList = Get-ChildItem -Path $logFolderPath -Filter "*.log" -Recurse -File | Where-Object { $_.LastWriteTime -ge $startTime }
    Write-Output "Found $($logFileList.count) log files within time frame specified. Parsing..." 

    foreach($currentLogFile in $logFileList) {
        # Search for lines with HTTP code 200 and 'POST' method in the latest log file
        $IpTable = @{}
        Write-Output "Loading content of log file $($currentLogFile.FullName)"
        $LogFile = Get-Content -Path $currentLogFile.FullName
        Write-Output "Log file has $($LogFile.count) lines"
        $LogFile | Where-Object {
            # Only process lines with HTTP code 200 and 'POST' method that occurred within the last 60 minutes
            $_ -match 'POST' -and $_ -match ' 200 \d+ \d+ \d+$' -and [DateTime]::ParseExact($_.Substring(0, 19), 'yyyy-MM-dd HH:mm:ss', $null) -ge $startTime
        } | ForEach-Object {
            $line = $_
            # $line | out-file "$($output)\logLines.txt" -append
            # $IpAddress = ($line -split ' ')[-1]
            # $line = $line.split(' - ')[2] ; $IpAddress = $($line -split ' ')[0]
            if ($line) {
                $regexIP = '\d+\.\d+\.\d+\.\d+'
                $matches = $line | Select-String -pattern $regexIP -allmatches
                $IpAddress = $matches.matches[1].value
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
            Write-Output "Found $ipcount public IP addresses with failed sign-in count greater than threshold of $threshold in $currentLogFile."
        }
    }
    Write-Output "See $outputCSV for full report."
}

# One-liner version to generate report & IP blocklist (for ease of remote execution):
$ListFailedRDSWebSigninsFromPastThreeDaysOneLine = @'
Write-Output "Search for public IP addresses with failed sign-in count greater than threshold of $threshold which occurred in the past $hoursago hours starting..." ; Import-Module WebAdministration ; $threshold = 5 ; $hoursago = 72 ; $debug = 0 ; $outputCSV = "c:\temp\$($env:computername)-RdsFailedSignInIps-$($(Get-Date).ToString('yyyyMMddHHmm')).csv" ; "IPAddress,Count" | out-file $outputCSV ; foreach($WebSite in $(get-website)) { $logFolderPath = "$($Website.logFile.directory)\w3svc$($website.id)".replace("%SystemDrive%",$env:SystemDrive) ; Write-Output "$($WebSite.name) [$logFolderPath]" ; $startTime = (Get-Date).AddHours(-$hoursago) ; $logFileList = Get-ChildItem -Path $logFolderPath -Filter "*.log" -Recurse -File | Where-Object { $_.LastWriteTime -ge $startTime } ; Write-Output "Found $($logFileList.count) log files within time frame specified. Parsing..." ; foreach($currentLogFile in $logFileList) { $IpTable = @{} ; Write-Output "Loading content of log file $($currentLogFile.FullName)" ; $LogFile = Get-Content -Path $currentLogFile.FullName ; Write-Output "Log file has $($LogFile.count) lines" ; $LogFile | Where-Object { $_ -match 'POST' -and $_ -match ' 200 \d+ \d+ \d+$' -and [DateTime]::ParseExact($_.Substring(0, 19), 'yyyy-MM-dd HH:mm:ss', $null) -ge $startTime } | ForEach-Object { $line = $_ ; if ($line) { $regexIP = '\d+\.\d+\.\d+\.\d+' ; $matches = $line | Select-String -pattern $regexIP -allmatches ; $IpAddress = $matches.matches[1].value } ; $regexPattern = "^(?:10|127|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\..*" ; if (!$IpAddress) { if ($debug -eq 1) {Write-Output "Skipping blank IP value"} } elseif ($IpAddress -match $regexPattern) { if ($debug -eq 1) {Write-Output "Skipping private address $IpAddress"} } else { if ($IpTable.ContainsKey($IpAddress)) { $IpTable[$IpAddress]++ } else { $IpTable.add($IpAddress, 1) } } } ; $ipcount = 0 ; $IpTable.getenumerator() | Sort-Object -Property Value -Descending | Where-Object { $_.value -gt $threshold } | ForEach-Object { $IpAddress = $_.name ; $count = $_.value ; $ipcount = $ipcount + 1 ; if ($debug -eq 1) {Write-Output "Adding $IpAddress with failed sign-in count of $count"} ; "$IpAddress,$count" | out-file $outputCSV -append ; $IpAddress | out-file "C:\Temp\blockIP.txt" -append } ; if ($ipcount) { Write-Output "Found $ipcount public IP addresses with failed sign-in count greater than threshold of $threshold in $currentLogFile." } } Write-Output "See $outputCSV for full report." }
'@


# Create/update firewall rule to block the IP list generated above:
if ($blockips -eq 1 -and $ipcount) {
    Write-Output "Firewall rule creation/update starting..."
    $newIps = Get-Content "$($output)\blockIP.txt" | Sort-Object | Select-Object -Unique
    $rule = (Get-NetFirewallRule | Where-Object { $_.DisplayName -eq 'BlockRDPandRDWEBBruteForce' } | Get-NetFirewallAddressFilter).RemoteAddress
    if ($null -ne $rule -and $null -ne $newIps) {
        $new = Compare-Object -ReferenceObject ($rule) -DifferenceObject ($newIps) -IncludeEqual | Where-Object { $_.SideIndicator -eq '=>' } | Select-Object -ExpandProperty InputObject | Sort-Object
        $updated = Compare-Object -ReferenceObject ($rule) -DifferenceObject ($newIps) -IncludeEqual | Select-Object -ExpandProperty InputObject | Sort-Object
        $updated = Compare-Object $updated $whitelist | Select-Object -ExpandProperty InputObject | Sort-Object
        Set-NetFirewallRule -DisplayName 'BlockRDPandRDWEBBruteForce' -Action Block -Direction Inbound -Protocol TCP -LocalPort 443,3389 -RemoteAddress $updated
        Write-Output "Using raw list of list of $($newIps.Count) addresses, firewall rule 'BlockRDPandRDWEBBruteForce' has been updated to block $($new.Count) additional IP addresses - Now blocking $($updated.Count) addresses in total."
    } elseif ($null -ne $newIps) {
        $newIps = Compare-Object $newIps $whitelist | Select-Object -ExpandProperty InputObject | Sort-Object
        New-NetFirewallRule -DisplayName "BlockRDPandRDWEBBruteForce" -Action Block -Direction Inbound -Protocol TCP -LocalPort 443,3389 -RemoteAddress $newIps
        Write-Output "Created firewall rule 'BlockRDPandRDWEBBruteForce' from IP address list to block $($newIps.Count) IP addresses."
    } elseif ($null -ne $rule) {
        Write-Output "No new IPs found to update firewall rule. Rule 'BlockRDPandRDWEBBruteForce' is blocking $($rule.Count) IP addresses."
    } else {
        Write-Output "No IP address lists found. Firewall rule not created."
    }
}


# One-liner version to create/update firewall rule (for ease of remote execution):
$BlockIpAddressesFromListOneLine = @'
Write-Output "Firewall rule creation/update starting..." ; $whitelist = "1.1.1.1", "8.8.8.8" ; $newIps = Get-Content "C:\Temp\blockIP.txt" | Sort-Object | Select-Object -Unique ; $rule = (Get-NetFirewallRule | Where-Object { $_.DisplayName -eq 'BlockRDPandRDWEBBruteForce' } | Get-NetFirewallAddressFilter).RemoteAddress ; if ($null -ne $rule -and $null -ne $newIps) { $new = Compare-Object -ReferenceObject ($rule) -DifferenceObject ($newIps) -IncludeEqual | Where-Object { $_.SideIndicator -eq '=>' } | Select-Object -ExpandProperty InputObject | Sort-Object ; $updated = Compare-Object -ReferenceObject ($rule) -DifferenceObject ($newIps) -IncludeEqual | Select-Object -ExpandProperty InputObject | Sort-Object ; $updated = Compare-Object $updated $whitelist | Select-Object -ExpandProperty InputObject | Sort-Object ; Set-NetFirewallRule -DisplayName 'BlockRDPandRDWEBBruteForce' -Action Block -Direction Inbound -Protocol TCP -LocalPort 443,3389 -RemoteAddress $updated ; Write-Output "Using raw list of list of $($newIps.Count) addresses, firewall rule 'BlockRDPandRDWEBBruteForce' has been updated to block $($new.Count) additional IP addresses - Now blocking $($updated.Count) addresses in total." } elseif ($null -ne $newIps) { $newIps = Compare-Object $newIps $whitelist | Select-Object -ExpandProperty InputObject | Sort-Object ; New-NetFirewallRule -DisplayName "BlockRDPandRDWEBBruteForce" -Action Block -Direction Inbound -Protocol TCP -LocalPort 443,3389 -RemoteAddress $newIps ; Write-Output "Created firewall rule 'BlockRDPandRDWEBBruteForce' from IP address list to block $($newIps.Count) IP addresses." } elseif ($null -ne $rule) { Write-Output "No new IPs found to update firewall rule. Rule 'BlockRDPandRDWEBBruteForce' is blocking $($rule.Count) IP addresses." } else { Write-Output "No IP address lists found. Firewall rule not created." }
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
'@

