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
# v1.5 last updated 2025-09-18
# Search through the IIS log files and find accounts with
# a failed login, then list all IPs associated with more than
# five failed logins.
#
# Function for creating a firewall rule based on this list is included at the bottom.
#
# Usage:
# powershell -executionpolicy bypass -f .\FindFailedRdwebLogin.ps1
#
# powershell -executionpolicy bypass -f .\FindFailedRdwebLogin.ps1
#
# Use with DropShim.bat to allow drag-and-drop processing of log file.
#
# Use simplified and minified one-liner versions at the bottom to easily
# copy/paste into console of remote system (remote tools don't generally handle
# input with line breaks well).
#
#comp #ad #security #incident #script #rdweb #rds #gateway #terminalservices #password #reset #powershell

#Requires -Version 5.1

param(
    [string[]]$inputFiles = @("IIS.log"),
    [string]$outputFile
)

# Enable debugging output
$debug = 1

# Set the path to the log folder
Import-Module WebAdministration

# Set the output location
$output = "c:\temp"
$outputCSV = "c:\temp\$($env:computername)-RdsFailedSignInIps-$($(Get-Date).ToString('yyyyMMddHHmm')).csv"
"IPAddress,Count" | out-file $outputCSV 

foreach($WebSite in $(get-website)) {
    $logFolderPath = "$($Website.logFile.directory)\w3svc$($website.id)".replace("%SystemDrive%",$env:SystemDrive)
    Write-Output "$($WebSite.name) [$logFolderPath]"

    # foreach($WebSite in $(get-website)) { $logFile="$($Website.logFile.directory)\w3svc$($website.id)".replace("%SystemDrive%",$env:SystemDrive) ; $WebSite | FL ; $Website.logFile | fl ; Write-Output "$($WebSite.name) - $logfile" } 

    # usually C:\inetpub\logs\LogFiles\W3SVC1


    # Set the time range to filter log entries (when grabbing only latest log file it will only include entries from current day)
    $startTime = (Get-Date).AddHours(-72) # Past three days

    # Get the latest log file in the folder
    $currentLogFile = Get-ChildItem -Path $logFolderPath -Filter "*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $logFileList = Get-ChildItem -Path $logFolderPath -Filter "*.log" -Recurse -File | Where-Object { $_.LastWriteTime -ge $startTime }

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
                if ($debug -eq 1) {Write-Output "Skipping $IpAddress"}
            } else {
                # Count the occurrences of the IP address
                if ($IpTable.ContainsKey($IpAddress)) {
                    $IpTable[$IpAddress]++
                } else {
                    $IpTable.add($IpAddress, 1)
                }
            }
        }

        # Save IPs that occur more than a defined number of times
        $IpTable.getenumerator() | Sort-Object -Property Value -Descending | Where-Object { $_.value -gt 5 } | ForEach-Object {
            $IpAddress = $_.name
            $count = $_.value
            # Debugging output
            if ($debug -eq 1) {Write-Output "Adding $IpAddress with count $count"}
            "$IpAddress,$count" | out-file $outputCSV -append
            $IpAddress | out-file "$($output)\blockIP.txt" -append
        }
    }
}



## One-liner version of the above:
$ListFailedRDSWebSigninsFromPastThreDays = @'
Import-Module WebAdministration ; $debug = 1 ; $outputCSV = "c:\temp\$($env:computername)-RdsFailedSignInIps-$($(Get-Date).ToString('yyyyMMddHHmm')).csv" ; "IPAddress,Count" | out-file $outputCSV ; foreach($WebSite in $(get-website)) { $logFolderPath = "$($Website.logFile.directory)\w3svc$($website.id)".replace("%SystemDrive%",$env:SystemDrive) ; Write-Output "$($WebSite.name) [$logFolderPath]" ; $startTime = (Get-Date).AddHours(-72) ; $logFileList = Get-ChildItem -Path $logFolderPath -Filter "*.log" -Recurse -File | Where-Object { $_.LastWriteTime -ge $startTime } ; foreach($currentLogFile in $logFileList) { $IpTable = @{} ; Write-Output "Loading content of log file $($currentLogFile.FullName)" ; $LogFile = Get-Content -Path $currentLogFile.FullName ; Write-Output "Log file has $($LogFile.count) lines" ; $LogFile | Where-Object { $_ -match 'POST' -and $_ -match ' 200 \d+ \d+ \d+$' -and [DateTime]::ParseExact($_.Substring(0, 19), 'yyyy-MM-dd HH:mm:ss', $null) -ge $startTime } | ForEach-Object { $line = $_ ; if ($line) { $regexIP = '\d+\.\d+\.\d+\.\d+' ; $matches = $line | Select-String -pattern $regexIP -allmatches ; $IpAddress = $matches.matches[1].value } ; $regexPattern = "^(?:10|127|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\..*" ; if (!$IpAddress) { if ($debug -eq 1) {Write-Output "Skipping blank IP value"} } elseif ($IpAddress -match $regexPattern) { if ($debug -eq 1) {Write-Output "Skipping $IpAddress"} } else { if ($IpTable.ContainsKey($IpAddress)) { $IpTable[$IpAddress]++ } else { $IpTable.add($IpAddress, 1) } } } ; $IpTable.getenumerator() | Sort-Object -Property Value -Descending | Where-Object { $_.value -gt 5 } | ForEach-Object { $IpAddress = $_.name ; $count = $_.value ; if ($debug -eq 1) {Write-Output "Adding $IpAddress with count $count"} ; "$IpAddress,$count" | out-file $outputCSV -append ; $IpAddress | out-file "C:\Temp\blockIP.txt" -append } } }
'@



## Additional useful report generation queries:
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



## Create or update firewall rule to block the above generated IP list:
$BlockIpAddresses = @'
$newIps = Get-Content "C:\Temp\blockIP.txt" | Sort-Object | Select-Object -Unique
$rule = (Get-NetFirewallRule | Where-Object { $_.DisplayName -eq 'BlockRDPandRDWEBBruteForce' } | Get-NetFirewallAddressFilter).RemoteAddress
if ($null -ne $rule -and $null -ne $newIps) {
    $new = Compare-Object -ReferenceObject ($rule) -DifferenceObject ($newIps) -IncludeEqual | Where-Object { $_.SideIndicator -eq '=>' } | Select-Object -ExpandProperty InputObject | Sort-Object
    $updated = Compare-Object -ReferenceObject ($rule) -DifferenceObject ($newIps) -IncludeEqual | Select-Object -ExpandProperty InputObject | Sort-Object
    Set-NetFirewallRule -DisplayName 'BlockRDPandRDWEBBruteForce' -Action Block -Direction Inbound -Protocol TCP -LocalPort 443,3389 -RemoteAddress $updated
    Write-Output "Updated firewall rule blocking $($new.Count) additional IP addresses, $($updated.Count) addresses total."
} elseif ($null -ne $newIps) {
    New-NetFirewallRule -DisplayName "BlockRDPandRDWEBBruteForce" -Action Block -Direction Inbound -Protocol TCP -LocalPort 443,3389 -RemoteAddress $newIps
    Write-Output "Created firewall rule blocking $($newIps.Count) IP addresses."
} else {
    Write-Output "No IP address lists found."
}
'@

## One-liner version of the above:
$BlockIpAddressesOneLine = @'
$newIps = Get-Content "C:\Temp\blockIP.txt" | Sort-Object | Select-Object -Unique ; $rule = (Get-NetFirewallRule | Where-Object { $_.DisplayName -eq 'BlockRDPandRDWEBBruteForce' } | Get-NetFirewallAddressFilter).RemoteAddress ; if ($null -ne $rule -and $null -ne $newIps) { $new = Compare-Object -ReferenceObject ($rule) -DifferenceObject ($newIps) -IncludeEqual | Where-Object { $_.SideIndicator -eq '=>' } | Select-Object -ExpandProperty InputObject | Sort-Object ; $updated = Compare-Object -ReferenceObject ($rule) -DifferenceObject ($newIps) -IncludeEqual | Select-Object -ExpandProperty InputObject | Sort-Object ; Set-NetFirewallRule -DisplayName 'BlockRDPandRDWEBBruteForce' -Action Block -Direction Inbound -Protocol TCP -LocalPort 443,3389 -RemoteAddress $updated ; Write-Output "Updated firewall rule blocking $($new.Count) additional IP addresses, $($updated.Count) addresses total." } elseif ($null -ne $newIps) { New-NetFirewallRule -DisplayName "BlockRDPandRDWEBBruteForce" -Action Block -Direction Inbound -Protocol TCP -LocalPort 443,3389 -RemoteAddress $newIps ; Write-Output "Created firewall rule blocking $($newIps.Count) IP addresses." } else { Write-Output "No IP address lists found." }
'@





