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
# Check-SubnetDevices.ps1 - By Bitpusher/The Digital Fox
# v1.0 last updated 2024-03-21
# Script to check devices by MAC on current subnet
#
# Usage:
# powershell -executionpolicy bypass -f ./Check-SubnetDevices.ps1 -Network "192.168.10." -Self "192.168.10.16"
#
# email log to yourself by including the emailServer, emailFrom, emailTo
# emailUsername, and emailPassword parameters.
#
# when creating a scheduled task to run such scripts, use the following structure example:
# powershell.exe -NoProfile -ExecutionPolicy Bypass -Scope Process -File "C:\Utility\TEMPLATE.ps1"
#
# To run as a scheduled task start PowerShell:
# C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.exe
# With arguments something like this:
# -Command "& 'C:\Utility\TEMPLATE.ps1' -Param1 XXX1,XXX2,XXX3 -Param2 15"
#
# To run remotely on a list of endpoints with PS remoting already enabled (Enable-PSRemoting):
# Invoke-Command -FilePath "C:\Utility\TEMPLATE.ps1" -ComputerName endpoint1,endpoint2,endpoint3
# or
# Invoke-command -ComputerName (get-content c:\Utility\EndpointList.txt) -filepath c:\Utility\TEMPLATE.ps1
# or using PsExec:
# psexec -s \\endpoint1 Powershell -ExecutionPolicy Bypass -File \\dc\netlogon\scripts\TEMPLATE.ps1
#
#template #script #powershell

#Requires -Version 5.1

param(
    [string]$Network = "192.168.10.",
    [array]$Self = (Get-NetIPAddress | Where-Object { $_.AddressState -eq "Preferred" -and $_.ValidLifetime -lt "24:00:00" }).IPAddress,
    [string]$LookupType = "NetBIOS",
    [string]$scriptName = "Check-SubnetDevices",
    [string]$Priority = "Normal",
    [int]$RandMax = "2",
    [string]$DebugPreference = "SilentlyContinue",
    [string]$VerbosePreference = "SilentlyContinue",
    [string]$InformationPreference = "Continue",
    [string]$logFileFolderPath = "C:\Utility\log",
    [string]$ComputerName = $env:computername,
    [string]$ScriptUserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
    [string]$emailServer = "",
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
    [string]$Encoding = "utf8bom" # PS 5 & 7: "Ascii" (7-bit), "BigEndianUnicode" (UTF-16 big-endian), "BigEndianUTF32", "Oem", "Unicode" (UTF-16 little-endian), "UTF32" (little-endian), "UTF7", "UTF8" (PS 5: BOM, PS 7: NO BOM). PS 7: "ansi", "utf8BOM", "utf8NoBOM"
)

process {
    #region initialization
    if ($PSVersionTable.PSVersion.Major -eq 5 -and ($Encoding -eq "utf8bom" -or $Encoding -eq "utf8nobom")) { $Encoding = "utf8" }

    function Get-TimeStamp {
        param(
            [switch]$NoWrap,
            [switch]$Utc
        )
        $dt = Get-Date
        if ($Utc -eq $true) {
            $dt = $dt.ToUniversalTime()
        }
        $str = "{0:MM/dd/yy} {0:HH:mm:ss}" -f $dt

        if ($NoWrap -ne $true) {
            $str = "[$str]"
        }
        return $str
    }

    function Test-FileLock {
        param(
            [Parameter(Mandatory = $true)] [string]$Path
        )

        $oFile = New-Object System.IO.FileInfo $Path

        if ((Test-Path -Path $Path) -eq $false) {
            return $false
        }

        try {
            $oStream = $oFile.Open([System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)

            if ($oStream) {
                $oStream.Close()
            }
            return $false
        } catch {
            # file is locked by a process.
            return $true
        }
    }

    if ($logFileFolderPath -ne "") {
        if (!(Test-Path -PathType Container -Path $logFileFolderPath)) {
            Write-Output "$(Get-TimeStamp) Creating directory $logFileFolderPath" | Out-Null
            New-Item -ItemType Directory -Force -Path $logFileFolderPath | Out-Null
        } else {
            $DatetoDelete = $(Get-Date).AddDays(- $logFileRetentionDays)
            Get-ChildItem $logFileFolderPath | Where-Object { $_.Name -like "*$logFilePrefix*" -and $_.LastWriteTime -lt $DatetoDelete } | Remove-Item | Out-Null
        }
        $logFilePath = $logFileFolderPath + "\$logFilePrefix" + (Get-Date -Format $logFileDateFormat) + ".LOG"
    }

    # Set script priority
    # Possible values: Idle, BelowNormal, Normal, AboveNormal, High, RealTime
    $process = Get-Process -Id $pid
    Write-Output "Setting process priority to `"$Priority`""
    #Write-Output "Script priority before:"
    #Write-Output $process.PriorityClass
    $process.PriorityClass = $Priority
    #Write-Output "Script priority After:"
    #Write-Output $process.PriorityClass
    #endregion initialization

    #region main
    # debug tracing - set to "2" for testing, set to "0" for production use
    Set-PSDebug -Trace 0
    [int]$MyExitStatus = 1
    $StartTime = $(Get-Date)
    Write-Output "Script $scriptName started at $(Get-TimeStamp)"
    Write-Output "ISO8601:$(Get-Date (Get-Date).ToUniversalTime() -UFormat '+%Y%m%dT%H%M%S.000Z')`n"
    $RandSeconds = Get-Random -Minimum 1 -Maximum $RandMax
    Write-Output "Script $scriptName started at $(Get-TimeStamp)" | Out-File -FilePath $logFilePath -Encoding $Encoding
    Write-Output "ISO8601:$(Get-Date (Get-Date).ToUniversalTime() -UFormat '+%Y%m%dT%H%M%S.000Z')`n" | Out-File -FilePath $logFilePath -Append -Encoding $Encoding
    Write-Output "Waiting $RandSeconds seconds (between 1 and $RandMax) to stagger execution across devices`n"
    Start-Sleep -Seconds $RandSeconds

    # List devices by MAC on current subnet

    function Test-OnlineFast {
        param (
            [Parameter(Mandatory, ValueFromPipeline)]
            [string[]]
            $Computer,
            $TimeoutMillisec = 200
        )

        begin {
            [Collections.ArrayList]$bucket = @()
            $IsOnline = @{
                Name       = 'Online'
                Expression = { $_.StatusCode -eq 0 }
            }
        }

        process {
            $Computer | ForEach-Object {
                $null = $bucket.Add($_)
            }
        }

        end {
            $query = $bucket -join "' or Address='"
            Get-CimInstance -Class Win32_PingStatus -Filter "(Address='$query') and timeout=$TimeoutMillisec" |
                Select-Object -Property Address, $IsOnline
        }
    }

    $Results = @()
    $DevicesAnswered = @()
    $MacVendors = Import-Csv macvendors.csv
    $KnownMacs = Import-Csv knownmacs.csv

    # Ping all addresses in subnet
    Write-Output "Pinging subnet $($Network)X..."
    $IPs = 1..254
    $IPs = $IPs | ForEach-Object { "$($Network)$_" }

    $Ping1Answer = $IPs | Test-OnlineFast | Where-Object { $_.Online -eq "True" }
    
    #Write-Output "`nIPs: $($IPs.GetType())"
    #$IPs | FT
    
    # Add the "Address" property header to the IP list:
    $IPobject = New-Object -TypeName PSObject
    $IPobject = foreach($n in $IPs) { [PSCustomObject] @{ "Address" = $n } }
    #Write-Output "`nIP OBJECT: $($IPobject.GetType())"
    #$IPobject | FT
    # $IPobject | Select-Object -ExpandProperty Address
    
    Write-Output "`nAnswering devices (round 1):"
    $Ping1Answer | FT

    # Compare the full IP list with those that answered, and keep list of the ones that didn't answer
    $NoAnswer = Compare-Object -ReferenceObject $IPobject -DifferenceObject $Ping1Answer -Property Address
    #$NoAnswer += new-object psobject -property @{ Address = '192.168.10.17'; SideIndicator = 'Manually added for testing' }
    #$NoAnswer += new-object psobject -property @{ Address = '192.168.10.22'; SideIndicator = 'Manually added for testing' }
    #Write-Output "`nNon-answering devices: $($NoAnswer.GetType())"
    #$NoAnswer | ft
    #$NoAnswer | Select-Object -ExpandProperty Address
    
    Start-Sleep -Milliseconds 200
    $Ping2Answer = $NoAnswer | Select-Object -ExpandProperty Address | Test-OnlineFast | Where-Object { $_.Online -eq "True" }
    
    Write-Output "`nAnswering devices (round 2):"
    $Ping2Answer
    
    $PingDiff = @()
    $PingDiff += $Ping1Answer
    $PingDiff += $Ping2Answer

    $NoAnswer = Compare-Object -ReferenceObject $IPobject -DifferenceObject $PingDiff -Property Address
    
    Start-Sleep -Milliseconds 200
    $Ping3Answer = $NoAnswer | Select-Object -ExpandProperty Address | Test-OnlineFast | Where-Object { $_.Online -eq "True" }
    
    Write-Output "`nAnswering devices (round 3):"
    $Ping3Answer

    
    $DevicesAnswered = @()
    $DevicesAnswered += $Ping1Answer
    $DevicesAnswered += $Ping2Answer
    $DevicesAnswered += $Ping3Answer
    Write-Output "`nCombined answering devices from all three rounds:"
    $DevicesAnswered | Sort-Object | FT

    #Write-Output "`nUnique list of answering devices:"
    #$DevicesAnswered = $DevicesAnswered | Sort-Object -Unique -Property Address
    #$DevicesAnswered
    
    Write-Output "`n$($DevicesAnswered.length) devices answered on the subnet $($Network)x"
    Write-Output "`n-------------------------------------`n"

    #Lookup MAC for found devices
    foreach ($Device in $DevicesAnswered) {
        $Address = $Device.Address
        $MAC = arp -a $Address | Select-String '([0-9a-f]{2}-){5}[0-9a-f]{2}' | Select-Object -Expand Matches | Select-Object -Expand Value
        # https://stackoverflow.com/questions/41632656/getting-the-mac-address-by-arp-a
        
        if ($Self -contains $Address) {
            # $KnownName = $env:computername
            # $HostName = $KnownName
            $SelfInfo = Get-NetIPConfiguration | select @{n='ipv4address';e={$_.ipv4address[0]}}, @{n='macaddress'; e={$_.netadapter.macaddress}}
            $SelfMac = $SelfInfo | Select-Object -Property ipv4address, macaddress | Where-Object {$_.ipv4address -like "$($Network)*"}
            $MAC = $SelfMac | Select-Object -ExpandProperty macaddress
        }

        if ($LookupType -eq "DNS") {
            try {
                $DNSName = [System.Net.Dns]::GetHostByAddress("$Address").Hostname
            } catch {
                $DNSName = ""
            }
            # Write-Output "`nDNSName: $DNSName"
            $HostName = $DNSName.NameHost
        } elseif ($LookupType -eq "NetBIOS") {
            $HostName = Resolve-DnsName -Name "$Address" -LlmnrNetbiosOnly -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NameHost
        }
        
        if ($MAC) {
            $MacSegment = $MAC.SubString(0, 8)
        } else {
            $MacSegment = "Null"
        }
        
        # Write-Output "`nMacSegment: $MacSegment"

        $Vendor = "Unknown"
        foreach ($Record in $MacVendors) {
            if ($Record.Mac -eq $MacSegment) {
                $Vendor = $Record.Vendor
                # Write-Output "`nVendor: $Vendor"
            }
        }

        $KnownName = ""
        $DocHostName = ""
        $KnownIP = ""
        foreach ($Known in $KnownMacs) {
            if ($Known.Mac -eq $MAC) {
                $KnownName = $Known.Name
                $DocHostName = $KnownName
                $KnownIP = $Known.IP
            }
        }

        if (!$KnownName) {
            Write-Output "`nUNKNOWN DEVICE ON NETWORK: $Address $MAC"
        } else {
            # Write-Output "`nKnown Device Name: $KnownName $Address $MAC"
        }

        #Write Data to Object
        $System = New-Object -TypeName PSObject
        $System | Add-Member -Type NoteProperty -Name DocumentedName -Value $DocHostName
        $System | Add-Member -Type NoteProperty -Name DiscoveredName -Value $HostName
        $System | Add-Member -Type NoteProperty -Name DocumentedIP -Value $KnownIP
        $System | Add-Member -Type NoteProperty -Name DiscoveredIP -Value $Address
        $System | Add-Member -Type NoteProperty -Name MAC -Value $Mac
        $System | Add-Member -Type NoteProperty -Name Vendor -Value $Vendor
        $Results += $System
    }

    #Show object
    $Results | Select-Object DocumentedName, DiscoveredName, DocumentedIP, DiscoveredIP, MAC, Vendor | Sort-Object -Property DiscoveredIP | Format-Table
    Write-Output "Done!`n`n"

    $MyExitStatus = 0
    #endregion main

    #region finalization
    if ($logFileFolderPath -ne "") {
        Write-Output "`nScript $scriptName ended at $(Get-TimeStamp)"
        Write-Output "Script $scriptName ended at $(Get-TimeStamp)" | Out-File -FilePath $logFilePath -Append -Encoding $Encoding
        $elapsedTime = $(Get-Date) - $StartTime
        Write-Output "Elapsed time (seconds): $($elapsedTime.TotalSeconds)"
        Write-Output "Elapsed time (seconds): $($elapsedTime.TotalSeconds)" | Out-File -FilePath $logFilePath -Append -Encoding $Encoding
        Write-Output "ISO8601:$(Get-Date (Get-Date).ToUniversalTime() -UFormat '+%Y%m%dT%H%M%S.000Z')`n" | Out-File -FilePath $logFilePath -Append -Encoding $Encoding
        if (($emailServer -ne "") -and ($emailUsername -ne "") -and ($emailPassword -ne "") -and ($emailFrom -ne "") -and ($emailTo -ne "")) {
            Send-MailMessage -SmtpServer "$emailServer" -Port 587 -From "$emailFrom" -To "$emailTo" -Subject "$scriptName - $ComputerName - $MyExitStatus - Log File" -Body "$logFilePath" -UseSsl -Credential (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$emailUsername", (ConvertTo-SecureString -String "$emailPassword" -AsPlainText -Force)) -Attachments $logFilePath
        }
        if (($shareLocation -ne "") -and ($shareUsername -ne "") -and ($sharePassword -ne "")) {
            [securestring]$secStringPassword = ConvertTo-SecureString $sharePassword -AsPlainText -Force
            [pscredential]$shareCred = New-Object System.Management.Automation.PSCredential ($shareUsername, $secStringPassword)
            New-PSDrive -Name LogStore -PSProvider FileSystem -Root "$shareLocation" -Description "Log Store" -Credential $shareCred
            $destFolder = "LogStore:\"
            Copy-Item -LiteralPath "$logFilePath" -Destination "$destFolder" -Force -ErrorAction Continue -ErrorVariable ErrorOutput
            Remove-PSDrive -Name LogStore
        }
    }
    Set-PSDebug -Trace 0
    #Get-Content $logFilePath
    exit $MyExitStatus
    #endregion finalization
}
