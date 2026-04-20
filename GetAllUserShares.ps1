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
# GetAllUserShares.ps1 - By Bitpusher/The Digital Fox
# v1.1.2 last updated 2026-01-08
# Searches through all local user registry hives and
# lists configured mapped shares.
# Outputs a report to C:\temp\COMPUTERNAME-UserShares-DATESTAMP.csv
#
# Usage:
# powershell -executionpolicy bypass -f .\GetAllUserShares.ps1
#
# Use simplified and minified one-liner version at the bottom to easily
# copy/paste into console of remote system (remote tools don't generally handle
# input with line breaks well).
#
#comp #ad #security #incident #script #shares #mount #net #use #mapped #powershell

#Requires -Version 5.1

# Locate and mount all non-mounted NTUSER.DAT hives
$Users = Get-LocalUser | Where-Object {$_.Enabled -eq $true -and $_.Name -notlike "DefaultAccount" -and $_.Name -notlike "Guest"}
foreach ($User in $Users) {
    $hivePath = "C:\Users\$($User.name)\NTUSER.DAT"
    # $tempKeyName = "UserHive_$($User.sid.Value.Substring($User.sid.Value.LastIndexOf('-') + 1))"
    $tempKeyName = "UserHive_$($User.sid.Value)"
    if (Test-Path $hivePath) {
        try {
            if (Test-Path "Registry::HKEY_USERS\$($User.sid.Value)") {
                Write-Output "USER: $($User.name) hive already loaded at HKEY_USERS\$($User.sid.Value)"
            } else {
                # reg load HKLM\$tempKeyName $hivePath # registry hive gets stuck with open handles when using this
                Start-Process reg -ArgumentList "LOAD HKLM\$tempKeyName $hivePath" -PassThru -Wait
                if (Test-Path "Registry::HKEY_LOCAL_MACHINE\$tempKeyName") {
                    Write-Output "Loaded hive for USER: $($User.name) SID: $($User.sid.Value) as key: $tempKeyName"
                } else {
                    Write-Output "Failed to load hive for USER: $($User.name) SID: $($User.sid.Value)"
                }
            }
        } catch {
            Write-Output "Failed to load hive for USER: $($User.name) SID: $($User.sid.Value) - $($_.Exception.Message)"
        }
    } else {
        Write-Output "NTUSER.DAT not found for USER: $($User.name) SID: $($User.sid.Value) at path: $hivePath"
    }
}

# Pull mapped drive information from all user hives
$Results = @()
foreach ($User in $Users) {
    if (Test-Path "Registry::HKEY_USERS\$($User.sid.Value)") {
        $Drives = Get-ItemProperty "Registry::HKEY_USERS\$($User.sid.Value)\Network\*" | Select-Object pspath, pschildname, remotepath
    } elseif (Test-Path "Registry::HKEY_LOCAL_MACHINE\UserHive_$($User.sid.Value)") {
        $Drives = Get-ItemProperty "Registry::HKEY_LOCAL_MACHINE\UserHive_$($User.sid.Value)\Network\*" | Select-Object pspath, pschildname, remotepath
    } else {
        Write-Output "Hive for user $($User.name) not found - skipping."
    }

    foreach ($Drive in $Drives) {
        $ResultHash = @{
            "Username" = $User.name
            "SID" = $User.sid.Value
            # "RegPath" = $Drive.pspath
            "MountPath" = $Drive.pschildname
            "RemotePath" = $Drive.remotepath
        }
        $Results += (New-Object PSObject -Property $ResultHash)
    }
}

# Show and export report
if ($Results) {
    Write-Output "User share settings found:"
    $Results
    $Results | Export-Csv C:\temp\$($env:computername)-UserShares-$($(Get-Date).ToString("yyyyMMddHHmm")).csv -notypeinformation
} else {
    Write-Output "No user share settings found."
}

# Unmount all user registry hives mounted by this script
$loadedHives = Get-ChildItem "Registry::HKEY_LOCAL_MACHINE\*" -ErrorAction SilentlyContinue | Where-Object {$_.Name -like "HKEY_LOCAL_MACHINE\UserHive_*"} | Select -ExpandProperty PSChildName
if ($loadedHives) {
    Get-Variable | Where-Object {$_.Name -ne "loadedHives"} | Remove-Variable -Force -ErrorAction SilentlyContinue
    [gc]::collect()
    Start-Sleep -Seconds 5
    [gc]::Collect(1000, [System.GCCollectionMode]::Forced , $true )
    Start-Sleep -Seconds 5
    foreach ($hive in $loadedHives) {
        try {
            # reg unload HKLM\$($hive.PSChildName)
            Start-Process reg -ArgumentList "UNLOAD HKLM\$hive" -PassThru -Wait
            if (Test-Path "Registry::HKEY_LOCAL_MACHINE\$hive") {
                Write-Output "Failed to unload hive: $hive"
            } else {
                Write-Output "Unloaded hive: $hive"
            }
        } catch {
            Write-Output "Failed to unload hive: $hive - $($_.Exception.Message)"
        }
    }
}

# One-liner version (for ease of remote execution):
$GetSharesReportOneLine = @'
$Users = Get-LocalUser | Where-Object {$_.Enabled -eq $true -and $_.Name -notlike "DefaultAccount" -and $_.Name -notlike "Guest"} ; foreach ($User in $Users) { $hivePath = "C:\Users\$($User.name)\NTUSER.DAT" ; $tempKeyName = "UserHive_$($User.sid.Value)" ; if (Test-Path $hivePath) { try { if (Test-Path "Registry::HKEY_USERS\$($User.sid.Value)") { Write-Output "USER: $($User.name) hive already loaded at HKEY_USERS\$($User.sid.Value)" } else { Start-Process reg -ArgumentList "LOAD HKLM\$tempKeyName $hivePath" -PassThru -Wait ; if (Test-Path "Registry::HKEY_LOCAL_MACHINE\$tempKeyName") { Write-Output "Loaded hive for USER: $($User.name) SID: $($User.sid.Value) as key: $tempKeyName" } else { Write-Output "Failed to load hive for USER: $($User.name) SID: $($User.sid.Value)" } } } catch { Write-Output "Failed to load hive for USER: $($User.name) SID: $($User.sid.Value) - $($_.Exception.Message)" } } else { Write-Output "NTUSER.DAT not found for USER: $($User.name) SID: $($User.sid.Value) at path: $hivePath" } } ; $Results = @() ; foreach ($User in $Users) { if (Test-Path "Registry::HKEY_USERS\$($User.sid.Value)") { $Drives = Get-ItemProperty "Registry::HKEY_USERS\$($User.sid.Value)\Network\*" | Select-Object pspath, pschildname, remotepath } elseif (Test-Path "Registry::HKEY_LOCAL_MACHINE\UserHive_$($User.sid.Value)") { $Drives = Get-ItemProperty "Registry::HKEY_LOCAL_MACHINE\UserHive_$($User.sid.Value)\Network\*" | Select-Object pspath, pschildname, remotepath } else { Write-Output "Hive for user $($User.name) not found - skipping." } ; foreach ($Drive in $Drives) { $ResultHash = @{ "Username" = $User.name; "SID" = $User.sid.Value; "MountPath" = $Drive.pschildname; "RemotePath" = $Drive.remotepath } ; $Results += (New-Object PSObject -Property $ResultHash) } } ; if ($Results) { Write-Output "User share settings found:" ; $Results ; $Results | Export-Csv C:\temp\$($env:computername)-UserShares-$($(Get-Date).ToString("yyyyMMddHHmm")).csv -notypeinformation } else { Write-Output "No user share settings found." } ; $loadedHives = Get-ChildItem "Registry::HKEY_LOCAL_MACHINE\*" -ErrorAction SilentlyContinue | Where-Object {$_.Name -like "HKEY_LOCAL_MACHINE\UserHive_*"} | Select -ExpandProperty PSChildName ; if ($loadedHives) { Get-Variable | Where-Object {$_.Name -ne "loadedHives"} | Remove-Variable -Force -ErrorAction SilentlyContinue ; [gc]::collect() ; Start-Sleep -Seconds 5 ; [gc]::Collect(1000, [System.GCCollectionMode]::Forced , $true ) ; Start-Sleep -Seconds 5 ; foreach ($hive in $loadedHives) { try { Start-Process reg -ArgumentList "UNLOAD HKLM\$hive" -PassThru -Wait ; if (Test-Path "Registry::HKEY_LOCAL_MACHINE\$hive") { Write-Output "Failed to unload hive: $hive" } else { Write-Output "Unloaded hive: $hive" } } catch { Write-Output "Failed to unload hive: $hive - $($_.Exception.Message)" } } }
'@

# One-liner of local hive mount/unmount to sandwich around desired registry lookup commands:
$GetSharesReportOneLine = @'
$Users = Get-LocalUser | Where-Object {$_.Enabled -eq $true -and $_.Name -notlike "DefaultAccount" -and $_.Name -notlike "Guest"} ; foreach ($User in $Users) { $hivePath = "C:\Users\$($User.name)\NTUSER.DAT" ; $tempKeyName = "UserHive_$($User.sid.Value)" ; if (Test-Path $hivePath) { try { if (Test-Path "Registry::HKEY_USERS\$($User.sid.Value)") { Write-Output "USER: $($User.name) hive already loaded at HKEY_USERS\$($User.sid.Value)" } else { Start-Process reg -ArgumentList "LOAD HKLM\$tempKeyName $hivePath" -PassThru -Wait ; if (Test-Path "Registry::HKEY_LOCAL_MACHINE\$tempKeyName") { Write-Output "Loaded hive for USER: $($User.name) SID: $($User.sid.Value) as key: $tempKeyName" } else { Write-Output "Failed to load hive for USER: $($User.name) SID: $($User.sid.Value)" } } } catch { Write-Output "Failed to load hive for USER: $($User.name) SID: $($User.sid.Value) - $($_.Exception.Message)" } } else { Write-Output "NTUSER.DAT not found for USER: $($User.name) SID: $($User.sid.Value) at path: $hivePath" } } ; 

## PLACE YOUR ONE-LINER REG LOOKUP HERE ##

; $loadedHives = Get-ChildItem "Registry::HKEY_LOCAL_MACHINE\*" -ErrorAction SilentlyContinue | Where-Object {$_.Name -like "HKEY_LOCAL_MACHINE\UserHive_*"} | Select -ExpandProperty PSChildName ; if ($loadedHives) { Get-Variable | Where-Object {$_.Name -ne "loadedHives"} | Remove-Variable -Force -ErrorAction SilentlyContinue ; [gc]::collect() ; Start-Sleep -Seconds 5 ; [gc]::Collect(1000, [System.GCCollectionMode]::Forced , $true ) ; Start-Sleep -Seconds 5 ; foreach ($hive in $loadedHives) { try { Start-Process reg -ArgumentList "UNLOAD HKLM\$hive" -PassThru -Wait ; if (Test-Path "Registry::HKEY_LOCAL_MACHINE\$hive") { Write-Output "Failed to unload hive: $hive" } else { Write-Output "Unloaded hive: $hive" } } catch { Write-Output "Failed to unload hive: $hive - $($_.Exception.Message)" } } }
'@


# One-liner of which lists Outlook addins installed for all users:
$GetSharesReportOneLine = @'
$Users = Get-LocalUser | Where-Object {$_.Enabled -eq $true -and $_.Name -notlike "DefaultAccount" -and $_.Name -notlike "Guest"} ; foreach ($User in $Users) { $hivePath = "C:\Users\$($User.name)\NTUSER.DAT" ; $tempKeyName = "UserHive_$($User.sid.Value)" ; if (Test-Path $hivePath) { try { if (Test-Path "Registry::HKEY_USERS\$($User.sid.Value)") { Write-Output "USER: $($User.name) hive already loaded at HKEY_USERS\$($User.sid.Value)" } else { Start-Process reg -ArgumentList "LOAD HKLM\$tempKeyName $hivePath" -PassThru -Wait ; if (Test-Path "Registry::HKEY_LOCAL_MACHINE\$tempKeyName") { Write-Output "Loaded hive for USER: $($User.name) SID: $($User.sid.Value) as key: $tempKeyName" } else { Write-Output "Failed to load hive for USER: $($User.name) SID: $($User.sid.Value)" } } } catch { Write-Output "Failed to load hive for USER: $($User.name) SID: $($User.sid.Value) - $($_.Exception.Message)" } } else { Write-Output "NTUSER.DAT not found for USER: $($User.name) SID: $($User.sid.Value) at path: $hivePath" } } ; $searchScopes = @( 'HKCU:\SOFTWARE\Microsoft\Office\Outlook\Addins', 'HKLM:\SOFTWARE\Microsoft\Office\Outlook\Addins', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Office\Outlook\Addins' ) ; $searchScopes | ForEach-Object { Get-ChildItem -Path $_ | ForEach-Object { Get-ItemProperty -Path $_.PSPath } | Select-Object @{ Name = "Name"; Expression = { Split-Path $_.PSPath -Leaf } }, FriendlyName, Description } | Sort-Object -Unique -Property Name ; $loadedHives = Get-ChildItem "Registry::HKEY_LOCAL_MACHINE\*" -ErrorAction SilentlyContinue | Where-Object {$_.Name -like "HKEY_LOCAL_MACHINE\UserHive_*"} | Select -ExpandProperty PSChildName ; if ($loadedHives) { Get-Variable | Where-Object {$_.Name -ne "loadedHives"} | Remove-Variable -Force -ErrorAction SilentlyContinue ; [gc]::collect() ; Start-Sleep -Seconds 5 ; [gc]::Collect(1000, [System.GCCollectionMode]::Forced , $true ) ; Start-Sleep -Seconds 5 ; foreach ($hive in $loadedHives) { try { Start-Process reg -ArgumentList "UNLOAD HKLM\$hive" -PassThru -Wait ; if (Test-Path "Registry::HKEY_LOCAL_MACHINE\$hive") { Write-Output "Failed to unload hive: $hive" } else { Write-Output "Unloaded hive: $hive" } } catch { Write-Output "Failed to unload hive: $hive - $($_.Exception.Message)" } } }
'@

