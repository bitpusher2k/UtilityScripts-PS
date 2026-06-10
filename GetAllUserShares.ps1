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
# v1.1.4 last updated 2026-06-08
# Searches through all user registry hives (loaded AND offline) and
# lists configured mapped shares. Reads currently logged-on users
# (local or domain) directly from HKEY_USERS, and loads offline local
# hives from disk. Note: only persistent ("reconnect at sign-in")
# mappings are stored in the registry; session-only "net use" mounts
# are not captured here.
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
#Requires -RunAsAdministrator

# Ensure output directory exists (Export-Csv will not create it)
if (-not (Test-Path C:\temp)) { New-Item -ItemType Directory -Path C:\temp -Force | Out-Null }

# Locate and mount all non-mounted NTUSER.DAT hives
$Users = Get-LocalUser | Where-Object {$_.Enabled -eq $true -and $_.Name -notin @("DefaultAccount", "Guest")}
foreach ($User in $Users) {
    $hivePath = "C:\Users\$($User.name)\NTUSER.DAT"
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
# Resolve a SID string to a DOMAIN\Username (falls back to the raw SID)
function Resolve-Sid ($sidStr) {
    try {
        return (New-Object System.Security.Principal.SecurityIdentifier($sidStr)).Translate([System.Security.Principal.NTAccount]).Value
    } catch {
        return $sidStr
    }
}

# Build the list of hive roots to scan, keyed by SID, so each user is read once.
# 1) Every currently-loaded user hive under HKEY_USERS (catches logged-on local
#    AND domain users). Skip _Classes companion hives and service SIDs.
# 2) Every offline local hive this script loaded into HKLM\UserHive_<SID>.
$HiveRoots = @{}
Get-ChildItem "Registry::HKEY_USERS\*" -ErrorAction SilentlyContinue |
    Where-Object {$_.PSChildName -match '^S-1-(5-21|12-1)-' -and $_.PSChildName -notlike "*_Classes"} |
    ForEach-Object { $HiveRoots[$_.PSChildName] = $_.PSPath }
foreach ($User in $Users) {
    $sid = $User.sid.Value
    if (-not $HiveRoots.ContainsKey($sid) -and (Test-Path "Registry::HKEY_LOCAL_MACHINE\UserHive_$sid")) {
        $HiveRoots[$sid] = "Registry::HKEY_LOCAL_MACHINE\UserHive_$sid"
    }
}

# Pull mapped drive information from all collected user hives
$Results = @()
foreach ($sid in $HiveRoots.Keys) {
    $root = $HiveRoots[$sid]
    $userName = Resolve-Sid $sid
    $Drives = Get-ItemProperty "$root\Network\*" -ErrorAction SilentlyContinue | Select-Object pspath, pschildname, remotepath
    foreach ($Drive in $Drives) {
        $ResultHash = @{
            "Username" = $userName
            "SID" = $sid
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

# ============================================================================
# Minified one-liner (copy/paste into remote console - run elevated):
# ============================================================================
$GetSharesReportOneLine = @'
if(-not(Test-Path C:\temp)){New-Item -ItemType Directory -Path C:\temp -Force|Out-Null};$Users=Get-LocalUser|?{$_.Enabled -and $_.Name -notin @("DefaultAccount","Guest")};foreach($User in $Users){$h="C:\Users\$($User.name)\NTUSER.DAT";$k="UserHive_$($User.sid.Value)";if((Test-Path $h)-and -not(Test-Path "Registry::HKEY_USERS\$($User.sid.Value)")){Start-Process reg -ArgumentList "LOAD HKLM\$k $h" -PassThru -Wait|Out-Null}};$R=@{};Get-ChildItem "Registry::HKEY_USERS\*" -ErrorAction SilentlyContinue|?{$_.PSChildName -match '^S-1-(5-21|12-1)-' -and $_.PSChildName -notlike "*_Classes"}|%{$R[$_.PSChildName]=$_.PSPath};foreach($User in $Users){$s=$User.sid.Value;if(-not $R.ContainsKey($s)-and(Test-Path "Registry::HKEY_LOCAL_MACHINE\UserHive_$s")){$R[$s]="Registry::HKEY_LOCAL_MACHINE\UserHive_$s"}};$Results=@();foreach($s in @($R.Keys)){try{$n=(New-Object System.Security.Principal.SecurityIdentifier($s)).Translate([System.Security.Principal.NTAccount]).Value}catch{$n=$s};Get-ItemProperty "$($R[$s])\Network\*" -ErrorAction SilentlyContinue|Select pspath,pschildname,remotepath|%{$Results+=New-Object PSObject -Property @{Username=$n;SID=$s;MountPath=$_.pschildname;RemotePath=$_.remotepath}}};if($Results){$Results;$Results|Export-Csv C:\temp\$($env:computername)-UserShares-$((Get-Date).ToString("yyyyMMddHHmm")).csv -NoTypeInformation}else{"No user share settings found."};$loadedHives=Get-ChildItem "Registry::HKEY_LOCAL_MACHINE\*" -ErrorAction SilentlyContinue|?{$_.Name -like "HKEY_LOCAL_MACHINE\UserHive_*"}|Select -ExpandProperty PSChildName;if($loadedHives){Get-Variable|?{$_.Name -ne "loadedHives"}|Remove-Variable -Force -ErrorAction SilentlyContinue;[gc]::Collect();Start-Sleep -Seconds 5;[gc]::Collect(1000,[System.GCCollectionMode]::Forced,$true);Start-Sleep -Seconds 5;foreach($hive in $loadedHives){Start-Process reg -ArgumentList "UNLOAD HKLM\$hive" -PassThru -Wait|Out-Null}}
'@





# One-liner of local hive mount/unmount to sandwich around desired registry lookup commands:
$GetSharesReportOneLine = @'
$Users = Get-LocalUser | Where-Object {$_.Enabled -eq $true -and $_.Name -notlike "DefaultAccount" -and $_.Name -notlike "Guest"} ; foreach ($User in $Users) { $hivePath = "C:\Users\$($User.name)\NTUSER.DAT" ; $tempKeyName = "UserHive_$($User.sid.Value)" ; if (Test-Path $hivePath) { try { if (Test-Path "Registry::HKEY_USERS\$($User.sid.Value)") { Write-Output "USER: $($User.name) hive already loaded at HKEY_USERS\$($User.sid.Value)" } else { Start-Process reg -ArgumentList "LOAD HKLM\$tempKeyName $hivePath" -PassThru -Wait ; if (Test-Path "Registry::HKEY_LOCAL_MACHINE\$tempKeyName") { Write-Output "Loaded hive for USER: $($User.name) SID: $($User.sid.Value) as key: $tempKeyName" } else { Write-Output "Failed to load hive for USER: $($User.name) SID: $($User.sid.Value)" } } } catch { Write-Output "Failed to load hive for USER: $($User.name) SID: $($User.sid.Value) - $($_.Exception.Message)" } } else { Write-Output "NTUSER.DAT not found for USER: $($User.name) SID: $($User.sid.Value) at path: $hivePath" } } ; 

## PLACE YOUR ONE-LINER REG LOOKUP HERE ##

; $loadedHives = Get-ChildItem "Registry::HKEY_LOCAL_MACHINE\*" -ErrorAction SilentlyContinue | Where-Object {$_.Name -like "HKEY_LOCAL_MACHINE\UserHive_*"} | Select -ExpandProperty PSChildName ; if ($loadedHives) { Get-Variable | Where-Object {$_.Name -ne "loadedHives"} | Remove-Variable -Force -ErrorAction SilentlyContinue ; [gc]::collect() ; Start-Sleep -Seconds 5 ; [gc]::Collect(1000, [System.GCCollectionMode]::Forced , $true ) ; Start-Sleep -Seconds 5 ; foreach ($hive in $loadedHives) { try { Start-Process reg -ArgumentList "UNLOAD HKLM\$hive" -PassThru -Wait ; if (Test-Path "Registry::HKEY_LOCAL_MACHINE\$hive") { Write-Output "Failed to unload hive: $hive" } else { Write-Output "Unloaded hive: $hive" } } catch { Write-Output "Failed to unload hive: $hive - $($_.Exception.Message)" } } }
'@


# One-liner of which lists Outlook addins installed for all users:
$GetSharesReportOneLine = @'
$Users = Get-LocalUser | Where-Object {$_.Enabled -eq $true -and $_.Name -notlike "DefaultAccount" -and $_.Name -notlike "Guest"} ; foreach ($User in $Users) { $hivePath = "C:\Users\$($User.name)\NTUSER.DAT" ; $tempKeyName = "UserHive_$($User.sid.Value)" ; if (Test-Path $hivePath) { try { if (Test-Path "Registry::HKEY_USERS\$($User.sid.Value)") { Write-Output "USER: $($User.name) hive already loaded at HKEY_USERS\$($User.sid.Value)" } else { Start-Process reg -ArgumentList "LOAD HKLM\$tempKeyName $hivePath" -PassThru -Wait ; if (Test-Path "Registry::HKEY_LOCAL_MACHINE\$tempKeyName") { Write-Output "Loaded hive for USER: $($User.name) SID: $($User.sid.Value) as key: $tempKeyName" } else { Write-Output "Failed to load hive for USER: $($User.name) SID: $($User.sid.Value)" } } } catch { Write-Output "Failed to load hive for USER: $($User.name) SID: $($User.sid.Value) - $($_.Exception.Message)" } } else { Write-Output "NTUSER.DAT not found for USER: $($User.name) SID: $($User.sid.Value) at path: $hivePath" } } ; 

$searchScopes = @( 'HKCU:\SOFTWARE\Microsoft\Office\Outlook\Addins', 'HKLM:\SOFTWARE\Microsoft\Office\Outlook\Addins', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Office\Outlook\Addins' ) ; $searchScopes | ForEach-Object { Get-ChildItem -Path $_ | ForEach-Object { Get-ItemProperty -Path $_.PSPath } | Select-Object @{ Name = "Name"; Expression = { Split-Path $_.PSPath -Leaf } }, FriendlyName, Description } | Sort-Object -Unique -Property Name ; 

$loadedHives = Get-ChildItem "Registry::HKEY_LOCAL_MACHINE\*" -ErrorAction SilentlyContinue | Where-Object {$_.Name -like "HKEY_LOCAL_MACHINE\UserHive_*"} | Select -ExpandProperty PSChildName ; if ($loadedHives) { Get-Variable | Where-Object {$_.Name -ne "loadedHives"} | Remove-Variable -Force -ErrorAction SilentlyContinue ; [gc]::collect() ; Start-Sleep -Seconds 5 ; [gc]::Collect(1000, [System.GCCollectionMode]::Forced , $true ) ; Start-Sleep -Seconds 5 ; foreach ($hive in $loadedHives) { try { Start-Process reg -ArgumentList "UNLOAD HKLM\$hive" -PassThru -Wait ; if (Test-Path "Registry::HKEY_LOCAL_MACHINE\$hive") { Write-Output "Failed to unload hive: $hive" } else { Write-Output "Unloaded hive: $hive" } } catch { Write-Output "Failed to unload hive: $hive - $($_.Exception.Message)" } } }
'@

