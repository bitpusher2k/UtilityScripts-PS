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
# Detect-RAS.ps1 - By Bitpusher/The Digital Fox
# v1.1 last updated 2024-11-20
# Script to search installed software, running processes, services, and program files for remote access software (RAS)
# on the endpoint. Outputs CSV report. Can be passed a list of tools to ignore.
#
# Usage:
# powershell -executionpolicy bypass -f ./Detect-RAS.ps1
# powershell -executionpolicy bypass -f ./Detect-RAS.ps1 -ExcludeTools "Connectwise Control/ScreenConnect","Kaseya"
# powershell -executionpolicy bypass -f ./Detect-RAS.ps1 -ExcludeTools "Connectwise Control/ScreenConnect","Kaseya" -emailServer "XXXX" -emailUsername "XXXX" -emailPassword "XXXX" -emailFrom "XXXX" -emailTo "XXXX"
#
# Attempts to detect a wide variety of Remote Access Software, including but not limited to:
# Acronis Cyber Protect
# AeroAdmin
# Ammyy Admin
# AnyDesk
# Atera
# Automate
# BeyondTrust
# Chrome Remote Desktop
# Connectwise Control
# Datto RMM
# DWService
# GoToMyPC
# Kaseya
# LiteManager
# LogMeIn
# ManageEngine
# N-Able N-Central
# N-Able N-Sight
# Ninja RMM
# NoMachine
# Parsec
# Remote Utilities
# RemotePC, Splashtop
# RustDesk
# Supremo
# Syncro
# TeamViewer
# TightVNC
# UltraVNC
# VNC Connect/RealVNC
# Zoho Assist
#
# Uses file names collected in the Living Off the Land Remote Monitoring and Management project - https://github.com/magicsword-io/LOLRMM
#
# Email execution log & report to yourself by including the emailServer, emailFrom, emailTo
# emailUsername, and emailPassword parameters.
#
# DISCLAIMER: This script is provided as-is and is a best effort in finding remote access software installed on an
# endpoint, but is not guaranteed to be accurate. 
# This software space is changing all the time, and false-negatives/false-positives should be expected.
# Plenty of room for improvement, refinement, and additions to detection rules.
#
#remote #access #software #inventory #ras #rat #rmm #search #script #powershell

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string[]]$ExcludeTools = @(), # Optional - List of tools to exclude (by name, as defined below)
    [string]$scriptName = "Detect-RAS",
    [string]$Priority = "Normal",
    [int]$RandMax = "500",
    [string]$DebugPreference = "SilentlyContinue",
    [string]$VerbosePreference = "SilentlyContinue",
    [string]$InformationPreference = "Continue",
    [string]$logFileFolderPath = "C:\Temp\log",
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
    [string]$Encoding = "utf8bom" # "ascii","ansi","bigendianunicode","unicode","utf8","utf8NoBOM","utf32"
)

begin {
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
        #OR: $logFilePath = $logFileFolderPath + "\$logFilePrefix" + (Get-Date (Get-Date).ToUniversalTime() -UFormat '+%Y%m%dT%H%M%S.000Z') + ".LOG"
        # attempt to start the transcript log, but don't fail the script if unsuccessful:
        try {
            Start-Transcript -Path $logFilePath -Append
        } catch [Exception] {
            Write-Warning "$(Get-TimeStamp) Unable to start Transcript: $($_.Exception.Message)"
            $logFileFolderPath = ""
        }
    }

    $ExportCSV = $logFileFolderPath + "\$logFilePrefix" + (Get-Date -Format $logFileDateFormat) + ".csv"

    # debug tracing - set to "0" for most production use
    Set-PSDebug -Trace 0
    [int]$MyExitStatus = 1
    $StartTime = $(Get-Date)
    Write-Output "Script $scriptName started at $(Get-TimeStamp)"
    Write-Output "ISO8601:$(Get-Date (Get-Date).ToUniversalTime() -UFormat '+%Y%m%dT%H%M%S.000Z')`n"
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

    # Function to check if a process is currently active by executable name
    function Find-Process {
        [CmdletBinding()]
        param(
            [Parameter(ValueFromPipeline)]
            [string]$Name
        )
        process {
            $Result = $Name | ForEach-Object { $str = $_; $Processes | Where-Object { $_.ProcessName -like "$str*" } } | Select-Object -ExpandProperty Name
            $Result
        }
    }

    # Function to check if a service is currently active by executable name
    function Find-Service {
        [CmdletBinding()]
        param(
            [Parameter(ValueFromPipeline)]
            [string]$Name
        )
        process {
            $Result = $Name | ForEach-Object { $str = $_; $Services | Where-Object { $_.pathname -like "*\$str*" } } | Select-Object -ExpandProperty Pathname
            $Result
        }
    }

    # Function to search the registry for uninstall keys locations by program name as it would appear in the Control Panel
    function Find-UninstallKey {
        [CmdletBinding()]
        param(
            [Parameter(ValueFromPipeline)]
            [string]$DisplayName,
            [Parameter()]
            [switch]$UninstallString
        )
        process {
            $UninstallList = New-Object System.Collections.Generic.List[Object]

            $Result = $Uninstall64 | Where-Object { $_.DisplayName -like "*$DisplayName*" }

            if ($Result) { $UninstallList.Add($Result) }

            $Result = $Uninstall32 | Where-Object { $_.DisplayName -like "*$DisplayName*" }

            if ($Result) { $UninstallList.Add($Result) }

            if ($UninstallString) {
                #$UninstallList | Select-Object -ExpandProperty UninstallString -ErrorAction Ignore
                $UninstallList.UninstallString
            } else {
                $UninstallList
            }
        }
    }

    # Function to search "C:\Program Files", "C:\Program Files (x86)", and "C:\ProgramData" for an file by name, or check a specific full path
    function Find-Executable {
        [CmdletBinding()]
        param(
            [Parameter(ValueFromPipeline)]
            [string]$File,
            [Parameter()]
            [switch]$Full
        )
        process {
            if (!$Full) {
                if ($File -match "\*") {
                    # Single-vlaue matches:
                    # $NameValue = $ProgramFilesFiles.GetEnumerator() | Where-Object { $_.Value -like $File }
                    # $NameValue += $ProgramFiles86Files.GetEnumerator() | Where-Object { $_.Value -like $File }
                    # $NameValue += $ProgramDataFiles.GetEnumerator() | Where-Object { $_.Value -like $File }
                    
                    # Array matches:
                    $NameValue = $File | ForEach-Object { $pattern = $_ ; $ProgramFilesFiles.GetEnumerator() | Where-Object { $_.Value -like $pattern } }
                    $NameValue += $File | ForEach-Object { $pattern = $_ ; $ProgramFiles86Files.GetEnumerator() | Where-Object { $_.Value -like $pattern } }
                    $NameValue += $File | ForEach-Object { $pattern = $_ ; $ProgramDataFiles.GetEnumerator() | Where-Object { $_.Value -like $pattern } }
                    
                    if ($NameValue.value) {
                        $NameValue.Value
                    }
                } else {
                    if ($ProgramFilesFiles[$File]) {
                        $ProgramFilesFiles[$File]
                    }

                    if ($ProgramFiles86Files[$File]) {
                        $ProgramFiles86Files[$File]
                    }

                    if ($ProgramDataFiles[$File]) {
                        $ProgramDataFiles[$File]
                    }
                }
            } else {
                if (Test-Path $File) {
                    $File
                }
            }
        }
    }

    Write-Output "Loading system information (running processes, running services, installed software listed in registry, program file list)..."

    # Load variables & create hash tables where possible to speed searching
    $Processes = Get-Process

    $Services = Get-CimInstance win32_service | Where-Object { $_.State -notlike "Disabled" -and $_.State -notlike "Stopped" }
    # $Services | ForEach-Object -Begin {$ServiceList=@{}} -Process { $ServiceList[$_.Name] = "" + $_.PathName }

    $Uninstall64 = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty

    $Uninstall32 = Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty

    $ProgramFiles = Get-ChildItem "${Env:ProgramFiles}" -Recurse -ErrorAction SilentlyContinue
    $ProgramFiles | ForEach-Object -Begin { $ProgramFilesFiles = @{} } -Process { $ProgramFilesFiles[$_.Name] = "" + $_.FullName }

    $ProgramFiles86 = Get-ChildItem "${Env:ProgramFiles(x86)}" -Recurse -ErrorAction SilentlyContinue
    $ProgramFiles86 | ForEach-Object -Begin { $ProgramFiles86Files = @{} } -Process { $ProgramFiles86Files[$_.Name] = "" + $_.FullName }

    $ProgramData = Get-ChildItem "${Env:ProgramData}" -Recurse -ErrorAction SilentlyContinue
    $ProgramData | ForEach-Object -Begin { $ProgramDataFiles = @{} } -Process { $ProgramDataFiles[$_.Name] = "" + $_.FullName }

    # List of software to look for:
    # NAME is what is listed in script output - ONE value per line
    # DisplayName is name used in registry uninstall keys - ONE value per line
    # ProcessName is the name of processes & services searched for - can be multiple values
    # IndicatorFilename is name of associated file - can be multiple values & should be relatively distinctive file names to minimize false positives - can use "*" wildcard if needed (slows searches)
    # FullIndicatorPath is full path to an associated file - ONE value for use if the full path to a file is needed to make a distinct identification- use instead of IndicatorFilename if needed - can use "*" wildcard 
    $RASList = @(
        #[PSCustomObject]@{ Name = "xxxxx"; DisplayName = "xxxxx"; ProcessName = "xxxxx"; IndicatorFilename = "xxxxx"; FullIndicatorPath = "C:\Full Path\xxxxx.exe" }
        [pscustomobject]@{ Name = "(Uncategorized suspicious files)"; IndicatorFilename = "eicar.txt" }
        [PSCustomObject]@{ Name = "247ithelp.com (ConnectWise)"; DisplayName = "247ithelp.com"; ProcessName = "Remote Workforce Client"; IndicatorFilename = "Remote Workforce Client.exe" }
        [PSCustomObject]@{ Name = "Absolute (Computrace)"; DisplayName = "Absolute"; ProcessName = "ctespersitence"; IndicatorFilename = "rpcnet.exe", "ctes.exe", "ctespersitence.exe", "cteshostsvc.exe", "rpcld.exe" }
        [PSCustomObject]@{ Name = "Access Remote PC"; DisplayName = "Access Remote PC"; ProcessName = "rpcgrab"; IndicatorFilename = "rpcgrab.exe", "rpcsetup.exe" }
        [pscustomobject]@{ Name = "Acronis Cyber Protect (Remotix)"; DisplayName = "Acronis Cyber Protect"; ProcessName = "AcronisCyberProtectConnectAgent"; IndicatorFilename = "AcronisCyberProtectConnectAgent.exe" }
        [PSCustomObject]@{ Name = "Action1"; DisplayName = "Action1"; ProcessName = "action1_connector"; FullIndicatorPath = "C:\Windows\Action1\action1_connector.exe" }
        [PSCustomObject]@{ Name = "Adobe Connect"; DisplayName = "Adobe Connect"; ProcessName = "Adobe Connect"; IndicatorFilename = "*\ConnectAppSetup*.exe", "*\ConnectShellSetup*.exe", "ConnectDetector.exe" }
        [pscustomobject]@{ Name = "AeroAdmin"; ProcessName = "AeroAdmin"; IndicatorFilename = "AeroAdmin.exe" }
        [PSCustomObject]@{ Name = "AliWangWang-remote-control"; DisplayName = "AliWangWang"; ProcessName = "alitask"; IndicatorFilename = "alitask.exe" }
        [PSCustomObject]@{ Name = "Alpemix"; DisplayName = "Alpemix"; ProcessName = "Alpemix", "AlpemixService"; FullIndicatorPath = "C:\AlpemixService.exe" }
        [pscustomobject]@{ Name = "Ammyy Admin"; ProcessName = "AA_v3" }
        [PSCustomObject]@{ Name = "Any Support"; DisplayName = "Any Support"; ProcessName = "ManualLauncher"; IndicatorFilename = "ManualLauncher.exe" }
        [pscustomobject]@{ Name = "AnyDesk"; DisplayName = "AnyDesk"; ProcessName = "AnyDesk"; IndicatorFilename = "AnyDesk.exe" }
        [PSCustomObject]@{ Name = "Anyplace Control"; DisplayName = "Anyplace Control"; ProcessName = "apc_host"; IndicatorFilename = "apc_host.exe" }
        [PSCustomObject]@{ Name = "AnyViewer"; DisplayName = "AnyViewer"; ProcessName = "AnyViewer"; IndicatorFilename = "AnyViewer.exe" }
        [pscustomobject]@{ Name = "Atera"; DisplayName = "AteraAgent"; ProcessName = "AteraAgent"; IndicatorFilename = "AteraAgent.exe", "atera_agent.exe", "syncrosetup.exe", "AgentPackageTaskScheduler.exe" }
        [pscustomobject]@{ Name = "Automate"; DisplayName = "Connectwise Automate"; ProcessName = "LTService", "LabTechService"; FullIndicatorPath = "C:\Windows\LTSvc\LTSvc.exe" }
        [PSCustomObject]@{ Name = "Auvik"; DisplayName = "Auvik"; ProcessName = "auvik.engine", "auvik.agent.exe"; IndicatorFilename = "auvik.engine.exe", "auvik.agent.exe" }
        [PSCustomObject]@{ Name = "AweRay"; DisplayName = "AweRay"; ProcessName = "AweSun"; IndicatorFilename = "AweSun.exe" }
        [PSCustomObject]@{ Name = "BeamYourScreen"; DisplayName = "BeamYourScreen"; ProcessName = "BeamYourScreen", "BeamYourScreen-Host" ; IndicatorFilename = "beamyourscreen.exe", "beamyourscreen-host.exe" }
        [PSCustomObject]@{ Name = "BeAnyWhere/TakeControl"; DisplayName = "BeAnyWhere"; ProcessName = "BASupApp", "BASupAppSrvc", "TakeControl"; IndicatorFilename = "basuptshelper.exe", "basupsrvcupdate.exe", "BASupApp.exe", "BASupSysInf.exe", "BASupAppSrvc.exe", "TakeControl.exe", "BASupAppElev.exe", "basupsrvc.exe" }
        [PSCustomObject]@{ Name = "BeInSync"; DisplayName = "BeInSync"; ProcessName = "BeInSync"; IndicatorFilename = "*\Beinsync*.exe" }
        [pscustomobject]@{ Name = "BeyondTrust (Bomgar)"; DisplayName = "Remote Support Jump Client", "Jumpoint"; ProcessName = "bomgar-jpt"; IndicatorFilename = "bomgar-pac.exe", "bomgar-rdp.exe", "bomgar-scc.exe" }
        [PSCustomObject]@{ Name = "Bitvise SSH Client/Server"; DisplayName = "Bitvise SSH"; ProcessName = "BvSshServer-Inst"; IndicatorFilename = "BvSshClient-Inst.exe", "BvSshServer-Inst.exe" }
        [PSCustomObject]@{ Name = "CarotDAV"; DisplayName = "CarotDAV"; ProcessName = "CarotDAV"; IndicatorFilename = "CarotDAV.exe" }
        [PSCustomObject]@{ Name = "CentraStage (Now Datto)"; DisplayName = "CentraStage"; ProcessName = "CagService"; IndicatorFilename = "CagService.exe", "AEMAgent.exe" }
        [PSCustomObject]@{ Name = "Centurion"; DisplayName = "Centurion"; ProcessName = "ctiserv"; IndicatorFilename = "ctiserv.exe" }
        [pscustomobject]@{ Name = "Chrome Remote Desktop"; DisplayName = "Chrome Remote Desktop Host"; ProcessName = "remoting_host"; IndicatorFilename = "remote_host.exe", "remoting_host.exe" }
        [PSCustomObject]@{ Name = "Chrome SSH Extension"; DisplayName = "Chrome SSH Extension"; FullIndicatorPath = "C:\Users\*\AppData\Local\Google\*\User Data\Default\Extensions\iodihamcpbpeioajjeobimgagajmlibd*" }
        [PSCustomObject]@{ Name = "CloudFlare Tunnel"; DisplayName = "CloudFlare Tunnel"; ProcessName = "cloudflared"; IndicatorFilename = "cloudflared.exe" }
        [PSCustomObject]@{ Name = "Comodo RMM"; DisplayName = "Comodo RMM"; ProcessName = "itsmagent", "rviewer"; IndicatorFilename = "itsmagent.exe", "rviewer.exe" }
        [PSCustomObject]@{ Name = "Connectwise Automate (LabTech)"; DisplayName = "Connectwise Automate"; ProcessName = "ltsvcmon"; IndicatorFilename = "ltsvc.exe", "ltsvcmon.exe", "lttray.exe" }
        [pscustomobject]@{ Name = "Connectwise Control/ScreenConnect"; DisplayName = "ScreenConnect Client", "connectwisecontrol.client", "screenconnect.windowsclient"; ProcessName = "ScreenConnect.ClientService"; IndicatorFilename = "ScreenConnect.WindowsClient.exe", "ScreenConnect.ClientService.exe", "connectwisechat-customer.exe", "connectwisecontrol.client.exe", "Remote Workforce Client.exe" }
        [PSCustomObject]@{ Name = "CrossLoop"; DisplayName = "CrossLoop"; ProcessName = "crossloopservice", "CrossLoopConnect"; IndicatorFilename = "crossloopservice.exe", "CrossLoopConnect.exe", "WinVNCStub.exe" }
        [PSCustomObject]@{ Name = "CrossTec Remote Control"; DisplayName = "CrossTec Remote Control"; ProcessName = "PCIVIDEO", "supporttool"; IndicatorFilename = "PCIVIDEO.EXE", "supporttool.exe" }
        [PSCustomObject]@{ Name = "DameWare"; DisplayName = "DameWare"; ProcessName = "dwrcs", "DameWare Remote Support"; IndicatorFilename = "dwrcs.exe", "dwrcst.exe", "DameWare Remote Support.exe" }
        [pscustomobject]@{ Name = "Datto RMM"; DisplayName = "Datto RMM"; ProcessName = "AEMAgent"; IndicatorFilename = "CentraStageAEMAgentAEMAgent.exe", "CentraStagegui.exe", "AEMAgent.exe" }
        [PSCustomObject]@{ Name = "DeskDay"; DisplayName = "DeskDay"; IndicatorFilename = "*\ultimate_*.exe" }
        [PSCustomObject]@{ Name = "DeskShare"; DisplayName = "DeskShare"; ProcessName = "DSGuest"; IndicatorFilename = "TeamTaskManager.exe", "DSGuest.exe" }
        [PSCustomObject]@{ Name = "DesktopNow"; DisplayName = "DesktopNow"; ProcessName = "DesktopNow"; IndicatorFilename = "desktopnow.exe" }
        [pscustomobject]@{ Name = "Distant Desktop"; DisplayName = "Distant Desktop"; ProcessName = "ddsystem", "distant-desktop"; IndicatorFilename = "ddsystem.exe", "distant-desktop.exe" }
        [PSCustomObject]@{ Name = "Domotz"; DisplayName = "Domotz"; ProcessName = "Domotz"; IndicatorFilename = "domotz.exe", "Domotz Pro Desktop App.exe", "domotz_bash.exe", "*\Domotz Pro Desktop App Setup*.exe", "*\domotz-windows*.exe" }
        [PSCustomObject]@{ Name = "DragonDisk"; DisplayName = "DragonDisk"; ProcessName = "DragonDisk"; IndicatorFilename = "DragonDisk.exe" }
        [PSCustomObject]@{ Name = "Duplicati"; DisplayName = "Duplicati"; ProcessName = "Duplicati"; IndicatorFilename = "Duplicati.Server.exe" }
        [PSCustomObject]@{ Name = "DW Service"; DisplayName = "DW Service"; ProcessName = "dwagsvc"; IndicatorFilename = "dwagsvc.exe", "dwagent.exe" }
        [pscustomobject]@{ Name = "DWService"; DisplayName = "DWAgent"; ProcessName = "dwagent", "dwagsvc"; IndicatorFilename = "dwagent.exe" }
        [PSCustomObject]@{ Name = "Echoware"; DisplayName = "Echoware"; ProcessName = "echoserver", "echoware"; IndicatorFilename = "echoserver.exe", "echoware.dll" }
        [PSCustomObject]@{ Name = "eHorus"; DisplayName = "eHorus"; ProcessName = "ehorus standalone"; IndicatorFilename = "ehorus standalone.exe" }
        [PSCustomObject]@{ Name = "EMCO Remote Console"; DisplayName = "EMCO Remote Console"; ProcessName = "remoteconsole"; IndicatorFilename = "remoteconsole.exe" }
        [PSCustomObject]@{ Name = "Ericom AccessNow"; DisplayName = "Ericom AccessNow"; ProcessName = "accessserver"; IndicatorFilename = "accessserver.exe" }
        [PSCustomObject]@{ Name = "Ericom Connect"; DisplayName = "Ericom Connect"; ProcessName = "ericomconnnectconfigurationtool"; IndicatorFilename = "ericomconnnectconfigurationtool.exe" }
        [PSCustomObject]@{ Name = "ESET Remote Administrator"; DisplayName = "ESET Remote Administrator"; ProcessName = "ERAAgent"; IndicatorFilename = "era.exe", "einstaller.exe", "*\ezhelp*.exe", "eratool.exe", "ERAAgent.exe" }
        [PSCustomObject]@{ Name = "ExtraPuTTY"; DisplayName = "ExtraPuTTY"; ProcessName = "ExtraPuTTY"; IndicatorFilename = "ExtraPuTTY-0.30-2016-01-28-installer.exe" }
        [PSCustomObject]@{ Name = "ezHelp"; DisplayName = "ezHelp"; ProcessName = "ezhelpclient"; IndicatorFilename = "ezhelpclientmanager.exe", "ezHelpManager.exe", "ezhelpclient.exe" }
        [PSCustomObject]@{ Name = "FastViewer"; DisplayName = "FastViewer"; ProcessName = "FastViewer"; IndicatorFilename = "fastclient.exe", "fastmaster.exe", "FastViewer.exe" }
        [PSCustomObject]@{ Name = "FixMe.it"; DisplayName = "FixMe.it"; ProcessName = "FixMeit Client"; IndicatorFilename = "FixMeit Client.exe", "TiExpertStandalone.exe", "TiExpertCore.exe", "FixMeit Unattended Access Setup.exe", "FixMeit Expert Setup.exe", "TiExpertCore.exe", "fixmeitclient.exe", "TiClientCore.exe" }
        [PSCustomObject]@{ Name = "FleetDeck.io"; DisplayName = "FleetDeck.io"; ProcessName = "fleetdeck_agent_svc"; IndicatorFilename = "fleetdeck_agent_svc.exe", "fleetdeck_commander_svc.exe", "fleetdeck_installer.exe", "fleetdeck_commander_launcher.exe", "fleetdeck_agent.exe" }
        [PSCustomObject]@{ Name = "FreeNX"; DisplayName = "FreeNX"; ProcessName = "nxplayer"; IndicatorFilename = "nxplayer.exe" }
        [PSCustomObject]@{ Name = "GatherPlace-desktop sharing"; DisplayName = "GatherPlace-desktop sharing"; ProcessName = "gp3", "gp4", "gp5"; IndicatorFilename = "gp3.exe", "gp4.exe", "gp5.exe" }
        [PSCustomObject]@{ Name = "GetScreen"; DisplayName = "GetScreen"; ProcessName = "GetScreen"; IndicatorFilename = "GetScreen.exe" }
        [PSCustomObject]@{ Name = "GoToAssist"; DisplayName = "GoToAssist"; ProcessName = "GoToAssist"; IndicatorFilename = "gotoassist.exe", "GoTo Assist Opener.exe" }
        [PSCustomObject]@{ Name = "GotoHTTP"; DisplayName = "GotoHTTP"; ProcessName = "GotoHTTP"; IndicatorFilename = "GotoHTTP_x64.exe", "gotohttp.exe", "*\GotoHTTP*.exe" }
        [pscustomobject]@{ Name = "GoToMyPC"; DisplayName = "GoToMyPC"; ProcessName = "g2comm", "g2pre", "g2svc", "g2tray"; IndicatorFilename = "g2comm.exe", "g2pre.exe", "g2svc.exe", "g2tray.exe" }
        [PSCustomObject]@{ Name = "Goverlan"; DisplayName = "Goverlan"; ProcessName = "goverrmc"; IndicatorFilename = "goverrmc.exe", "GovAgentInstallHelper.exe", "GovAgentx64.exe", "GovReachClient.exe", "GovSrv.exe" }
        [PSCustomObject]@{ Name = "Guacamole"; DisplayName = "Guacamole"; ProcessName = "guacd"; IndicatorFilename = "guacd.exe" }
        [PSCustomObject]@{ Name = "HelpBeam"; DisplayName = "HelpBeam"; ProcessName = "HelpBeam"; IndicatorFilename = "*\helpbeam*.exe" }
        [PSCustomObject]@{ Name = "HelpU"; DisplayName = "HelpU"; ProcessName = "HelpuManager"; IndicatorFilename = "helpu_install.exe", "HelpuUpdater.exe", "HelpuManager.exe" }
        [PSCustomObject]@{ Name = "I'm InTouch"; DisplayName = "I'm InTouch"; ProcessName = "intouch"; IndicatorFilename = "iit.exe", "intouch.exe", "I'm InTouch Go Installer.exe" }
        [PSCustomObject]@{ Name = "Impero Connect"; DisplayName = "Impero Connect"; ProcessName = "ImperoClientSVC"; IndicatorFilename = "ImperoClientSVC.exe" }
        [PSCustomObject]@{ Name = "Instant Housecall"; DisplayName = "Instant Housecall"; ProcessName = "InstantHousecall"; IndicatorFilename = "hsloader.exe", "InstantHousecall.exe", "ihcserver.exe", "ihcserver.exe" }
        [PSCustomObject]@{ Name = "Insync"; DisplayName = "Insync"; ProcessName = "Insync"; IndicatorFilename = "Insync.exe" }
        [PSCustomObject]@{ Name = "IntelliAdmin Remote Control"; DisplayName = "IntelliAdmin Remote Control"; ProcessName = "intelliadmin"; IndicatorFilename = "iadmin.exe", "intelliadmin.exe", "agent32.exe", "agent64.exe", "agent_setup_5.exe" }
        [PSCustomObject]@{ Name = "Iperius Remote"; DisplayName = "Iperius Remote"; ProcessName = "iperius", "iperiusremote"; IndicatorFilename = "iperius.exe", "iperiusremote.exe" }
        [PSCustomObject]@{ Name = "ISL Light/ISL Online"; DisplayName = "ISL Light"; ProcessName = "isllight"; IndicatorFilename = "islalwaysonmonitor.exe", "isllight.exe", "isllightservice.exe", "ISLLightClient.exe" }
        [PSCustomObject]@{ Name = "Itarian"; DisplayName = "Itarian"; ProcessName = "ITSMAgent"; IndicatorFilename = "ITSMAgent.exe", "RViewer.exe", "ItsmRsp.exe", "RAccess.exe", "RmmService.exe", "ITarianRemoteAccessSetup.exe", "RDesktop.exe", "ComodoRemoteControl.exe", "ITSMService.exe", "RHost.exe" }
        [PSCustomObject]@{ Name = "ITSupport247 (ConnectWise)"; DisplayName = "ITSupport247"; ProcessName = "saazapsc"; IndicatorFilename = "saazapsc.exe" }
        [PSCustomObject]@{ Name = "Ivanti Remote Control"; DisplayName = "Ivanti Remote Control"; ProcessName = "IvantiRemoteControl"; IndicatorFilename = "IvantiRemoteControl.exe", "ArcUI.exe", "AgentlessRC.exe" }
        [PSCustomObject]@{ Name = "Jump Cloud"; DisplayName = "Jump Cloud"; IndicatorFilename = "*\JumpCloud*.exe " }
        [PSCustomObject]@{ Name = "Jump Desktop"; DisplayName = "Jump Desktop"; ProcessName = "jumpclient", "jumpservice"; IndicatorFilename = "jumpclient.exe", "jumpdesktop.exe", "jumpservice.exe", "jumpconnect.exe", "jumpupdater.exe" }
        [PSCustomObject]@{ Name = "Kabuto"; DisplayName = "Kabuto"; ProcessName = "Kabuto.App.Runner"; IndicatorFilename = "Kabuto.App.Runner.exe" }
        [pscustomobject]@{ Name = "Kaseya"; DisplayName = "Kaseya Agent"; ProcessName = "AgentMon", "KaseyaRemoteControlHost", "Kasaya.AgentEndpoint"; IndicatorFilename = "AgentMon.exe" }
        [PSCustomObject]@{ Name = "KHelpDesk"; DisplayName = "KHelpDesk"; ProcessName = "KHelpDesk"; IndicatorFilename = "KHelpDesk.exe" }
        [PSCustomObject]@{ Name = "KickIdler"; DisplayName = "KickIdler"; IndicatorFilename = "*\grabberEM.*msi", "*\grabberTT*.msi" }
        [PSCustomObject]@{ Name = "KiTTY"; DisplayName = "KiTTY"; ProcessName = "KiTTY"; IndicatorFilename = "kitty.exe" }
        [PSCustomObject]@{ Name = "LANDesk"; DisplayName = "LANDesk"; ProcessName = "LANDeskPortalManager"; IndicatorFilename = "issuser.exe", "landeskagentbootstrap.exe", "LANDeskPortalManager.exe", "ldinv32.exe", "ldsensors.exe", "tmcsvc.exe" }
        [PSCustomObject]@{ Name = "Laplink Everywhere/Laplink Gold"; DisplayName = "Laplink Everywhere"; ProcessName = "laplink"; IndicatorFilename = "tsircusr.exe", "laplink.exe", "laplinkeverywhere.exe", "llrcservice.exe", "serverproxyservice.exe", "OOSysAgent.exe" }
        [PSCustomObject]@{ Name = "Level.io"; DisplayName = "Level.io"; ProcessName = "level-windows-amd64"; IndicatorFilename = "level-windows-amd64.exe", "level.exe", "level-remote-control-ffmpeg.exe" }
        [pscustomobject]@{ Name = "LiteManager Pro"; DisplayName = "LiteManager Pro - Server"; ProcessName = "ROMServer", "ROMFUSClient"; IndicatorFilename = "ROMFUSClient.exe", "ROMServer.exe" }
        [PSCustomObject]@{ Name = "LiteManager"; DisplayName = "LiteManager"; ProcessName = "lmnoipserver"; IndicatorFilename = "lmnoipserver.exe", "ROMFUSClient.exe", "romfusclient.exe", "romviewer.exe", "romserver.exe", "ROMServer.exe" }
        [PSCustomObject]@{ Name = "LogMeIn rescue"; DisplayName = "LogMeIn rescue"; ProcessName = "support-logmeinrescue", "lmi_rescue"; IndicatorFilename = "support-logmeinrescue.exe", "lmi_rescue.exe" }
        [pscustomobject]@{ Name = "LogMeIn"; DisplayName = "LogMeIn"; ProcessName = "LogMeIn", "lmiguardiansvc"; IndicatorFilename = "LogMeIn.exe", "LogMeInSystray.exe", "support-logmeinrescue.exe", "lmiguardiansvc.exe" }
        [PSCustomObject]@{ Name = "Manage Engine (Desktop Central)"; DisplayName = "ManageEngine"; ProcessName = "dcagentservice"; IndicatorFilename = "dcagentservice.exe", "dcagentregister.exe", "ManageEngine_Remote_Access_Plus.exe" }
        [pscustomobject]@{ Name = "ManageEngine"; DisplayName = "ManageEngine Remote Access Plus - Server", "ManageEngine UEMS - Agent"; ProcessName = "dcagenttrayicon", "UEMS"; IndicatorFilename = "dcagenttrayicon.exe", "UEMS.exe" }
        [PSCustomObject]@{ Name = "MEGAsync"; DisplayName = "MEGAsync"; ProcessName = "MEGAupdater"; IndicatorFilename = "MEGAsyncSetup64.exe", "MEGAupdater.exe" }
        [PSCustomObject]@{ Name = "MeshCentral"; DisplayName = "MeshCentral"; ProcessName = "MeshCentral"; IndicatorFilename = "MeshAgent.exe" }
        [PSCustomObject]@{ Name = "Microsoft Quick Assist"; DisplayName = "Microsoft Quick Assist"; ProcessName = "quickassist"; IndicatorFilename = "quickassist.exe" }
        [PSCustomObject]@{ Name = "Microsoft RDP/TSC"; DisplayName = "Microsoft RDP"; ProcessName = "termsrv"; IndicatorFilename = "termsrv.exe", "mstsc.exe" }
        [PSCustomObject]@{ Name = "Mikogo"; DisplayName = "Mikogo"; ProcessName = "Mikogo"; IndicatorFilename = "mikogo.exe", "mikogo-starter.exe", "mikogo-service.exe", "mikogolauncher.exe", "Mikogo-Screen-Service.exe" }
        [PSCustomObject]@{ Name = "MioNet (WD Anywhere Access)"; DisplayName = "MioNet"; ProcessName = "mionet"; IndicatorFilename = "mionet.exe", "mionetmanager.exe" }
        [PSCustomObject]@{ Name = "MobaXterm"; DisplayName = "MobaXterm"; IndicatorFilename = "*\Mobatek\MobaXterm\*" }
        [PSCustomObject]@{ Name = "mRemoteNG"; DisplayName = "mRemoteNG"; ProcessName = "mRemoteNG"; IndicatorFilename = "mRemoteNG.exe" }
        [PSCustomObject]@{ Name = "MSP360"; DisplayName = "MSP360"; ProcessName = "CBBackupPlan"; IndicatorFilename = "Online Backup.exe", "CBBackupPlan.exe", "Cloud.Backup.Scheduler.exe", "Cloud.Backup.RM.Service.exe", "cbb.exe", "CloudRaService.exe", "CloudRaSd.exe", "CloudRaCmd.exe", "CloudRaUtilities.exe", "Remote Desktop.exe" }
        [PSCustomObject]@{ Name = "MyGreenPC"; DisplayName = "MyGreenPC"; ProcessName = "MyGreenPC"; IndicatorFilename = "mygreenpc.exe" }
        [PSCustomObject]@{ Name = "MyIVO"; DisplayName = "MyIVO"; ProcessName = "myivomgr"; IndicatorFilename = "myivomgr.exe", "myivomanager.exe" }
        [pscustomobject]@{ Name = "N-Able N-Central"; DisplayName = "Windows Agent"; ProcessName = "winagent", "Windows Agent", "Windows Agent (32 bit)", "Windows Agent Service"; IndicatorFilename = "winagent.exe", "TakeControl.exe", "BASupApp.exe", "BASupAppElev.exe", "BASupAppSrvc.exe", "BASupSrvc.exe", "BASupSrvcCnfg.exe", "BASupSysInf.exe", "BASupTSHelper.exe", "basupsrvcupdate.exe" }
        [pscustomobject]@{ Name = "N-Able N-Sight"; DisplayName = "Advanced Monitoring Agent"; ProcessName = "winagent"; IndicatorFilename = "winagent.exe" }
        [PSCustomObject]@{ Name = "NateOn-desktop sharing"; DisplayName = "NateOn-desktop sharing"; ProcessName = "nateon"; IndicatorFilename = "nateon.exe", "nateonmain.exe" }
        [PSCustomObject]@{ Name = "Netop Remote Control (Impero Connect)"; DisplayName = "Netop Remote Control"; ProcessName = "Netop Ondemand", "nldrw32", "rmserverconsolemediator", "ImperoInit", "ImperoClientSVC"; IndicatorFilename = "nhostsvc.exe", "nhstw32.exe", "ngstw32.exe", "Netop Ondemand.exe", "nldrw32.exe", "rmserverconsolemediator.exe", "ImperoInit.exe", "ImperoClientSVC.exe" }
        [PSCustomObject]@{ Name = "NetSupport Manager"; DisplayName = "NetSupport Manager"; ProcessName = "pcictlui"; IndicatorFilename = "pcictlui.exe", "pcicfgui.exe", "client32.exe" }
        [PSCustomObject]@{ Name = "Neturo"; DisplayName = "Neturo"; ProcessName = "Neturo"; IndicatorFilename = "ntrntservice.exe", "neturo.exe" }
        [PSCustomObject]@{ Name = "Netviewer (GoToMeet)"; DisplayName = "Netviewer"; ProcessName = "netviewer"; IndicatorFilename = "nvClient.exe", "netviewer.exe" }
        [PSCustomObject]@{ Name = "ngrok"; DisplayName = "ngrok"; ProcessName = "ngrok"; IndicatorFilename = "ngrok.exe" }
        [pscustomobject]@{ Name = "Ninja RMM"; DisplayName = "Ninja RMM Agent"; ProcessName = "NinjaRMMAgent"; IndicatorFilename = "NinjaRMMAgenPatcher.exe", "NinjaRMMAgent.exe", "ninjarmm-cli.exe" }
        [pscustomobject]@{ Name = "NoMachine"; DisplayName = "NoMachine"; ProcessName = "nxd", "nxnode.bin", "nxserver.bin", "nxservice64", "nxservice"; IndicatorFilename = "nxd.exe", "nxnode.bin", "nxserver.bin", "nxservice64.exe", "*\nomachine*.exe", "*\nxservice*.exe" }
        [PSCustomObject]@{ Name = "NoteOn-desktop sharing"; DisplayName = "NoteOn-desktop sharing"; ProcessName = "nateon"; IndicatorFilename = "nateon.exe", "nateonmain.exe" }
        [PSCustomObject]@{ Name = "NTR Remote"; DisplayName = "NTR Remote"; ProcessName = "NTRsupportPro_EN"; IndicatorFilename = "NTRsupportPro_EN.exe" }
        [PSCustomObject]@{ Name = "OCS inventory"; DisplayName = "OCS inventory"; ProcessName = "ocsservice"; IndicatorFilename = "ocsinventory.exe", "ocsservice.exe" }
        [PSCustomObject]@{ Name = "Onionshare"; DisplayName = "Onionshare"; ProcessName = "Onionshare"; IndicatorFilename = "*\OnionShare\*", "*\onionshare*.exe" }
        [PSCustomObject]@{ Name = "OptiTune"; DisplayName = "OptiTune"; ProcessName = "OTService"; IndicatorFilename = "OTService.exe", "OTPowerShell.exe" }
        [PSCustomObject]@{ Name = "Pandora RC (eHorus)"; DisplayName = "Pandora RC"; ProcessName = "ehorus_agent"; IndicatorFilename = "ehorus standalone.exe", "ehorus_agent.exe" }
        [PSCustomObject]@{ Name = "Panorama9"; DisplayName = "Panorama9"; ProcessName = "Panorama9"; IndicatorFilename = "*\p9agent*.exe" }
        [PSCustomObject]@{ Name = "Parallels Access"; DisplayName = "Parallels Access"; ProcessName = "prl_deskctl_agent", "prl_pm_service"; IndicatorFilename = "TSClient.exe", "prl_deskctl_agent.exe", "prl_deskctl_wizard.exe", "prl_pm_service.exe" }
        [pscustomobject]@{ Name = "Parsec"; DisplayName = "Parsec"; ProcessName = "parsecd", "pservice"; IndicatorFilename = "parsecd.exe", "pservice.exe" }
        [PSCustomObject]@{ Name = "pcAnywhere"; DisplayName = "pcAnywhere"; ProcessName = "pcaquickconnect"; IndicatorFilename = "awhost32.exe", "awrem32.exe", "pcaquickconnect.exe", "winaw32.exe" }
        [PSCustomObject]@{ Name = "Pcnow"; DisplayName = "Pcnow"; ProcessName = "pcnmgr"; IndicatorFilename = "mwcliun.exe", "pcnmgr.exe", "webexpcnow.exe" }
        [PSCustomObject]@{ Name = "Pcvisit"; DisplayName = "Pcvisit"; ProcessName = "pcvisit_client"; IndicatorFilename = "pcvisit.exe", "pcvisit_client.exe", "pcvisit-easysupport.exe", "pcvisit_service_client.exe" }
        [PSCustomObject]@{ Name = "PDQ Connect"; DisplayName = "PDQ Connect"; ProcessName = "PDQ Connect"; IndicatorFilename = "*\pdq-connect*.exe" }
        [PSCustomObject]@{ Name = "Pilixo"; DisplayName = "Pilixo"; IndicatorFilename = "*\Pilixo_Installer*.exe" }
        [PSCustomObject]@{ Name = "Pocket Cloud/Pocket Controller/Wyse"; DisplayName = "Pocket Cloud"; ProcessName = "pocketcloudservice"; IndicatorFilename = "pocketcontroller.exe", "pocketcloudservice.exe", "wysebrowser.exe", "XSightService.exe" }
        [PSCustomObject]@{ Name = "PSEXEC"; DisplayName = "PSEXEC"; ProcessName = "PSEXEC"; IndicatorFilename = "psexec.exe", "psexecsvc.exe", "paexec.exe", "csexec.exe ", "remcom.exe", "remcomsvc.exe", "xcmd.exe", "xcmdsvc.exe" }
        [PSCustomObject]@{ Name = "Pulseway"; DisplayName = "Pulseway"; ProcessName = "pcmonitorsrv"; IndicatorFilename = "PCMonitorManager.exe", "pcmonitorsrv.exe" }
        [PSCustomObject]@{ Name = "PuTTY Tray"; DisplayName = "PuTTY Tray"; ProcessName = "puttytray"; IndicatorFilename = "puttytray.exe" }
        [PSCustomObject]@{ Name = "QQ IM-remote assistance"; DisplayName = "QQ IM-remote assistance"; ProcessName = "QQProtect"; IndicatorFilename = "qq.exe", "QQProtect.exe", "qqpcmgr.exe" }
        [PSCustomObject]@{ Name = "Quest KACE Agent (formerly Dell KACE)"; DisplayName = "Quest KACE Agent"; ProcessName = "konea"; IndicatorFilename = "konea.exe" }
        [PSCustomObject]@{ Name = "Quick Assist"; DisplayName = "Quick Assist"; ProcessName = "quickassist"; IndicatorFilename = "quickassist.exe" }
        [PSCustomObject]@{ Name = "RAdmin"; DisplayName = "RAdmin"; ProcessName = "Radmin"; IndicatorFilename = "RServer3.exe", "Radmin.exe", "rserver3.exe" }
        [PSCustomObject]@{ Name = "Rapid7"; DisplayName = "Rapid7"; ProcessName = "ir_agent"; IndicatorFilename = "ir_agent.exe", "rapid7_agent_core.exe", "rapid7_endpoint_broker.exe" }
        [PSCustomObject]@{ Name = "rdp2tcp"; DisplayName = "rdp2tcp"; ProcessName = "tdp2tcp"; IndicatorFilename = "tdp2tcp.exe", "rdp2tcp.py" }
        [PSCustomObject]@{ Name = "RDPView"; DisplayName = "RDPView"; ProcessName = "dwrcs"; IndicatorFilename = "dwrcs.exe" }
        [PSCustomObject]@{ Name = "rdpwrap"; DisplayName = "rdpwrapper"; ProcessName = "RDPCheck"; IndicatorFilename = "RDPWInst.exe", "RDPCheck.exe", "RDPConf.exe" }
        [PSCustomObject]@{ Name = "Remcos"; DisplayName = "Remcos"; ProcessName = "Remcos"; IndicatorFilename = "*\remcos*.exe" }
        [PSCustomObject]@{ Name = "Remobo"; DisplayName = "Remobo"; ProcessName = "remobo"; IndicatorFilename = "remobo.exe", "remobo_client.exe", "remobo_tracker.exe" }
        [PSCustomObject]@{ Name = "Remote Desktop Plus"; DisplayName = "Remote Desktop Plus"; IndicatorFilename = "rdp.exe" }
        [PSCustomObject]@{ Name = "Remote Manipulator System"; DisplayName = "Remote Manipulator System"; ProcessName = "rfusclient"; IndicatorFilename = "rfusclient.exe", "rutserv.exe" }
        [pscustomobject]@{ Name = "Remote Utilities - Host"; DisplayName = "Remote Utilities - Host"; ProcessName = "rutserv", "rfusclient"; IndicatorFilename = "rfusclient.exe" }
        [PSCustomObject]@{ Name = "Remote Utilities"; DisplayName = "Remote Utilities"; ProcessName = "rutserv"; IndicatorFilename = "rutview.exe", "rutserv.exe" }
        [PSCustomObject]@{ Name = "Remote.it"; DisplayName = "Remote.it"; ProcessName = "Remote.it"; IndicatorFilename = "remote-it-installer.exe", "remote.it.exe", "remoteit.exe" }
        [PSCustomObject]@{ Name = "RemoteCall"; DisplayName = "RemoteCall"; ProcessName = "rcmgrsvc"; IndicatorFilename = "rcengmgru.exe", "rcmgrsvc.exe", "rxstartsupport.exe", "rcstartsupport.exe", "raautoup.exe", "agentu.exe", "remotesupportplayeru.exe" }
        [PSCustomObject]@{ Name = "RemotePass"; DisplayName = "RemotePass"; ProcessName = "rpaccess"; IndicatorFilename = "remotepass-access.exe", "rpaccess.exe", "rpwhostscr.exe" }
        [PSCustomObject]@{ Name = "RemotePC"; DisplayName = "RemotePC"; ProcessName = "RemotePC", "RemotePCHostUI", "RPCPerformanceService"; IndicatorFilename = "remotepcservice.exe", "RemotePC.exe", "remotepchost.exe", "idrive.RemotePCAgent", "rpcsuite.exe", "RemotePCHostUI.exe", "RPCPerformanceService.exe" }
        [PSCustomObject]@{ Name = "RemoteUtilities"; DisplayName = "RemoteUtilities"; ProcessName = "rutview"; IndicatorFilename = "rutview.exe", "rutserv.exe" }
        [PSCustomObject]@{ Name = "RemoteView"; DisplayName = "RemoteView"; ProcessName = "remoteview"; IndicatorFilename = "remoteview.exe", "rv.exe", "rvagent.exe", "rvagtray.exe" }
        [PSCustomObject]@{ Name = "RES Automation Manager"; DisplayName = "RES Automation Manager"; ProcessName = "wmc_deployer"; IndicatorFilename = "wmc.exe", "wmc_deployer.exe", "wmcsvc.exe" }
        [PSCustomObject]@{ Name = "Rocket Remote Desktop"; DisplayName = "Rocket Remote Desktop"; ProcessName = "RDConsole"; IndicatorFilename = "RDConsole.exe", "RocketRemoteDesktop_Setup.exe" }
        [PSCustomObject]@{ Name = "Royal Apps"; DisplayName = "Royal Apps"; ProcessName = "royalserver"; IndicatorFilename = "royalserver.exe", "royalts.exe" }
        [PSCustomObject]@{ Name = "Royal TS"; DisplayName = "Royal TS"; ProcessName = "royalts"; IndicatorFilename = "royalts.exe" }
        [PSCustomObject]@{ Name = "RPort"; DisplayName = "RPort"; ProcessName = "RPort"; IndicatorFilename = "rport.exe" }
        [PSCustomObject]@{ Name = "RuDesktop"; DisplayName = "RuDesktop"; ProcessName = "RuDesktop"; IndicatorFilename = "rd.exe", "*\rudesktop*.exe" }
        [pscustomobject]@{ Name = "RustDesk"; DisplayName = "RustDesk"; ProcessName = "rustdesk"; IndicatorFilename = "rustdesk.exe" }
        [PSCustomObject]@{ Name = "S3 Browser"; DisplayName = "S3 Browser"; ProcessName = "S3 Browser"; IndicatorFilename = "*\S3 Browser\*", "*\s3browser*.exe" }
        [PSCustomObject]@{ Name = "ScreenMeet"; DisplayName = "ScreenMeet"; ProcessName = "ScreenMeetSupport"; IndicatorFilename = "ScreenMeetSupport.exe", "ScreenMeet.Support.exe" }
        [PSCustomObject]@{ Name = "SecureCRT"; DisplayName = "SecureCRT"; ProcessName = "SecureCRT"; IndicatorFilename = "SecureCRT.EXE" }
        [PSCustomObject]@{ Name = "Seetrol"; DisplayName = "Seetrol"; ProcessName = "seetrolclient"; IndicatorFilename = "seetrolcenter.exe", "seetrolclient.exe", "seetrolmyservice.exe", "seetrolremote.exe", "seetrolsetting.exe" }
        [PSCustomObject]@{ Name = "Senso.cloud"; DisplayName = "Senso.cloud"; ProcessName = "SensoClient"; IndicatorFilename = "SensoClient.exe", "SensoService.exe", "aadg.exe" }
        [PSCustomObject]@{ Name = "ServerEye"; DisplayName = "ServerEye"; ProcessName = "ServiceProxyLocalSys"; IndicatorFilename = "ServiceProxyLocalSys.exe" }
        [PSCustomObject]@{ Name = "ShowMyPC"; DisplayName = "ShowMyPC"; ProcessName = "showmypc"; IndicatorFilename = "SMPCSetup.exe", "showmypc.exe", "smpcsetup.exe" }
        [PSCustomObject]@{ Name = "SimpleHelp"; DisplayName = "SimpleHelp"; ProcessName = "simpleservice"; IndicatorFilename = "simplehelpcustomer.exe", "simpleservice.exe", "simplegatewayservice.exe", "remote access.exe" }
        [PSCustomObject]@{ Name = "Site24x7"; DisplayName = "Site24x7"; ProcessName = "Site24x7PluginAgent"; IndicatorFilename = "MEAgentHelper.exe", "MonitoringAgent.exe", "Site24x7WindowsAgentTrayIcon.exe", "Site24x7PluginAgent.exe" }
        [PSCustomObject]@{ Name = "SkyFex"; DisplayName = "SkyFex"; ProcessName = "Deskroll"; IndicatorFilename = "Deskroll.exe", "DeskRollUA.exe" }
        [PSCustomObject]@{ Name = "SmartFTP"; DisplayName = "SmartFTP"; ProcessName = "SmartFTP"; IndicatorFilename = "*\SmartFTP Client\*" }
        [PSCustomObject]@{ Name = "SmarTTY"; DisplayName = "SmarTTY"; ProcessName = "SmarTTY"; IndicatorFilename = "SmarTTY.exe" }
        [PSCustomObject]@{ Name = "Solar-PuTTY"; DisplayName = "Solar-PuTTY"; ProcessName = "Solar-PuTTY"; IndicatorFilename = "Solar-PuTTY.exe" }
        [PSCustomObject]@{ Name = "Sophos-Remote Management System"; DisplayName = "Sophos-Remote Management System"; ProcessName = "clientmrinit"; IndicatorFilename = "clientmrinit.exe", "mgntsvc.exe", "routernt.exe" }
        [PSCustomObject]@{ Name = "Sorillus"; DisplayName = "Sorillus"; ProcessName = "Sorillus Launcher"; IndicatorFilename = "Sorillus Launcher.exe" }
        [pscustomobject]@{ Name = "Splashtop Streamer"; DisplayName = "Splashtop Streamer"; ProcessName = "SRAgent", "SRAppPB", "SRFeature", "SRManager", "SRService"; IndicatorFilename = "SRService.exe", "SplashtopSOS.exe" }
        [PSCustomObject]@{ Name = "Splashtop"; DisplayName = "Splashtop"; ProcessName = "srservice"; IndicatorFilename = "SRServer.exe", "SRManager.exe", "strwinclt.exe", "SplashtopSOS.exe", "sragent.exe", "srservice.exe" }
        [PSCustomObject]@{ Name = "SpyAnywhere"; DisplayName = "SpyAnywhere"; ProcessName = "sysdiag"; IndicatorFilename = "sysdiag.exe" }
        [PSCustomObject]@{ Name = "SunLogin"; DisplayName = "SunLogin"; ProcessName = "OrayRemoteService"; IndicatorFilename = "OrayRemoteShell.exe", "OrayRemoteService.exe" }
        [PSCustomObject]@{ Name = "SuperOps"; DisplayName = "SuperOps"; ProcessName = "superops"; IndicatorFilename = "superopsticket.exe", "superops.exe" }
        [PSCustomObject]@{ Name = "SuperPuTTY"; DisplayName = "SuperPuTTY"; ProcessName = "SuperPuTTY"; IndicatorFilename = "superputty.exe" }
        [PSCustomObject]@{ Name = "Supremo"; DisplayName = "Supremo"; ProcessName = "Supremo", "SupremoHelper", "SupremoService"; IndicatorFilename = "supremo.exe", "supremoservice.exe", "supremosystem.exe", "supremohelper.exe" }
        [pscustomobject]@{ Name = "Syncro"; DisplayName = "Syncro", "Kabuto"; ProcessName = "Syncro.App.Runner", "Kabuto.App.Runner", "Syncro.Service.Runner", "Kabuto.Service.Runner", "SyncroLive.Agent.Runner", "Kabuto.Agent.Runner", "SyncroLive.Agent.Service", "Syncro.Access.Service", "Syncro.Access.App"; IndicatorFilename = "Syncro.Service.Runner.exe", "Syncro.App.Runner.exe", "Syncro.Installer.exe", "Syncro.Overmind.Service.exe", "Syncro.Service.exe", "SyncroLive.Agent.exe", "SyncroLive.Service.exe" }
        [PSCustomObject]@{ Name = "Syncro"; DisplayName = "Syncro"; ProcessName = "Syncro.Service"; IndicatorFilename = "Syncro.Installer.exe", "Kabuto.App.Runner.exe", "Syncro.Overmind.Service.exe", "Kabuto.Installer.exe", "KabutoSetup.exe", "Syncro.Service.exe", "Kabuto.Service.Runner.exe", "Syncro.App.Runner.exe", "SyncroLive.Service.exe", "SyncroLive.Agent.exe" }
        [PSCustomObject]@{ Name = "Syncthing"; DisplayName = "Syncthing"; ProcessName = "Syncthing"; IndicatorFilename = "Syncthing.exe" }
        [PSCustomObject]@{ Name = "SysAid"; DisplayName = "SysAid"; ProcessName = "IliAS"; IndicatorFilename = "IliAS.exe" }
        [PSCustomObject]@{ Name = "Syspectr"; DisplayName = "Syspectr"; ProcessName = "OOSysAgent"; IndicatorFilename = "OOSysAgent.exe" }
        [PSCustomObject]@{ Name = "Tactical RMM"; DisplayName = "Tactical RMM"; ProcessName = "tacticalrmm"; IndicatorFilename = "tacticalrmm.exe" }
        [PSCustomObject]@{ Name = "Tailscale"; DisplayName = "Tailscale"; ProcessName = "tailscaled"; IndicatorFilename = "tailscaled.exe", "tailscale-ipn.exe" }
        [PSCustomObject]@{ Name = "Tanium"; DisplayName = "Tanium"; ProcessName = "TaniumClient"; IndicatorFilename = "TaniumClient.exe", "TaniumCX.exe", "TaniumExecWrapper.exe", "TaniumFileInfo.exe", "TPowerShell.exe" }
        [pscustomobject]@{ Name = "TeamViewer"; DisplayName = "TeamViewer"; ProcessName = "TeamViewer", "TeamViewer_Service", "tv_w32", "tv_x64"; IndicatorFilename = "TeamViewer.exe", "TeamViewer_Service.exe", "tv_w32.exe", "tv_x64.exe", "teamviewer_desktop.exe" }
        [PSCustomObject]@{ Name = "TeleDesktop"; DisplayName = "TeleDesktop"; ProcessName = "ptdskclient"; IndicatorFilename = "pstlaunch.exe", "ptdskclient.exe", "ptdskhost.exe" }
        [PSCustomObject]@{ Name = "TigerVNC/TightVNC/Web VNC/etc."; DisplayName = "TigerVNC"; ProcessName = "tvnserver"; IndicatorFilename = "winvnc4.exe", "tvnviewer.exe", "*\TightVNCViewerPortable*.exe", "tvnserver.exe", "*\TightVNC\*" }
        [PSCustomObject]@{ Name = "ToDesk"; DisplayName = "ToDesk"; ProcessName = "ToDesk"; IndicatorFilename = "todesk.exe", "ToDesk_Service.exe", "ToDesk_Setup.exe" }
        [PSCustomObject]@{ Name = "Total Software Deployment"; DisplayName = "Total Software Deployment"; ProcessName = "Tsdservice"; IndicatorFilename = "tniwinagent.exe", "Tsdservice.exe" }
        [PSCustomObject]@{ Name = "TurboMeeting"; DisplayName = "TurboMeeting"; ProcessName = "TurboMeeting"; IndicatorFilename = "pcstarter.exe", "turbomeeting.exe", "turbomeetingstarter.exe" }
        [PSCustomObject]@{ Name = "Ultra VNC"; DisplayName = "Ultra VNC"; ProcessName = "UVNC_Launch", "winvnc"; IndicatorFilename = "UVNC_Launch.exe", "winvnc.exe", "vncviewer.exe" }
        [PSCustomObject]@{ Name = "UltraViewer"; DisplayName = "UltraViewer"; ProcessName = "UltraViewer"; IndicatorFilename = "ultraviewer.exe", "UltraViewer_Desktop.exe", "ultraviewer_service.exe" }
        [PSCustomObject]@{ Name = "UltraVNC"; DisplayName = "UltraVNC"; ProcessName = "UltraVNC"; IndicatorFilename = "*\UltraVNC*.exe" }
        [pscustomobject]@{ Name = "VNC Connect (RealVNC)"; DisplayName = "VNC Server"; ProcessName = "vncserver"; IndicatorFilename = "vncserver.exe", "vncserverui.exe", "vncviewer.exe" }
        [PSCustomObject]@{ Name = "VNC"; DisplayName = "VNC"; ProcessName = "vncserver"; IndicatorFilename = "vncserver.exe", "winwvc.exe", "winvncsc.exe", "vncserverui.exe", "vncviewer.exe", "winvnc.exe" }
        [PSCustomObject]@{ Name = "WebRDP"; DisplayName = "WebRDP"; ProcessName = "WebRDP"; IndicatorFilename = "webrdp.exe" }
        [PSCustomObject]@{ Name = "Weezo"; DisplayName = "Weezo"; ProcessName = "Weezo"; IndicatorFilename = "weezohttpd.exe", "weezo.exe" }
        [PSCustomObject]@{ Name = "WinSCP"; DisplayName = "WinSCP"; ProcessName = "WinSCP"; IndicatorFilename = "WinSCP.exe" }
        [PSCustomObject]@{ Name = "Xeox"; DisplayName = "Xeox"; ProcessName = "xeox-agent_x64"; IndicatorFilename = "xeox-agent_x64.exe", "xeox_service_windows.exe", "xeox-agent_x86.exe" }
        [PSCustomObject]@{ Name = "Xpra"; DisplayName = "Xpra"; ProcessName = "Xpra-Launcher"; IndicatorFilename = "Xpra-Launcher.exe", "*Xpra-x86_64_Setup.exe" }
        [PSCustomObject]@{ Name = "Xshell"; DisplayName = "Xshell"; ProcessName = "Xshell"; IndicatorFilename = "xShell.exe" }
        [PSCustomObject]@{ Name = "Yandex.Disk"; DisplayName = "Yandex.Disk"; ProcessName = "YandexDisk2"; IndicatorFilename = "YandexDisk2.exe" }
        [PSCustomObject]@{ Name = "Zabbix Agent"; DisplayName = "Zabbix Agent"; ProcessName = "Zabbix Agent"; IndicatorFilename = "*\zabbix_agent*.exe" }
        [PSCustomObject]@{ Name = "ZeroTier"; DisplayName = "ZeroTier"; ProcessName = "zerotier-one_x64", "zero-powershell"; IndicatorFilename = "zerotier-one_x64.exe", "zero-powershell.exe" }
        [PSCustomObject]@{ Name = "ZOC"; DisplayName = "ZOC"; ProcessName = "ZOC"; IndicatorFilename = "zoc.exe" }
        [pscustomobject]@{ Name = "Zoho Assist"; DisplayName = "Zoho Assist Unattended Agent"; ProcessName = "ZohoURS", "ZohoURSService"; IndicatorFilename = "ZohoURS.exe", "ZohoURSService.exe", "zohotray.exe", "ZohoMeeting.exe" }
        [PSCustomObject]@{ Name = "Zoho Assist"; DisplayName = "Zoho Assist"; ProcessName = "ZMAgent"; IndicatorFilename = "ZMAgent.exe", "ZA_Access.exe", "ZohoMeeting.exe", "Zohours.exe", "zohotray.exe", "ZohoURSService.exe", "Zaservice.exe", "za_connect.exe" }
    )
    #endregion initialization
}

process {
    #region main
    #$RandSeconds = Get-Random -Minimum 1 -Maximum $RandMax
    #Write-Output "Waiting $RandSeconds seconds (between 1 and $RandMax) to stagger execution across devices`n"
    #Start-Sleep -Seconds $RandSeconds

    Write-Output "Starting search for Remote Access Software on $ComputerName..."

    # Search for remote access software by each method - process, service, uninstall string, filenames
    $RemoteAccessSoftware = $RASList | ForEach-Object {

        $ProcessStatus = if ($_.ProcessName) {
            $_.ProcessName | Find-Process
        }

        $ServiceStatus = if ($_.ProcessName) {
            $_.ProcessName | Find-Service
        }

        $UninstallKey = if ($_.DisplayName) {
            $_.DisplayName | Find-UninstallKey
        }
        $UninstallInfo = if ($_.DisplayName) {
            $_.DisplayName | Find-UninstallKey -UninstallString
        }

        $FilePaths = if ($_.IndicatorFilename) {
            $_.IndicatorFilename | Find-Executable
        } elseif ($_.FullIndicatorPath) {
            $_.FullIndicatorPath | Find-Executable -Full
        }

        if ($UninstallKey -or $ProcessStatus -or $FilePaths -or $ServiceStatus) {
            $Present = "Yes"
        } else {
            $Present = "No"
        }

        [pscustomobject]@{
            Name            = $_.Name
            Present         = $Present
            RunningProcess  = if ($ProcessStatus) { $ProcessStatus } else { "N/A" }
            RunningService  = if ($ServiceStatus) { $ServiceStatus } else { "N/A" }
            UninstallString = if ($UninstallInfo) { $UninstallInfo } else { "N/A" }
            FilePaths       = if ($FilePaths) { $FilePaths } else { "N/A" }
        }
    }

    if ($ExcludeTools) {
        Write-Output "Software excluded from report this run:"
        $ExcludeTools | Sort-Object | Format-Table
        $RemoteAccessSoftware = $RemoteAccessSoftware | Where-Object { $ExcludeTools -notcontains $_.Name }
    }

    $ActiveRemoteAccessSoftware = $RemoteAccessSoftware | Where-Object { $_.Present -eq "Yes" }

    if ($ActiveRemoteAccessSoftware) {

        #$ActiveRemoteAccessSoftware | Select-Object -Property Name, RunningProcess, RunningService, UninstallString, FilePaths | Sort-Object Name | Format-Table -AutoSize -Wrap
        $ActiveRemoteAccessSoftware | Select-Object -Property Name, @{ Name = "RunningProcess"; expression = { $_.RunningProcess -join ', ' } }, @{ Name = "RunningService"; expression = { $_.RunningService -join ', ' } }, @{ Name = "UninstallString"; expression = { $_.UninstallString -join ', ' } }, @{ Name = "FilePaths"; expression = { $_.FilePaths -join ', ' } } | Sort-Object Name | Format-List

        $ActiveRemoteAccessSoftware | Select-Object -Property @{ Name = "ComputerName"; expression = { $ComputerName } }, Name, @{ Name = "RunningProcess"; expression = { $_.RunningProcess -join ', ' } }, @{ Name = "RunningService"; expression = { $_.RunningService -join ', ' } }, @{ Name = "UninstallString"; expression = { $_.UninstallString -join ', ' } }, @{ Name = "FilePaths"; expression = { $_.FilePaths -join ', ' } } | Sort-Object Name | Export-Csv -Path $ExportCSV -NoTypeInformation -Encoding utf8

        $MyExitStatus = 99
    } else {
        Write-Output "No unexcluded remote access software found."
        $MyExitStatus = 0
    }

    Write-Output "Done!"
    #endregion main
}

end {
    #region finalization
    if ($logFileFolderPath -ne "") {
        Write-Output "`nScript $scriptName ended at $(Get-TimeStamp)"
        $elapsedTime = $(Get-Date) - $StartTime
        Write-Output "Elapsed time (seconds): $($elapsedTime.TotalSeconds)"
        Stop-Transcript
        if (($emailServer -ne "") -and ($emailUsername -ne "") -and ($emailPassword -ne "") -and ($emailFrom -ne "") -and ($emailTo -ne "")) {
            Send-MailMessage -SmtpServer "$emailServer" -Port 587 -From "$emailFrom" -To "$emailTo" -Subject "$scriptName - $ComputerName - $MyExitStatus - Log File" -Body "$logFilePath" -UseSsl -Credential (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$emailUsername", (ConvertTo-SecureString -String "$emailPassword" -AsPlainText -Force)) -Attachments $logFilePath, $ExportCSV
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
