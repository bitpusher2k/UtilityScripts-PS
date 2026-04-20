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
# Uninstall-AppByName.ps1 - By Bitpusher/The Digital Fox
# v1.1 last updated 2026-04-18
#
# Improved version of UninstallX.ps1. Uninstalls applications by name using
# multiple methods in sequence:
#  1. Registry-based uninstall string (MSI via msiexec, NSIS/Inno via UninstallString)
#  2. winget (Windows Package Manager) - if available
#  3. WMI Win32_Product (as last resort - known slow, not recommended for primary use)
# Supports partial name matching. TestMode prevents actual uninstallation.
# Covers applications that are not MSI-based (NSIS, Inno Setup, etc.) as well as
# modern apps installable via winget.
#
# NOTE: If PartialName flag is enabled script will attempt to uninstall ALL applications
# whose name contains the given AppName string.
#
# Usage:
# powershell -executionpolicy bypass -f .\Uninstall-AppByName.ps1 -AppName "Microsoft Silverlight" -PartialName 0
# powershell -executionpolicy bypass -f .\Uninstall-AppByName.ps1 -AppName "Adobe" -PartialName 1
# powershell -executionpolicy bypass -f .\Uninstall-AppByName.ps1 -AppName "TeamViewer" -PartialName 1 -UseWinget 1
#
# Test run without actual uninstall:
# powershell -executionpolicy bypass -f .\Uninstall-AppByName.ps1 -AppName "Adobe" -PartialName 1 -TestMode 1
#
# Email log to yourself by including the emailServer, emailFrom, emailTo,
# emailUsername, and emailPassword parameters.
#
# Run with admin privileges.
#
#uninstall #name #script #powershell #comp #msi #msiexec #winget #nsis #inno

#Requires -Version 5.1

param(
    [Parameter(Mandatory = $true)]
    [string]$AppName = "",
    [int]$PartialName = 0,                         # 1 = partial name match; 0 = exact match
    [int]$TestMode = 0,                            # 1 = dry run (no actual uninstall)
    [int]$UseWinget = 1,                           # 1 = also attempt winget uninstall
    [int]$SilentMode = 1,                          # 1 = pass /S or /silent flags to non-MSI uninstallers
    [string]$scriptName = "Uninstall-AppByName",
    [string]$Priority = "Normal",
    [int]$RandMax = "5",
    [string]$DebugPreference = "SilentlyContinue",
    [string]$VerbosePreference = "SilentlyContinue",
    [string]$InformationPreference = "Continue",
    [string]$logFileFolderPath = "C:\temp\log",
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

    if ($TestMode -eq 1) { Write-Output "*** TEST MODE ENABLED - No changes will be made ***`n" }
    if ($AppName -eq "") { Write-Warning "AppName parameter is required."; exit 1 }

    $UninstallAttempted = 0
    $UninstallSucceeded = 0

    # ----------------------------------------------------------------
    # Method 1: Registry-based uninstall strings (MSI, NSIS, Inno, etc.)
    # ----------------------------------------------------------------
    $RegistryPaths = @(
        "Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    if ($PartialName -eq 1) {
        Write-Output "$(Get-TimeStamp) Checking registry for apps with name containing '$AppName'..."
        $appList = Get-ChildItem $RegistryPaths -ErrorAction SilentlyContinue | Get-ItemProperty -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like "*$AppName*" -and $_.UninstallString }
    } else {
        Write-Output "$(Get-TimeStamp) Checking registry for app with exact name '$AppName'..."
        $appList = Get-ChildItem $RegistryPaths -ErrorAction SilentlyContinue | Get-ItemProperty -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -eq $AppName -and $_.UninstallString }
    }

    if ($appList) {
        Write-Output "$(Get-TimeStamp) Found $($appList.Count) registry match(es):"
        foreach ($app in $appList) {
            Write-Output "  Name: $($app.DisplayName) | Version: $($app.DisplayVersion) | Publisher: $($app.Publisher)"
            Write-Output "  UninstallString: $($app.UninstallString)"
            $UninstallAttempted++

            if ($TestMode -eq 1) { Write-Output "  [TestMode] Would attempt uninstall."; continue }

            $uninstStr = $app.UninstallString
            $guid = if ($uninstStr -match "\{[0-9A-Fa-f\-]+\}") { $Matches[0] } else { "" }

            if ($guid -ne "" -or $uninstStr -ilike "*msiexec*") {
                # MSI uninstall
                $msiArgs = if ($guid) { "/x $guid /qn /norestart" } else { ($uninstStr -replace "msiexec.exe", "").Trim() + " /qn /norestart" }
                Write-Output "  $(Get-TimeStamp) Running msiexec: msiexec.exe $msiArgs"
                $exitCode = (Start-Process "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru -ErrorAction SilentlyContinue).ExitCode
                Write-Output "  $(Get-TimeStamp) msiexec exit code: $exitCode"
                if ($exitCode -eq 0 -or $exitCode -eq 3010) { $UninstallSucceeded++ }
            } else {
                # Non-MSI uninstaller (NSIS, Inno Setup, etc.)
                # Parse executable and args from the UninstallString
                $exePath = ""
                $exeArgs = ""
                if ($uninstStr -match '^"([^"]+)"\s*(.*)$') {
                    $exePath = $Matches[1]
                    $exeArgs = $Matches[2]
                } elseif ($uninstStr -match '^(\S+)\s*(.*)$') {
                    $exePath = $Matches[1]
                    $exeArgs = $Matches[2]
                }

                if ($exePath -and (Test-Path $exePath)) {
                    # Detect uninstaller type and add silent flag if requested
                    if ($SilentMode -eq 1) {
                        if ($exeArgs -notmatch "/S|/silent|/SILENT|--uninstall") {
                            # NSIS installers use /S; Inno Setup uses /SILENT or /VERYSILENT
                            $isNSIS  = (Get-Content $exePath -Encoding Byte -TotalCount 512 -ErrorAction SilentlyContinue) -join "" | Select-String "Nullsoft" -Quiet
                            $isInno  = (Get-Content $exePath -Encoding Byte -TotalCount 512 -ErrorAction SilentlyContinue) -join "" | Select-String "Inno Setup" -Quiet
                            $silentFlag = if ($isInno) { "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART" } else { "/S" }
                            $exeArgs = "$exeArgs $silentFlag".Trim()
                        }
                    }
                    Write-Output "  $(Get-TimeStamp) Running non-MSI uninstaller: `"$exePath`" $exeArgs"
                    $proc = Start-Process -FilePath $exePath -ArgumentList $exeArgs -Wait -PassThru -ErrorAction SilentlyContinue
                    Write-Output "  $(Get-TimeStamp) Uninstaller exit code: $($proc.ExitCode)"
                    if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) { $UninstallSucceeded++ }
                } else {
                    Write-Warning "  $(Get-TimeStamp) Could not resolve uninstaller path from: $uninstStr"
                }
            }
        }
    } else {
        Write-Output "$(Get-TimeStamp) No registry entries found matching '$AppName'."
    }

    # ----------------------------------------------------------------
    # Method 2: winget
    # ----------------------------------------------------------------
    if ($UseWinget -eq 1) {
        $wingetPath = (Get-Command winget -ErrorAction SilentlyContinue).Source
        if ($wingetPath) {
            Write-Output "`n$(Get-TimeStamp) Attempting winget uninstall for '$AppName'..."
            $wingetSearchArgs = if ($PartialName -eq 1) { "list --name `"$AppName`" --accept-source-agreements" } else { "list --exact --name `"$AppName`" --accept-source-agreements" }
            $wingetList = & winget $wingetSearchArgs.Split(" ") 2>&1
            $matchedLines = $wingetList | Where-Object { $_ -like "*$AppName*" -and $_ -notmatch "^Name|^---" }

            if ($matchedLines) {
                Write-Output "$(Get-TimeStamp) winget found matching packages:"
                $matchedLines | ForEach-Object { Write-Output "  $_" }

                if ($TestMode -ne 1) {
                    $wingetArgs = if ($PartialName -eq 1) {
                        @("uninstall", "--name", $AppName, "--silent", "--accept-source-agreements", "--disable-interactivity")
                    } else {
                        @("uninstall", "--exact", "--name", $AppName, "--silent", "--accept-source-agreements", "--disable-interactivity")
                    }
                    Write-Output "$(Get-TimeStamp) Running: winget $($wingetArgs -join ' ')"
                    $UninstallAttempted++
                    $proc = Start-Process -FilePath $wingetPath -ArgumentList $wingetArgs -Wait -PassThru -NoNewWindow
                    Write-Output "$(Get-TimeStamp) winget exit code: $($proc.ExitCode)"
                    if ($proc.ExitCode -eq 0) { $UninstallSucceeded++ }
                } else {
                    Write-Output "[TestMode] Would run winget uninstall for: $($matchedLines -join ', ')"
                }
            } else {
                Write-Output "$(Get-TimeStamp) winget: no packages found matching '$AppName'."
            }
        } else {
            Write-Output "$(Get-TimeStamp) winget not found on this system - skipping."
        }
    }

    # ----------------------------------------------------------------
    # Summary
    # ----------------------------------------------------------------
    Write-Output "`n$(Get-TimeStamp) Uninstall summary:"
    Write-Output "  Uninstall attempts: $UninstallAttempted"
    Write-Output "  Successful (exit 0 or 3010): $UninstallSucceeded"
    if ($TestMode -eq 1) { Write-Output "  (TestMode was enabled - no actual changes made)" }

    if ($UninstallSucceeded -gt 0 -or ($TestMode -eq 0 -and $UninstallAttempted -gt 0)) {
        $MyExitStatus = 0
    } elseif ($UninstallAttempted -eq 0) {
        Write-Output "$(Get-TimeStamp) No matching applications found. Exit status: 0"
        $MyExitStatus = 0
    } else {
        Write-Output "$(Get-TimeStamp) Uninstall attempted but may not have fully succeeded. Check log."
        $MyExitStatus = 3
    }
    #endregion main

    #region finalization
    if ($logFileFolderPath -ne "") {
        Write-Output "`nScript $scriptName ended at $(Get-TimeStamp)"
        $elapsedTime = $(Get-Date) - $StartTime
        Write-Output "Elapsed time (seconds): $($elapsedTime.TotalSeconds)"
        Stop-Transcript
        if (($emailServer -ne "") -and ($emailUsername -ne "") -and ($emailPassword -ne "") -and ($emailFrom -ne "") -and ($emailTo -ne "")) {
            Send-MailMessage -SmtpServer "$emailServer" -Port $emailPort -From "$emailFrom" -To "$emailTo" -Subject "$scriptName - $ComputerName - $MyExitStatus - Log File" -Body "$logFilePath" -UseSsl -Credential (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$emailUsername", (ConvertTo-SecureString -String "$emailPassword" -AsPlainText -Force)) -Attachments $logFilePath
        }
        if (($shareLocation -ne "") -and ($shareUsername -ne "") -and ($sharePassword -ne "")) {
            [securestring]$secStringPassword = ConvertTo-SecureString $sharePassword -AsPlainText -Force
            [pscredential]$shareCred = New-Object System.Management.Automation.PSCredential ($shareUsername, $secStringPassword)
            New-PSDrive -Name LogStore -PSProvider FileSystem -Root "$shareLocation" -Description "Log Store" -Credential $shareCred
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
