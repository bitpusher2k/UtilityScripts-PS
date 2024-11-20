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
# UninstallX.ps1 - By Bitpusher/The Digital Fox
# v1.1 last updated 2024-03-11
# Script to uninstall MSI application by name or partial name.
#
# NOTE: If PartialName flag is enabled script will attempt to uninstall ALL applications whose name contains the given AppName string.
#
# Usage:
# powershell -executionpolicy bypass -f .\UninstallX.ps1 -AppName "Microsoft Silverlight" -PartialName 0
# powershell -executionpolicy bypass -f .\UninstallX.ps1 -AppName "Advanced IP Scanner" -PartialName 1
#
# Test run without actual uninstall:
# powershell -executionpolicy bypass -f .\UninstallX.ps1 -AppName "Adobe" -PartialName 1 -TestMode 1
#
# email log to yourself by including the emailServer, emailFrom, emailTo
# emailUsername, and emailPassword parameters.
#
# Run with admin privileges
#
#uninstall #name #script #powershell #comp #powershell #msi #msiexec

param
(
    [Parameter(Mandatory = $true)]
    [string]$AppName = "",
    [string]$PartialName = "0",
    [string]$TestMode = "0",
    [string]$scriptName = "UninstallX",
    [string]$Priority = "Normal",
    [int]$RandMax = "5",
    [string]$DebugPreference = "SilentlyContinue",
    [string]$VerbosePreference = "SilentlyContinue",
    [string]$InformationPreference = "Continue",
    [string]$logFileFolderPath = "C:\temp\log",
    [string]$ComputerName = $env:computername,
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
    [int]$logFileRetentionDays = 30
)
process {
    #region initialization
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
    #initial debug tracing for debugging - switch to "0" for most production use
    Set-PSDebug -Trace 0
    [int]$MyExitStatus = 1
    $StartTime = $(Get-Date)
    Write-Output "Script $scriptName started at $(Get-TimeStamp)"
    Write-Output "ISO8601:$(Get-Date (Get-Date).ToUniversalTime() -UFormat '+%Y%m%dT%H%M%S.000Z')`n"
    $RandSeconds = Get-Random -Minimum 1 -Maximum $RandMax
    Write-Output "Waiting $RandSeconds seconds (between 1 and $RandMax) to stagger execution across devices`n"
    Start-Sleep -Seconds $RandSeconds

    if ($AppName -ne "") {
        # Write-Output "Calling WMIC to attempt uninstall of $AppName"
        # Get-CimInstance -Classname WIn32_Product | Where-Object Name -Match "$AppName" | Invoke-CimMethod -MethodName UnInstall # Don't use Win32_Product - https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa394378(v=vs.85)
        if ($PartialName -eq 1) {
            Write-Output "`nChecking registry for installed applications name containing `"$AppName`"..."
            $applist = Get-ChildItem "Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object -FilterScript { $_.DisplayName -like "*$AppName*" }
        } else {
            Write-Output "`nChecking registry for installed applications with the full name `"$AppName`"..."
            $applist = Get-ChildItem "Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object -FilterScript { $_.DisplayName -like "$AppName" }
        }

        if ($applist) {
            Write-Output "`nApplications found:"
            $applist.DisplayName
            Write-Output "`nAttempting to uninstall..."
            foreach ($app in $applist) {
                Write-Output "`nName: $($app.DisplayName) - Version: $($app.DisplayVersion) - GUID: $($app.PSChildName)"
                Write-Output "msiexec.exe /x $($app.PSChildName) /qn /norestart /L*V `"$logFileFolderPath\MSIuninstallLog.txt`""
                if ($TestMode -eq 1) {
                    Write-Output "TestMode enabled - No uninstallations actually attempted."
                } else {
                    msiexec.exe /x $app.PSChildName /qn /norestart /L*V "$logFileFolderPath\MSIuninstallLog.txt"
                }
            }
            If (Test-Path -path "$logFileFolderPath\MSIuninstallLog.txt" -PathType Leaf) {
                Write-Output ""
                Get-Content "$logFileFolderPath\MSIuninstallLog.txt"
                # Remove-Item -Path "$logFileFolderPath\MSIuninstallLog.txt" -Force -ErrorAction Continue
            }
            Write-Output ""
            $MyExitStatus = 0
        } else {
            Write-Output "No applications by that name found - Ending`n"
            $MyExitStatus = 2
        }
    } else {
        Write-Output "No application name specified - Ending`n"
        $MyExitStatus = 3
    }

    #endregion main

    #region finalization
    if ($logFileFolderPath -ne "") {
        Write-Output "Script $scriptName ended at $(Get-TimeStamp)"
        $elapsedTime = $(Get-Date) - $StartTime
        Write-Output "Elapsed time (seconds): $($elapsedTime.TotalSeconds)"
        Stop-Transcript
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
