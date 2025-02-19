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
# Encode-Script.ps1 - By Bitpusher/The Digital Fox
# v1.7 last updated 2025-02-18
# Script to encode another PS script from file or the clipboard into base64 encoded string
# and output BAT file that can be run from CMD or PowerShell to execute the original script.
# Useful for running short scripts across networks through other utilities,
# such as RMM tools, PSExec, or PS remoting.
# Removes comment lines to make encoded string as short as possible.
#
# Usage:
# powershell -executionpolicy bypass -f .\Encode-Script.ps1 # Encodes contents of clipboard
# powershell -executionpolicy bypass -f .\Encode-Script.ps1 -inputFile "Path\to\input\script" -outputFile "Path\to\output\script"
#
# Use with DropShim.bat to allow drag-and-drop processing of scripts, or encoding of clipboard
# by simply double-clicking bat.
#
#script #powershell #batch #cmd #encode #base64 #clipboard

#Requires -Version 5.1

param(
    [string]$inputFile,
    [string]$outputFile = "script-$($(Get-Date).ToString("yyyyMMddhhmm"))",
    [string]$scriptName = "Encode-Script",
    [string]$Priority = "Normal",
    [int]$RandMax = "500",
    [string]$DebugPreference = "SilentlyContinue",
    [string]$VerbosePreference = "SilentlyContinue",
    [string]$InformationPreference = "Continue",
    [string]$logFileFolderPath = "C:\temp\log",
    [string]$ComputerName = $env:computername,
    [string]$ScriptUserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
    [string]$logFilePrefix = "$scriptName" + "_" + "$ComputerName" + "_",
    [string]$logFileDateFormat = "yyyyMMdd_HHmmss",
    [int]$logFileRetentionDays = 30
)

$sw = [Diagnostics.StopWatch]::StartNew()

Write-Output "$scriptName started"

# Load script from file or clipboard
if ($inputfile) {
    Write-Output "`nLoading, stripping comments, and encoding script $inputFile..."
    # $InputScript = Get-Content -Path "$inputFile" | Out-String
    $InputScript = Get-Content -Path "$inputFile" -Raw
} else {
        Write-Output "`nLoading, stripping comments, and encoding contents of clipboard..."
    $InputScript = Get-Clipboard -Format Text
}

# Write-Output "`n-----------------"
# Write-Output "Original input:"
# $InputScript

Write-Output "`n-----------------"
Write-Output "Input script measure:"
$InputScript |  Measure-Object -character -line -word

# Remove comments from script
$InputScript = $InputScript -split "[\r\n]+"             # Remove all consecutive line-breaks, in any format, by splitting on breaks. '-split "\r?\n|\r"' would do line by line.
$InputScript = $InputScript | ? { $_ -notmatch "^\s*$" } # Remove empty lines.
$InputScript = $InputScript | ? { $_ -notmatch "^\s*#" } # Remove lines starting with "#" including with whitespace before start of comment.
$InputScript = $InputScript | % { ($_ -split " #")[0] }  # Remove end of line comments by splitting at " #".
$InputScript = ($InputScript -replace $regex).Trim()     # Remove whitespace at start and end of line.
# $InputScript = $InputScript | foreach {$_ +  "`n"}
$InputScript = $InputScript | %{$_ -replace '$',"`n"}    # Add new line character back onto the end of every line before encoding.

# Encode script to compressed Base64 JSON object - Extra layer which is not generally needed
# $JsonScript = [PSCustomObject]@{ "Script" =  [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($InputScript)) } | ConvertTo-Json -Compress
# $OneLine = "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(('" + $JsonScript + "' | ConvertFrom-Json).Script)) | iex"
# $CmdString = [convert]::ToBase64String([System.Text.encoding]::Unicode.GetBytes($OneLine))

# $CmdString = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($InputScript))
# $CmdString = [System.Convert]::ToBase64String([System.Text.encoding]::UTF8.GetBytes($InputScript))
$CmdString = [Convert]::ToBase64String([System.Text.encoding]::Unicode.GetBytes($InputScript))
$BatString = "Powershell -NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass -Encoded " + $CmdString
Set-Clipboard -Value $BatString

# Export encoded script
if ($inputFile) {
    [string]$outputFolder = Split-Path -Path $inputFile -Parent
    [string]$outputFile = (Get-Item $inputFile).BaseName
    [string]$outputPath = $outputFolder + "\" + $outputFile + ".bat"
} else {
    [string]$outputPath = $outputFile + ".bat"
}
Write-Output "`nSaving output BAT script to $outputPath..."
$BatString | Out-File -Filepath "$outputPath" -Encoding Default

# Write-Output "`nPS5 encoded command execution:"
# Write-Output "Powershell -NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass -Encoded 'XXXX'"
# Write-Output "`nPS7 encoded command execution:"
# Write-Output "C:\Program Files\PowerShell\7\pwsh.exe -NoExit -NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass -Encoded 'XXXX'"

# Write-Output "`n-----------------"
# Write-Output "Input script without comments:"
# $InputScript
# Write-Output "`n-----------------"
# Write-Output "JsonScript:"
# $JsonScript
# Write-Output "`n-----------------"
# Write-Output "OneLine:"
# $OneLine
# Write-Output "`n-----------------"
# Write-Output "CmdString:"
# $CmdString
Write-Output "`n-----------------"
Write-Output "BatString:"
$BatString

Write-Output "`nOutput encoded string measure:"
$CmdString |  Measure-Object -character -line -word
Write-Output "`nNote that the interactive CMD prompt supports a maximum input length of 8,191 characters,"
Write-Output "while PowerShell supports interactive input up to a maximum length of 32,766 characters."
Write-Output "Other remote utilities may impose different limits."
# https://learn.microsoft.com/en-us/troubleshoot/windows-client/shell-experience/command-line-string-limitation

if ($CmdString.length -gt 8191) {
    Write-Output "`nWARNING - Encoded command may be too large for direct input from prompt,"
    Write-Output "and may need to be saved to local file in order to successfully execute:"
    Write-Output "powershell -NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass -EncodedCommand (Get-Content 'SCRIPTNAME.ps1' -Raw)"
}

Write-Output "`nDone! Encoded command string also pushed to clipboard, ready to paste."
Write-Output "Seconds elapsed for processing: $($sw.elapsed.totalseconds)"

exit
