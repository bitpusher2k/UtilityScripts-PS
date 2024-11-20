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
# Create-LocalAdmin.ps1 - By Bitpusher/The Digital Fox
# v1.0 last updated 2024-03-26
# Script to create a local administrator account. Useful for use with RMM/automation.
#
# Usage:
# powershell -executionpolicy bypass -f ./Create-LocalAdmin.ps1 -Username "localadmin" -Password "pA$$w0rd"
#
# Requires the Username and Password parameters be supplied.
#
# Run with admin permissions
#
#script #powershell #local #admin #account #creation

param(
    [Parameter(Mandatory = $true)]
    [string]$Username = "localadmin",
    [Parameter(Mandatory = $true)]
    [string]$Password = "Tr2TBhUxRinK#iXe",
    [string]$scriptName = "Create-LocalAdmin",
    [string]$Priority = "Normal",
    [int]$RandMax = "500",
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
    [string]$Encoding = "utf8bom" # "ascii","ansi","bigendianunicode","unicode","utf8","utf8","utf8NoBOM","utf32"
)

function Create-LocalAdmin {
    [CmdletBinding()]
    param(
        [string]$NewLocalAdmin,
        [securestring]$Password
    )
    begin {
    }
    process {
        New-LocalUser "$NewLocalAdmin" -Password $Password -FullName "$NewLocalAdmin" -Description "Local admin account"
        Write-Verbose "$NewLocalAdmin local user crated"
        Add-LocalGroupMember -Group "Administrators" -Member "$NewLocalAdmin"
        Write-Verbose "$NewLocalAdmin added to the local administrator group"
    }
    end {
    }
}

Write-Output "Creating local admin - Username: $Username"
$SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
Create-LocalAdmin -NewLocalAdmin $Username -Password $SecurePassword -Verbose
