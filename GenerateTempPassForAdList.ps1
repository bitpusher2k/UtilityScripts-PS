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
# GenerateTepmPassForAdList.ps1 - By Bitpusher/The Digital Fox
# v1.9.1 last updated 2025-09-24
# Processes an exported CSV report of AD users containing at least the columns
# "SamAccountName" and "PasswordLastSet". Generate a random temporary password
# for each enabled account, skipping some known administrative accounts that
# need to be reset manually.
# Designed to be used with the GenerateAdUserReport script to facilitate rapid
# review and resetting of AD account passwords during a security incident.
#
# Usage:
# powershell -executionpolicy bypass -f .\GenerateTepmPassForAdList.ps1 -InputPath "Path\to\input\log.csv" -OutputPath "Path\to\output\file.csv"
#
# powershell -executionpolicy bypass -f .\GenerateTepmPassForAdList.ps1
#
# Use with DropShim.bat to allow drag-and-drop processing of CSV file.
#
# Use simplified and minified one-liner versions at the bottom to easily
# copy/paste into console of remote system (remote tools don't generally handle
# input with line breaks well).
#
#comp #ad #security #incident #script #active #directory #samaccountname #password #reset #powershell

#Requires -Version 4

param(
    [string]$InputPath = $(Get-ChildItem c:\temp -Filter "*account_report_before_reset*.csv" | Sort-Object -Descending | Select-Object -First 1),
    [string]$OutputPath = 'c:\temp\temppasswords.csv',
    [string]$NewColumnName = "NewPassword"
)

# Return random words
function Get-RandomWord {
    if (!$script:RandomWords) {
        # Get random wordlist from online dictionary API
        try {
            $script:RandomWords = Invoke-RestMethod -Uri 'https://random-word-api.vercel.app/api?words=200&length=7&alphabetize=true' -Method Get
            $script:RandomWords += Invoke-RestMethod -Uri 'https://random-word-api.vercel.app/api?words=200&length=6&alphabetize=true' -Method Get
            $script:RandomWords += Invoke-RestMethod -Uri 'https://random-word-api.vercel.app/api?words=200&length=5&alphabetize=true' -Method Get
        } catch {
            # Fallback to random characters if word retrieval fails
            $script:RandomWords = [System.Collections.ArrayList]@()
            # $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
            $characters = 'abcdefghijklmnopqrstuvwxyz'
            # These are supposed to be temporary passwords, so as a fallback using two groups of lowercase letters along with the number should be sufficient, and keep it easier to communicate over the phone
            for ($i = 0; $i -lt 300; $i++) {
                $password = -join ((1..4) | ForEach-Object { $characters[(Get-Random -Minimum 0 -Maximum $characters.Length)] })
                $script:RandomWords += $password
            }
        }
    }
    try {
        $word = $script:RandomWords | Get-Random
        return $word
    } catch {
        $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
        $password = -join ((1..10) | ForEach-Object { $characters[(Get-Random -Minimum 0 -Maximum $characters.Length)] })
        return $password
    }
}

# Generate a pair of random words (or character blocks), followed by a two-digit random number, hyphen separated (U+002D, Hyphen-Minus)
function Get-RandomPass {
    $first = Get-RandomWord
    $second = Get-RandomWord
    $third = Get-Random -Minimum 10 -Maximum 99
    return "$first-$second-$third"
}

# Process CSV file adding column of random passwords
function Add-NewPassToCSV {
    param(
        [string]$InputPath,
        [string]$OutputPath,
        [string]$NewColumnName
    )

    # Check if input file exists
    if (-not (Test-Path $InputPath)) {
        Write-Output "`nInput file not found: $InputPath"
        return
    }

    try {
        # Read the CSV file
        Write-Output "`nInput file found. Loading for processing..."
        $csv = Import-Csv -Path $InputPath
        $csv = $csv | Where-Object { $_.SamAccountName }
        Write-Output "$($csv.length) total user accounts."
        $csv = $csv | Where-Object { $_.Enabled -eq 'True' }
        Write-Output "$($csv.length) enabled user accounts."

        # List of account names to SKIP creating a temporary password for and resetting in bulk
        $RegexMatchAdmin = '^administrator$|^adsync$|^aad_|^msol_'

        $skip = $csv | Where-Object { $_.SamAccountName -match $RegexMatchAdmin } | Select-Object SamAccountName, PasswordLastSet
        if ($skip) {
            Write-Output "`nFound admin/service accounts which will be SKIPPED - manually update password(s) for $($skip.length) account(s):"
            $skip
            Write-Output "`n------------------------------"
        }

        $csv = $csv | Where-Object { $_.SamAccountName -notmatch $RegexMatchAdmin }

        # Add the new column with random word pairs
        $csv | ForEach-Object {
            $_ | Add-Member -NotePropertyName $NewColumnName -NotePropertyValue (Get-RandomPass)
        }

        # Export to a new CSV file
        $csv | Select-Object SamAccountName, NewPassword | Export-Csv -Path $OutputPath -NoTypeInformation

        Write-Output "`nSuccessfully processed CSV file. Output saved to: $OutputPath"
        Write-Output "`nTemporary password file written."
        Write-Output "`nUsernames in file:"
        $csv.SamAccountName | Sort-Object
        Write-Output "`nLength of file: $($csv.length) user accounts."
        Write-Output "`nReview file with: type $OutputPath"
        Write-Output "`nRemove a USERNAME from the file with:"
        Write-Output "`$csv = Import-Csv -Path '$OutputPath' ; `$csv | Where-Object { $_.SamAccountName -ne 'USERNAME' } | Export-Csv -Path $OutputPath -NoTypeInformation"
        Write-Output "`nUpdate account passwords using temporary password file with:"
        Write-Output "Import-Csv $OutputPath -Delimiter `",`" | Foreach { `$NewPassword = ConvertTo-SecureString -AsPlainText `$_.NewPassword -Force ; Set-ADAccountPassword -Identity `$_.SAMAccountName -NewPassword `$NewPassword -Reset -PassThru | Set-ADUser -ChangePasswordAtLogon `$false }"
        Write-Output "`nSet passwords to require change at login for all accounts in file (note this will have no effect if password is set to never expire for account):"
        Write-Output "Import-Csv $OutputPath -Delimiter `",`" | Foreach { -Identity `$_.SAMAccountName Set-ADUser -ChangePasswordAtLogon `$true }"
        Write-Output "`nSet password to expire for all accounts in file:"
        Write-Output "Import-Csv $OutputPath -Delimiter `",`" | Foreach { Set-ADUser -Identity `$_.SAMAccountName -PasswordNeverExpires `$False }"
        Write-Output "`nEnable all accounts in file:"
        Write-Output "Import-Csv $OutputPath -Delimiter `",`" | Foreach { Enable-ADAccount -Identity `$_.SAMAccountName }"
        Write-Output "`nBe sure to remove temporary password file from server after reset."
        Write-Output "Run AD account report again after reset is complete, and review report."
        Write-Output "`nBe sure to reset KRBTGT password twice, with resets spaced at least 10 hours apart:"
        Write-Output "Get-ADUser `"krbtgt`" -Property Created, PasswordLastSet ; $NewPassword = ConvertTo-SecureString -AsPlainText 'xXxXxXxX' -Force ; Set-ADAccountPassword -Identity `"krbtgt`" -NewPassword $NewPassword -Reset -PassThru ; Get-ADUser `"krbtgt`" -Property Created, PasswordLastSet"
    } catch {
        Write-Output "`nError processing CSV file: $_"
    }
}

Add-NewPassToCSV -InputPath $InputPath -OutputPath $OutputPath -NewColumnName $NewColumnName


# Minified bare-bones one-liner version of script for copy/paste into console (requires internet access for random wordlist retrieval):
$OneLinerWords = @'
$InPath = $(gci c:\temp -filter "*account_report_before_reset*.csv" | sort -descending | select -first 1) ; $OutPath = 'c:\temp\temppasswords.csv' ; $url = 'https://random-word-api.vercel.app/' ; $words = $(irm -Uri "$($url)api?words=200&length=7&alphabetize=true") + $(irm -Uri "$($url)api?words=200&length=6&alphabetize=true") + $(irm -Uri "$($url)api?words=200&length=5&alphabetize=true") ; function Get-Word { $word = $words | Get-Random ; return $word } ; function Get-Pass { $first = Get-Word ; $second = Get-Word ; $third = Get-Random -Minimum 10 -Maximum 99 ; return "$first-$second-$third" } ; $Regex = '^administrator$|^adsync$|^aad_|^msol_' ; $csv = ipcsv -Path $InPath ; $csv = $csv | ? {$_.SamAccountName -and $_.Enabled -eq 'True' -and $_.SamAccountName -notmatch $Regex} ; $csv | % { $_ | Add-Member -NotePropertyName 'NewPassword' -NotePropertyValue (Get-Pass) } ; $csv | Select SamAccountName, NewPassword | epcsv -Path $OutPath -NTI
'@
# Version using random character passwords (does not require internet access):
$OneLinerChars = @'
$InPath = $(gci c:\temp -filter "*account_report_before_reset*.csv" | sort -descending | select -first 1) ; $OutPath = 'c:\temp\temppasswords.csv' ; $Words = [System.Collections.ArrayList]@() ; $Chars = 'abcdefghijklmnopqrstuvwxyz' ; for ($i = 0; $i -lt 300; $i++) { $password = -join ((1..4) | ForEach-Object { $Chars[(Get-Random -Minimum 0 -Maximum $Chars.Length)] }) ; $Words += $password } ; function Get-Word { $word = $words | Get-Random ; return $word } ; function Get-Pass { $first = Get-Word ; $second = Get-Word ; $third = Get-Random -Minimum 10 -Maximum 99 ; return "$first-$second-$third" } ; $Regex = '^administrator$|^adsync$|^aad_|^msol_' ; $csv = ipcsv -Path $InPath ; $csv = $csv | ? {$_.SamAccountName -and $_.Enabled -eq 'True' -and $_.SamAccountName -notmatch $Regex} ; $csv | % { $_ | Add-Member -NotePropertyName 'NewPassword' -NotePropertyValue (Get-Pass) } ; $csv | Select SamAccountName, NewPassword | epcsv -Path $OutPath -NTI
'@
# Reset AD passwords using generated file:
$OneLinerResetUsingFile = @'
Import-Csv c:\temp\temppasswords.csv -Delimiter "," | Foreach { $NewPassword = ConvertTo-SecureString -AsPlainText $_.NewPassword -Force ; Set-ADAccountPassword -Identity $_.SAMAccountName -NewPassword $NewPassword -Reset -PassThru | Set-ADUser -ChangePasswordAtLogon $false }
'@
# Alternate (backupP random word APIs:
# https://random-word-api.herokuapp.com/word?number=200&length=7
