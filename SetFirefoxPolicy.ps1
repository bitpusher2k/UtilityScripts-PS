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
# SetFirefoxPolicy.ps1 - By Bitpusher/The Digital Fox
# v1.1 last updated 2026-04-18
# Manages Firefox enterprise policies via the policies.json file mechanism.
# Firefox equivalent of SetChromeExtension.ps1 - manages extensions through
# Firefox Enterprise Policy, which overrides user settings.
#
# Capabilities:
#  - Force-install extensions by AMO (addons.mozilla.org) ID
#  - Block specific extensions by ID
#  - Block ALL extensions (ExtensionSettings: {"*": {"blocked_install_message": ..., "installation_mode": "blocked"}})
#  - Generate a report of currently configured Firefox policies
#  - Set common security/privacy policies (disable telemetry, enforce safe browsing, etc.)
#
# Firefox extension IDs can be found on AMO (addons.mozilla.org) by navigating to the
# extension page - the ID is visible in the URL as the slug, or in the addon's manifest.
#
# The policies.json file is placed in:
#  - Windows: C:\Program Files\Mozilla Firefox\distribution\policies.json
#  - If Firefox is installed to a custom path, use the -FirefoxInstallPath parameter.
#
# Note: A Firefox restart is required for policy changes to take effect.
#       Policies can be verified in Firefox by navigating to about:policies.
#
# Usage:
# powershell -executionpolicy bypass -f .\SetFirefoxPolicy.ps1 -Report 1
# powershell -executionpolicy bypass -f .\SetFirefoxPolicy.ps1 -ExtensionIdInstall "uBlock0@raymondhill.net"
# powershell -executionpolicy bypass -f .\SetFirefoxPolicy.ps1 -ExtensionIdBlock "malware-ext@example.com"
# powershell -executionpolicy bypass -f .\SetFirefoxPolicy.ps1 -BlockAllExtensions 1
# powershell -executionpolicy bypass -f .\SetFirefoxPolicy.ps1 -ExtensionIdInstall "builtin" -SetSecurityPolicies 1
#
# Requires admin privileges to write to Program Files.
#
#comp #browser #firefox #extension #policy #security #script #powershell

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$FirefoxInstallPath = "C:\Program Files\Mozilla Firefox",   # Path to Firefox installation folder
    [string]$ExtensionIdInstall = "skip",   # Extension ID to force-install, "builtin" for built-in list, path to CSV, or "skip"
    [string]$ExtensionIdBlock   = "skip",   # Extension ID to block, "builtin" for built-in blocklist, path to CSV, or "skip"
    [int]$BlockAllExtensions    = 0,        # 1 = block ALL extensions machine-wide
    [int]$ClearBlocks           = 0,        # 1 = remove all block policies (restore defaults)
    [int]$Report                = 0,        # 1 = report current Firefox policies only, no changes
    [int]$SetSecurityPolicies   = 0,        # 1 = apply recommended security/privacy baseline policies
    [string]$scriptName = "SetFirefoxPolicy",
    [string]$Priority = "Normal",
    [int]$RandMax = "5",
    [string]$DebugPreference = "SilentlyContinue",
    [string]$VerbosePreference = "SilentlyContinue",
    [string]$InformationPreference = "Continue",
    [string]$logFileFolderPath = "C:\Utility\log",
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

    # Locate Firefox distribution folder
    $DistributionPath = Join-Path $FirefoxInstallPath "distribution"
    $PoliciesJsonPath = Join-Path $DistributionPath "policies.json"

    # Also check 64-bit alternate path
    if (-not (Test-Path $FirefoxInstallPath)) {
        $AltPath = "C:\Program Files (x86)\Mozilla Firefox"
        if (Test-Path $AltPath) {
            $FirefoxInstallPath = $AltPath
            $DistributionPath   = Join-Path $FirefoxInstallPath "distribution"
            $PoliciesJsonPath   = Join-Path $DistributionPath "policies.json"
        } else {
            Write-Warning "$(Get-TimeStamp) Firefox installation not found at '$FirefoxInstallPath' or '$AltPath'."
            Write-Warning "Specify correct path via -FirefoxInstallPath parameter."
        }
    }
    Write-Output "$(Get-TimeStamp) Firefox path: $FirefoxInstallPath"
    Write-Output "$(Get-TimeStamp) Policies.json path: $PoliciesJsonPath"

    # ----------------------------------------------------------------
    # Read existing policies.json (or create empty baseline)
    # ----------------------------------------------------------------
    if (Test-Path $PoliciesJsonPath) {
        $rawJson = Get-Content $PoliciesJsonPath -Raw -ErrorAction SilentlyContinue
        try {
            $PolicyObj = $rawJson | ConvertFrom-Json
            Write-Output "$(Get-TimeStamp) Existing policies.json loaded."
        } catch {
            Write-Warning "$(Get-TimeStamp) Could not parse existing policies.json: $($_.Exception.Message). Starting fresh."
            $PolicyObj = [PSCustomObject]@{ policies = [PSCustomObject]@{} }
        }
    } else {
        Write-Output "$(Get-TimeStamp) No policies.json found. Will create new one."
        $PolicyObj = [PSCustomObject]@{ policies = [PSCustomObject]@{} }
    }

    # ----------------------------------------------------------------
    # Report mode - print current policies and exit
    # ----------------------------------------------------------------
    if ($Report -eq 1) {
        Write-Output "`n=== CURRENT FIREFOX POLICIES ($PoliciesJsonPath) ==="
        if (Test-Path $PoliciesJsonPath) {
            Get-Content $PoliciesJsonPath | Write-Output
        } else {
            Write-Output "  No policies.json found - Firefox is running with default policies."
        }
        $MyExitStatus = 0
        # Fall through to finalization
    } else {
        # ----------------------------------------------------------------
        # ClearBlocks mode
        # ----------------------------------------------------------------
        if ($ClearBlocks -eq 1) {
            Write-Output "$(Get-TimeStamp) ClearBlocks=1: Removing ExtensionSettings block policies..."
            if ($PolicyObj.policies.PSObject.Properties["ExtensionSettings"]) {
                $PolicyObj.policies.PSObject.Properties.Remove("ExtensionSettings")
            }
        }

        # ----------------------------------------------------------------
        # Build install list
        # ----------------------------------------------------------------
        $InstallList = @()
        if ($ExtensionIdInstall -eq "skip") {
            # No installs
        } elseif ($ExtensionIdInstall -eq "builtin") {
            $InstallList = @(
                [PSCustomObject]@{ ID = "uBlock0@raymondhill.net";             Name = "uBlock Origin" }
                [PSCustomObject]@{ ID = "{74145f27-f039-47ce-a470-a662b129930a}"; Name = "Clearclick (browser isolation)" }
                [PSCustomObject]@{ ID = "{446900e4-71c2-419f-a6a7-df9c091e268b}"; Name = "Bitwarden Password Manager" }
            )
        } elseif ($ExtensionIdInstall -match "\.csv$" -and (Test-Path $ExtensionIdInstall)) {
            $InstallList = Import-Csv $ExtensionIdInstall
        } else {
            $InstallList = @([PSCustomObject]@{ ID = $ExtensionIdInstall; Name = "" })
        }

        # ----------------------------------------------------------------
        # Build block list
        # ----------------------------------------------------------------
        $BlockList = @()
        if ($ExtensionIdBlock -eq "skip") {
            # No blocks
        } elseif ($ExtensionIdBlock -eq "builtin") {
            # Known-bad extension IDs (Firefox format uses email-style IDs or GUIDs)
            $BlockList = @(
                [PSCustomObject]@{ ID = "{bad00001-0000-0000-0000-000000000001}"; Name = "Example blocked extension" }
            )
        } elseif ($ExtensionIdBlock -match "\.csv$" -and (Test-Path $ExtensionIdBlock)) {
            $BlockList = Import-Csv $ExtensionIdBlock
        } else {
            $BlockList = @([PSCustomObject]@{ ID = $ExtensionIdBlock; Name = "" })
        }

        # ----------------------------------------------------------------
        # Apply ExtensionSettings policy
        # ----------------------------------------------------------------
        # ExtensionSettings is a single policy object that handles both force-installs and blocks
        if ($InstallList.Count -gt 0 -or $BlockList.Count -gt 0 -or $BlockAllExtensions -eq 1) {
            if (-not $PolicyObj.policies.PSObject.Properties["ExtensionSettings"]) {
                $PolicyObj.policies | Add-Member -NotePropertyName "ExtensionSettings" -NotePropertyValue ([PSCustomObject]@{})
            }

            # Block all extensions if requested
            if ($BlockAllExtensions -eq 1) {
                Write-Output "$(Get-TimeStamp) Blocking ALL extensions..."
                $PolicyObj.policies.ExtensionSettings | Add-Member -NotePropertyName "*" -NotePropertyValue ([PSCustomObject]@{
                    blocked_install_message = "Extension installation is blocked by your organization."
                    installation_mode = "blocked"
                }) -Force
            }

            # Force-install extensions
            foreach ($ext in $InstallList) {
                Write-Output "$(Get-TimeStamp) Force-installing extension: $($ext.ID) ($($ext.Name))"
                $extPolicy = [PSCustomObject]@{
                    installation_mode = "force_installed"
                    install_url       = "https://addons.mozilla.org/firefox/downloads/latest/$($ext.ID)/addon.xpi"
                }
                $PolicyObj.policies.ExtensionSettings | Add-Member -NotePropertyName $ext.ID -NotePropertyValue $extPolicy -Force
            }

            # Block specific extensions
            foreach ($ext in $BlockList) {
                Write-Output "$(Get-TimeStamp) Blocking extension: $($ext.ID) ($($ext.Name))"
                $extPolicy = [PSCustomObject]@{
                    installation_mode       = "blocked"
                    blocked_install_message = "This extension is blocked by your organization."
                }
                $PolicyObj.policies.ExtensionSettings | Add-Member -NotePropertyName $ext.ID -NotePropertyValue $extPolicy -Force
            }
        }

        # ----------------------------------------------------------------
        # Security/Privacy baseline policies
        # ----------------------------------------------------------------
        if ($SetSecurityPolicies -eq 1) {
            Write-Output "$(Get-TimeStamp) Applying security/privacy baseline policies..."
            $secPolicies = @{
                "DisableTelemetry"                 = $true
                "DisableFirefoxAccounts"           = $false   # Keep false - blocking prevents sync
                "DisableFirefoxStudies"            = $true
                "DisableSafeMode"                  = $false   # Keep safe mode available
                "DontCheckDefaultBrowser"          = $false
                "OverrideFirstRunPage"             = ""
                "PasswordManagerEnabled"           = $true    # Allow - better to use built-in than nothing
                "PopupBlocking"                    = [PSCustomObject]@{ Default = $true }
                "Cookies"                          = [PSCustomObject]@{ Default = "accept"; AcceptThirdParty = "never"; Locked = $false }
                "EnableTrackingProtection"         = [PSCustomObject]@{ Value = $true; Locked = $true; Cryptomining = $true; Fingerprinting = $true }
                "SanitizeOnShutdown"               = [PSCustomObject]@{ Cache = $false; Cookies = $false; Downloads = $false; FormData = $false; History = $false; Sessions = $false; SiteSettings = $false; OfflineApps = $false; Locked = $false }
                "SearchEngines"                    = [PSCustomObject]@{ PreventInstalls = $true }
                "BlockAboutProfiles"               = $false
                "BlockAboutAddons"                 = $false
                "BlockAboutConfig"                 = $false
                "BlockAboutSupport"                = $false
                "DisableSetDesktopBackground"      = $false
                "HttpsOnlyMode"                    = "force_enabled"
                "SSLVersionMin"                    = "tls1.2"
            }
            foreach ($key in $secPolicies.Keys) {
                $PolicyObj.policies | Add-Member -NotePropertyName $key -NotePropertyValue $secPolicies[$key] -Force
            }
        }

        # ----------------------------------------------------------------
        # Write policies.json
        # ----------------------------------------------------------------
        $jsonOutput = $PolicyObj | ConvertTo-Json -Depth 10
        if (!(Test-Path $DistributionPath)) {
            New-Item -ItemType Directory -Force -Path $DistributionPath | Out-Null
        }
        # Backup existing policies.json before overwriting
        if (Test-Path $PoliciesJsonPath) {
            $backupPath = "$PoliciesJsonPath.bak-$(Get-Date -Format 'yyyyMMddHHmmss')"
            Copy-Item $PoliciesJsonPath $backupPath
            Write-Output "$(Get-TimeStamp) Backed up existing policies.json to: $backupPath"
        }
        $jsonOutput | Out-File -FilePath $PoliciesJsonPath -Encoding utf8 -Force
        Write-Output "$(Get-TimeStamp) policies.json written to: $PoliciesJsonPath"
        Write-Output "$(Get-TimeStamp) Firefox restart required for policies to take effect."
        Write-Output "$(Get-TimeStamp) Verify policies in Firefox by navigating to: about:policies"

        Write-Output "`n=== RESULTING POLICY CONTENT ==="
        $jsonOutput | Write-Output

        $MyExitStatus = 0
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
