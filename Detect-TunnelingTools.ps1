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
# Detect-TunnelingTools.ps1 - By Bitpusher/The Digital Fox
# v1.2 last updated 2026-04-19
# Detects mesh VPN, reverse proxy, and tunneling tools that are increasingly used
# as command-and-control (C2) infrastructure by threat actors.
# These tools are distinct from traditional RAS/RMM (covered by Detect-RAS.ps1)
# in that they establish persistent encrypted tunnels rather than provide direct
# interactive remote desktop access.
#
# Detects (among others):
#  Tailscale, ZeroTier, Netbird/WireGuard, ngrok, Cloudflare Tunnel (cloudflared),
#  frp (Fast Reverse Proxy), Chisel, ligolo-ng, bore, rathole, pgrok, Inlets,
#  SoftEther VPN, WireGuard, OpenVPN, Meshbird, Headscale, Husarnet
#
# Complements Detect-RAS.ps1 - run both for comprehensive coverage.
# Outputs CSV report. Use -ExcludeTools to suppress known legitimate tools.
#
# Usage:
# powershell -executionpolicy bypass -f .\Detect-TunnelingTools.ps1
# powershell -executionpolicy bypass -f .\Detect-TunnelingTools.ps1 -ExcludeTools "Tailscale","WireGuard"
# powershell -executionpolicy bypass -f .\Detect-TunnelingTools.ps1 -OutputHtml 1 -OutputPath "C:\temp"
#
# Email report to yourself by including the emailServer, emailFrom, emailTo,
# emailUsername, and emailPassword parameters.
#
# DISCLAIMER: Detection of these tools does not imply malicious use. Administrators
# may deploy them legitimately. Context and exclusion lists are important.
#
#remote #access #tunnel #vpn #c2 #mesh #ngrok #cloudflare #wireguard #detection #script #powershell

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string[]]$ExcludeTools = @(),                 # Names of tools to exclude from results
    [int]$OutputHtml = 1,                          # 1 = also generate HTML report
    [string]$OutputPath = "C:\temp",               # Folder for CSV/HTML output
    [string]$scriptName = "Detect-TunnelingTools",
    [string]$Priority = "Normal",
    [int]$RandMax = "3",
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

    New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
    $DateStamp  = $(Get-Date).ToString("yyyyMMddHHmm")
    $CsvPath    = "$OutputPath\$ComputerName-TunnelingTools-$DateStamp.csv"
    $HtmlPath   = "$OutputPath\$ComputerName-TunnelingTools-$DateStamp.html"

    # ----------------------------------------------------------------
    # Load system data upfront for efficient searching
    # ----------------------------------------------------------------
    Write-Output "$(Get-TimeStamp) Loading system information..."
    $Processes    = Get-Process -ErrorAction SilentlyContinue
    $Services     = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.State -ne "Stopped" -and $_.StartMode -ne "Disabled" }
    $Uninstall64  = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Get-ItemProperty -ErrorAction SilentlyContinue
    $Uninstall32  = Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Get-ItemProperty -ErrorAction SilentlyContinue

    # Build file hash tables for ProgramFiles + ProgramData
    $PfFiles = @{}; $Pf86Files = @{}; $PdFiles = @{}
    Get-ChildItem "${Env:ProgramFiles}" -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $PfFiles[$_.Name] = $_.FullName }
    Get-ChildItem "${Env:ProgramFiles(x86)}" -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $Pf86Files[$_.Name] = $_.FullName }
    Get-ChildItem "${Env:ProgramData}" -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $PdFiles[$_.Name] = $_.FullName }

    function Test-Tool {
        param([string]$ProcessName, [string]$DisplayName, [string[]]$Executables, [string[]]$FullPaths)
        $hits = [System.Collections.Generic.List[string]]::new()
        if ($ProcessName) {
            $found = $Processes | Where-Object { $_.ProcessName -like "$ProcessName*" }
            if ($found) { $hits.Add("RunningProcess:$($found[0].ProcessName)(PID:$($found[0].Id))") }
            $svcFound = $Services | Where-Object { $_.PathName -like "*$ProcessName*" }
            if ($svcFound) { $hits.Add("Service:$($svcFound[0].Name)") }
        }
        if ($DisplayName) {
            $regFound = ($Uninstall64 + $Uninstall32) | Where-Object { $_.DisplayName -like "*$DisplayName*" } | Select-Object -First 1
            if ($regFound) { $hits.Add("InstalledSoftware:$($regFound.DisplayName) v$($regFound.DisplayVersion)") }
        }
        foreach ($exe in $Executables) {
            if ($PfFiles[$exe]) { $hits.Add("FileFound:$($PfFiles[$exe])") }
            if ($Pf86Files[$exe]) { $hits.Add("FileFound:$($Pf86Files[$exe])") }
            if ($PdFiles[$exe]) { $hits.Add("FileFound:$($PdFiles[$exe])") }
        }
        foreach ($fp in $FullPaths) {
            if (Test-Path $fp) { $hits.Add("FullPathFound:$fp") }
        }
        return $hits
    }

    # ----------------------------------------------------------------
    # Tool definitions
    # (Name, ProcessName, DisplayName, Executables[], FullPaths[], RiskLevel, Notes)
    # ----------------------------------------------------------------
    $ToolList = @(
        # Mesh VPN / zero-trust networking
        [PSCustomObject]@{ Name="Tailscale";      ProcessName="tailscaled";           DisplayName="Tailscale";      Executables=@("tailscaled.exe","tailscale-ipn.exe","tailscale.exe");                            FullPaths=@();                                                          Risk="Medium"; Notes="Mesh VPN; legitimate but used as C2 pivot" }
        [PSCustomObject]@{ Name="ZeroTier";       ProcessName="zerotier-one_x64";     DisplayName="ZeroTier";       Executables=@("zerotier-one_x64.exe","ZeroTier One.exe");                                        FullPaths=@("C:\ProgramData\ZeroTier\One\zerotier-one_x64.exe");        Risk="Medium"; Notes="Mesh VPN overlay network" }
        [PSCustomObject]@{ Name="Netbird";        ProcessName="netbird";              DisplayName="Netbird";        Executables=@("netbird.exe","netbird-ui.exe");                                                    FullPaths=@("C:\Program Files\Netbird\netbird.exe");                    Risk="Medium"; Notes="WireGuard-based zero-trust mesh VPN" }
        [PSCustomObject]@{ Name="Husarnet";       ProcessName="husarnet-daemon";      DisplayName="Husarnet";       Executables=@("husarnet-daemon.exe");                                                             FullPaths=@();                                                          Risk="Medium"; Notes="Peer-to-peer VPN mesh" }
        [PSCustomObject]@{ Name="Headscale";      ProcessName="headscale";            DisplayName="Headscale";      Executables=@("headscale.exe");                                                                   FullPaths=@();                                                          Risk="Medium"; Notes="Self-hosted Tailscale control server" }
        [PSCustomObject]@{ Name="WireGuard";      ProcessName="wireguard";            DisplayName="WireGuard";      Executables=@("wireguard.exe","wg.exe","wg-quick.exe");                                           FullPaths=@("C:\Program Files\WireGuard\wireguard.exe");                Risk="Low";    Notes="VPN protocol - legitimate but check config" }

        # Reverse proxy / tunneling (high C2 risk)
        [PSCustomObject]@{ Name="ngrok";          ProcessName="ngrok";                DisplayName="ngrok";          Executables=@("ngrok.exe");                                                                       FullPaths=@();                                                          Risk="High";   Notes="Public tunnel relay - common for C2 exfil/access" }
        [PSCustomObject]@{ Name="Cloudflare Tunnel"; ProcessName="cloudflared";       DisplayName="Cloudflare Tunnel"; Executables=@("cloudflared.exe","cloudflared-windows-amd64.exe");                             FullPaths=@("C:\Windows\System32\cloudflared.exe","C:\ProgramData\cloudflared\cloudflared.exe"); Risk="Medium"; Notes="Cloudflare tunnel agent - check for unauthorized config" }
        [PSCustomObject]@{ Name="frp (Fast Reverse Proxy)"; ProcessName="frpc";       DisplayName="frp";            Executables=@("frpc.exe","frps.exe","frp.exe");                                                   FullPaths=@();                                                          Risk="High";   Notes="Open-source reverse proxy - common C2/pentest tool" }
        [PSCustomObject]@{ Name="Chisel";         ProcessName="chisel";               DisplayName="Chisel";         Executables=@("chisel.exe","chisel_windows_amd64.exe");                                           FullPaths=@();                                                          Risk="High";   Notes="TCP/UDP tunnel over HTTP/websockets - pentest/C2" }
        [PSCustomObject]@{ Name="bore";           ProcessName="bore";                 DisplayName="bore";           Executables=@("bore.exe");                                                                        FullPaths=@();                                                          Risk="High";   Notes="Simple TCP tunnel - minimal footprint" }
        [PSCustomObject]@{ Name="rathole";        ProcessName="rathole";              DisplayName="rathole";        Executables=@("rathole.exe");                                                                     FullPaths=@();                                                          Risk="High";   Notes="Lightweight reverse proxy/tunnel tool" }
        [PSCustomObject]@{ Name="pgrok";          ProcessName="pgrok";                DisplayName="pgrok";          Executables=@("pgrok.exe");                                                                       FullPaths=@();                                                          Risk="High";   Notes="Self-hosted ngrok alternative" }
        [PSCustomObject]@{ Name="Inlets";         ProcessName="inlets";               DisplayName="Inlets";         Executables=@("inlets.exe","inlets-pro.exe");                                                     FullPaths=@();                                                          Risk="Medium"; Notes="Self-hosted tunnel/reverse proxy" }
        [PSCustomObject]@{ Name="ligolo-ng";      ProcessName="ligolo-ng";            DisplayName="ligolo";         Executables=@("ligolo-ng.exe","agent.exe");                                                       FullPaths=@();                                                          Risk="High";   Notes="Advanced layer 3 pivot/tunnel - pentest/C2" }
        [PSCustomObject]@{ Name="SoftEther VPN";  ProcessName="vpnclient";            DisplayName="SoftEther VPN";  Executables=@("vpnclient.exe","vpnserver.exe","vpnbridge.exe","vpncmd.exe");                      FullPaths=@("C:\Program Files\SoftEther VPN Client\vpnclient.exe");     Risk="Medium"; Notes="Powerful multi-protocol VPN software" }

        # Remote access tools that create tunnels (also in Detect-RAS but worth cross-checking)
        [PSCustomObject]@{ Name="Sshuttle";       ProcessName="sshuttle";             DisplayName="sshuttle";       Executables=@("sshuttle.exe");                                                                    FullPaths=@();                                                          Risk="High";   Notes="Transparent proxy over SSH - pentest pivot tool" }
        [PSCustomObject]@{ Name="PuTTY Dynamic Forwarding"; ProcessName="putty";      DisplayName="PuTTY";          Executables=@("putty.exe","plink.exe","puttygen.exe");                                            FullPaths=@();                                                          Risk="Medium"; Notes="SSH client; -D flag enables SOCKS proxy tunnel" }
        [PSCustomObject]@{ Name="OpenSSH Tunneling"; ProcessName="ssh";              DisplayName="";               Executables=@();                                                                                  FullPaths=@("C:\Windows\System32\OpenSSH\ssh.exe");                     Risk="Low";    Notes="Built-in SSH; check for active tunnel processes" }
        [PSCustomObject]@{ Name="Proxychains/ProxyCap"; ProcessName="proxycap";      DisplayName="ProxyCap";       Executables=@("proxycap.exe","proxycap64.exe");                                                   FullPaths=@();                                                          Risk="High";   Notes="Routes all TCP through proxy/SOCKS chains" }

        # IOT/device tunneling
        [PSCustomObject]@{ Name="Meshbird";       ProcessName="meshbird";             DisplayName="Meshbird";       Executables=@("meshbird.exe");                                                                    FullPaths=@();                                                          Risk="Medium"; Notes="Distributed private networking" }
        [PSCustomObject]@{ Name="PacketStream";   ProcessName="packetstream";         DisplayName="PacketStream";   Executables=@("packetstream.exe");                                                                FullPaths=@();                                                          Risk="High";   Notes="Bandwidth sharing PUP - often bundled with malware" }
    )

    # ----------------------------------------------------------------
    # Run detection
    # ----------------------------------------------------------------
    $DetectedTools  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $ExcludedTools  = [System.Collections.Generic.List[string]]::new()
    $NotFoundTools  = [System.Collections.Generic.List[string]]::new()

    Write-Output "$(Get-TimeStamp) Scanning for $($ToolList.Count) tunneling/mesh-VPN tool signatures..."

    foreach ($tool in $ToolList) {
        if ($tool.Name -in $ExcludeTools) {
            $ExcludedTools.Add($tool.Name)
            continue
        }
        $hits = Test-Tool -ProcessName $tool.ProcessName -DisplayName $tool.DisplayName -Executables $tool.Executables -FullPaths $tool.FullPaths
        if ($hits.Count -gt 0) {
            $DetectedTools.Add([PSCustomObject]@{
                ComputerName  = $ComputerName
                ToolName      = $tool.Name
                RiskLevel     = $tool.Risk
                DetectionHits = $hits -join " | "
                Notes         = $tool.Notes
                ScanTime      = (Get-Date -Format "o")
            })
        } else {
            $NotFoundTools.Add($tool.Name)
        }
    }

    # Export CSV
    if ($DetectedTools.Count -gt 0) {
        $DetectedTools | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding $Encoding
    } else {
        # Write header-only CSV
        [PSCustomObject]@{ ComputerName=$ComputerName; ToolName="(none found)"; RiskLevel=""; DetectionHits=""; Notes=""; ScanTime=(Get-Date -Format "o") } |
            Export-Csv -Path $CsvPath -NoTypeInformation -Encoding $Encoding
    }

    # ----------------------------------------------------------------
    # HTML Report
    # ----------------------------------------------------------------
    if ($OutputHtml -eq 1) {
        $htmlRows = foreach ($t in $DetectedTools) {
            $riskColor = switch ($t.RiskLevel) { "High" { "#ff4444" } "Medium" { "#ffaa00" } default { "#888888" } }
            "<tr><td style='color:$riskColor;font-weight:bold'>$($t.RiskLevel)</td><td>$($t.ToolName)</td><td>$($t.DetectionHits)</td><td>$($t.Notes)</td></tr>"
        }
        $htmlContent = @"
<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Tunneling Tool Detection - $ComputerName</title>
<style>
body { font-family: Consolas, monospace; background: #1a1a1a; color: #e0e0e0; padding: 20px; }
h1 { color: #ff6600; } h2 { color: #aaaaaa; }
table { border-collapse: collapse; width: 100%; margin-top: 10px; }
th { background: #333; color: #ff6600; padding: 8px; text-align: left; }
td { padding: 6px 8px; border-bottom: 1px solid #333; }
tr:hover { background: #2a2a2a; }
.none { color: #44ff44; }
</style></head><body>
<h1>Tunneling Tool Detection Report</h1>
<h2>Host: $ComputerName &nbsp;|&nbsp; Scan: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</h2>
<p>Tools detected: <strong>$($DetectedTools.Count)</strong> &nbsp;|&nbsp; Excluded: $($ExcludedTools.Count) &nbsp;|&nbsp; Not found: $($NotFoundTools.Count)</p>
$(if ($DetectedTools.Count -eq 0) { '<p class="none">No tunneling tools detected.</p>' } else {
"<table><tr><th>Risk</th><th>Tool</th><th>Detection</th><th>Notes</th></tr>$($htmlRows -join '')</table>"
})
</body></html>
"@
        $htmlContent | Out-File -FilePath $HtmlPath -Encoding utf8
        Write-Output "$(Get-TimeStamp) HTML report saved to: $HtmlPath"
    }

    # Console output
    Write-Output "`n=== TUNNELING TOOL DETECTION: $ComputerName ==="
    if ($DetectedTools.Count -gt 0) {
        Write-Output "DETECTED ($($DetectedTools.Count) tools found):"
        $DetectedTools | ForEach-Object {
            Write-Output "  [RISK:$($_.RiskLevel)] $($_.ToolName)"
            Write-Output "    Detection: $($_.DetectionHits)"
            Write-Output "    Notes: $($_.Notes)"
        }
    } else {
        Write-Output "  No tunneling tools detected."
    }
    if ($ExcludedTools.Count -gt 0) { Write-Output "`nExcluded (by parameter): $($ExcludedTools -join ', ')" }
    Write-Output "`nCSV report: $CsvPath"
    if ($OutputHtml -eq 1) { Write-Output "HTML report: $HtmlPath" }

    $MyExitStatus = 0
    #endregion main

    #region finalization
    if ($logFileFolderPath -ne "") {
        Write-Output "`nScript $scriptName ended at $(Get-TimeStamp)"
        $elapsedTime = $(Get-Date) - $StartTime
        Write-Output "Elapsed time (seconds): $($elapsedTime.TotalSeconds)"
        Stop-Transcript
        if (($emailServer -ne "") -and ($emailUsername -ne "") -and ($emailPassword -ne "") -and ($emailFrom -ne "") -and ($emailTo -ne "")) {
            $attachments = @($logFilePath, $CsvPath) + $(if ($OutputHtml -eq 1 -and (Test-Path $HtmlPath)) { $HtmlPath })
            Send-MailMessage -SmtpServer "$emailServer" -Port $emailPort -From "$emailFrom" -To "$emailTo" -Subject "$scriptName - $ComputerName - $MyExitStatus - Detections:$($DetectedTools.Count)" -Body "$logFilePath" -UseSsl -Credential (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$emailUsername", (ConvertTo-SecureString -String "$emailPassword" -AsPlainText -Force)) -Attachments $attachments
        }
        if (($shareLocation -ne "") -and ($shareUsername -ne "") -and ($sharePassword -ne "")) {
            [securestring]$secStringPassword = ConvertTo-SecureString $sharePassword -AsPlainText -Force
            [pscredential]$shareCred = New-Object System.Management.Automation.PSCredential ($shareUsername, $secStringPassword)
            New-PSDrive -Name LogStore -PSProvider FileSystem -Root "$shareLocation" -Description "Log Store" -Credential $shareCred
            Copy-Item -LiteralPath "$logFilePath" -Destination "LogStore:\" -Force -ErrorAction Continue
            Copy-Item -LiteralPath "$CsvPath"     -Destination "LogStore:\" -Force -ErrorAction Continue
            if ($OutputHtml -eq 1 -and (Test-Path $HtmlPath)) { Copy-Item -LiteralPath "$HtmlPath" -Destination "LogStore:\" -Force -ErrorAction Continue }
            Remove-PSDrive -Name LogStore
        } elseif ($shareLocation -ne "") {
            Copy-Item -LiteralPath $LogFilePath -Destination $ShareLocation  -Force -ErrorAction Continue
        }
    }
    Set-PSDebug -Trace 0
    exit $MyExitStatus
    #endregion finalization
}
