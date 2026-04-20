           Bitpusher
            \`._,'/
            (_- -_)
              \o/
          The Digital
              Fox
          @VinceVulpes
    https://theTechRelay.com
 https://github.com/bitpusher2k

# UtilityScripts-PS

## Various PowerShell scripts that have been handy

## By Bitpusher/The Digital Fox

## Collection version 2.0 last updated 2026-04

### Scripts generally follow PS template format at https://github.com/bitpusher2k/ScriptTemplates, except where scripts are not the type to be scheduled/used remotely.

### Scripts provided as-is. Use at your own risk. No guarantees or warranty provided.

* Audit-LocalGroupMembers.ps1 - Enumerates all local groups and their members on the endpoint.
* Check-AdAdminGroups.ps1 - Run on an Active Directory Domain Controller to report on membership of all privileged AD groups. Recursively resolves nested group membership.
* Check-PatchCompliance.ps1 - Checks Windows Update status via the WU COM API.
* Check-SubnetDevices.ps1 - Scans local subnet & attempts to identify devices by name & MAC address. Used for home network monitoring.
* ConvertTo-CsvOnDoubleNewline.ps1 - Function to convert a text file to CSV format by splitting on double newlines.
* Create-LocalAdmin.ps1 - Creates a local admin account.
* Deploy-Sysmon.ps1 - Script to deploy, upgrade, or update Sysmon configuration on an endpoint using the SwiftOnSecurity sysmon-config ruleset.
* Detect-Persistence.ps1 - Script to scan common persistence mechanisms on a Windows endpoint and output a CSV report.
* Detect-RAS.ps1 - Checks for common remote access software on endpoint.
* Detect-TunnelingTools.ps1 - Detects mesh VPN, reverse proxy, and tunneling tools that are increasingly used as command-and-control (C2) infrastructure by threat actors.
* Encode-Script.ps1/bat - Encodes PowerShell script/commands from clipboard into Base64 string and prepend execution command. BAT shim allows drag-and-drop of script to process, or double-click to run against clipboard contents.
* Export-SecurityEventSummary.ps1 - Queries the Windows Security event log for key incident-response event IDs, produces a grouped summary by EventID, and exports full event detail records to CSV.
* Find-InactiveAdObjects.ps1 - Run on an Active Directory Domain Controller to identify stale, orphaned, or misconfigured AD objects.
* FindFailedRdwebLogin.ps1 - Script to search through the IIS log files and find IPs with failed logins going back specified number of hours, list all IPs associated with more than specified threshold of failed logins, and block them using firewall rule.
* GenerateAdUserReport.ps1 - Generates a report of all AD users with password, group membership, and sign-in information. Particularly useful during mass password resets. 
* GenerateTempPassForAdList.ps1 - Generates random passwords based on an AD user report for mass account password resets.
* Get-ADComputerInventory.ps1 - Script to generate an Active Directory computer inventory report with details including name, OU, OS, last logon, and staleness.
* Get-EntraUserReport.ps1 - Queries Microsoft Entra ID (Azure AD) via the Microsoft.Graph PowerShell module to generate a security-focused user report.
* Get-SysInfoSnapshot.ps1 - Endpoint profile collection script. Collects OS version, hardware, network, patch status, pending reboot state, antivirus products, firewall status, and key service states.
* GetAllUserShares.ps1 - Searches through all local user registry hives and lists configured mapped shares.
* Set-AppNotification.ps1 - Script to enable/disable Windows notifications for an application by name for all users. Useful to suppress scareware browser notification messages.
* Set-AuditPolicyStronger.ps1 - Script to configure Windows Advanced Audit Policy based on the "Stronger Recommendations" from Microsoft's audit policy guidance.
* SetChromeExtension.ps1 - Force-install, block, and generate reports on Chrome/Edge extensions.
* SetFirefoxPolicy.ps1 - Force-install, block, and generate reports on Firefox extensions, and manage some policy settings.
* Uninstall-AppByName.ps1 - Improvement on UninstallX that uninstalls MSI/NSIS/Inno/winget/Win32_Product software by name.
* UninstallX.ps1 - Uninstalls MSI software by name.
