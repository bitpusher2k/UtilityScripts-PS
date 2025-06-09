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
# SetChromeExtension.ps1 - By Bitpusher/The Digital Fox
# v1.5 last updated 2025-06-08
# Script to install/add or remove/block Chrome/Edge (Chromium based) extensions through registry entries.
# Can generate report of machine-level (HKLM) force-installed/allowed/blocked extensions.
#
# Updates HKLM, so added/blocked extensions are applied machine-wide and cannot be superseded by user settings.
# Does not change HKCU (local user) specific settings.
#
# Can force-install extensions into Chrome.
# Can remove/block specific (by ID) or all (*) extensions from both Chrome and Edge.
#
# Known good Chrome extension ID reference:
# https://www.jamieweb.net/info/chrome-extension-ids/
#
# Known bad extension ID information & sources:
# https://palant.info/2023/06/08/another-cluster-of-potentially-malicious-chrome-extensions/
# https://github.com/palant/malicious-extensions-list/blob/main/list.txt
# https://github.com/mallorybowes/chrome-mal-ids/blob/master/current-list.csv
# https://gitlab-com.gitlab.io/gl-security/security-tech-notes/threat-intelligence-tech-notes/malicious-browser-extensions-feb-2025/
# https://secureannex.com/blog/searching-for-something-unknow/
# https://levelblue.com/blogs/security-essentials/stories-from-the-soc-registry-clues-to-pdf-blues-a-tale-of-pua-persistence
#
# Note: It may take a restart for Chrome policies to refresh. Manually reload policies from within the browser by going to chrome://policy
# and clicking "Reload policies".
# Running "gpupdate /force" will also refresh Chrome policies from registry immediately, even on a locally managed endpoint.
# Note that the capitalization of the registry keys (e.g. "ExtensionInstallForcelist") MATTERS.
#
# Usage:
# Can pass extension ID, path to CSV file with list of IDs, or use builtin lists to install/block extensions.
# Skip either by passing "skip" as the parameter value. By default (no parameters) the script will use built in block
# list and skip adding any extensions. Remove all extensions in Chrome/Edge with the -RemoveAll switch.
# Use the -BlockAll switch to block all Chrome/Edge extensions. Use the -ClearBlocks switch to clear all blocks.
#
# Usage Examples:
# powershell -executionpolicy bypass -f .\SetChromeExtension.ps1 # Block extensions using default lists built into script.
# powershell -executionpolicy bypass -f .\SetChromeExtension.ps1 -ExtensionIdAdd "builtin" # Block and add extensions using default lists built into script.
# powershell -executionpolicy bypass -f .\SetChromeExtension.ps1 -ExtensionIdAdd "ID to add" -ExtensionIdBlock "ID to block" # Replace "ID" fields with the extension ID from Chrome Web Store.
# powershell -executionpolicy bypass -f .\SetChromeExtension.ps1 -ExtensionIdAdd "CSV to add" -ExtensionIdBlock "CSV to block" # Replace "CSV" fields with path to a CSV file containing "ID" and "Name" columns listing extension IDs.
# powershell -executionpolicy bypass -f .\SetChromeExtension.ps1 -Report # Output report of machine-wide blocked/allowed/forced extensions without changing any settings.
# powershell -executionpolicy bypass -f .\SetChromeExtension.ps1 -RemoveAll # Remove all Chrome/Edge extensions from all user profiles.
# powershell -executionpolicy bypass -f .\SetChromeExtension.ps1 -BlockAll # Block all Chrome/Edge extensions machine-wide.
# powershell -executionpolicy bypass -f .\SetChromeExtension.ps1 -ClearBlocks # Clear all machine-wide extension blocks.
#
# Run with admin privileges
#
#chrome #edge #extension #add #remove #block #set #browser #script #powershell #report

param(
    [string]$ExtensionIdAdd = "skip",
    [string]$ExtensionIdBlock = "builtin",
    [switch]$Report = $false,
    [switch]$RemoveAll = $false,
    [switch]$BlockAll = $false,
    [switch]$ClearBlocks = $false,
    [string]$scriptName = "SetChromeExtension",
    [string]$Priority = "Normal",
    [int]$RandMax = "50",
    [string]$DebugPreference = "SilentlyContinue",
    [string]$VerbosePreference = "SilentlyContinue",
    [string]$InformationPreference = "Continue",
    [string]$logFileFolderPath = "C:\temp\log",
    [string]$ComputerName = $env:computername,
    [string]$ScriptUserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
    [string]$logFilePrefix = "$scriptName" + "_" + "$ComputerName" + "_",
    [string]$logFileDateFormat = "yyyyMMdd_HHmmss",
    [int]$logFileRetentionDays = 30,
    [string]$Encoding = "utf8bom" # PS 5 & 7: "Ascii" (7-bit), "BigEndianUnicode" (UTF-16 big-endian), "BigEndianUTF32", "Oem", "Unicode" (UTF-16 little-endian), "UTF32" (little-endian), "UTF7", "UTF8" (PS 5: BOM, PS 7: NO BOM). PS 7: "ansi", "utf8BOM", "utf8NoBOM"
)

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
    $str = "{0:yyyy-MM-dd} {0:HH:mm:ss}" -f $dt

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
}

$sw = [Diagnostics.StopWatch]::StartNew()
Write-Output "$scriptName started on $ComputerName by $ScriptUserName at  $(Get-TimeStamp)" | Tee-Object -FilePath $logFilePath -Append

$process = Get-Process -Id $pid
Write-Output "Setting process priority to `"$Priority`"" | Tee-Object -FilePath $logFilePath -Append
$process.PriorityClass = $Priority

#endregion initialization

#region functions
function Get-ExtensionList {
    param (
        [string]$RegPath
    )
    $ExtensionList = New-Object System.Collections.ArrayList
    if (!(Test-Path $RegPath)) {
        # Write-Output "`n$RegPath key not found." | Tee-Object -FilePath $logFilePath -Append
    } else {
        # Write-Output "`nKey found." | Tee-Object -FilePath $logFilePath -Append
        # $Number = 0
        # $NoMore = 0
        # do {
        #     $Number++
        #     try {
        #         $ExtensionProperty = Get-ItemProperty $RegPath -name $Number -ErrorAction Stop
        #         $ExtensionObj = [PSCustomObject]@{
        #             Name = $Number
        #             Value = $ExtensionProperty.$Number
        #         }
        #         $ExtensionList.add($ExtensionObj) | Out-Null
        #     } catch {
        #         $NoMore = 1
        #     }
        # } until ($NoMore -eq 1)
        Push-Location
        Set-Location $RegPath
        $ExtensionList = Get-Item . | Select-Object -ExpandProperty property | ForEach-Object { New-Object psobject -Property @{ "Name" = $_ ; "Value" = (Get-ItemProperty -Path . -Name $_).$_ } }
        Pop-Location
    }
    Return $ExtensionList
}

function Remove-BrowserExtensions {
    param (
        [string]$ExtPath
    )

    if (Test-Path $ExtPath) {
        Write-Output "Removing extensions from: $ExtPath" | Tee-Object -FilePath $logFilePath -Append
        Get-ChildItem -Path $ExtPath | ForEach-Object {
            Write-Output "Removing $($_.FullName)..." | Tee-Object -FilePath $logFilePath -Append
            Remove-Item -Path $_.FullName -Recurse -Force
        }
        Write-Output "Extensions removed from $ExtPath" | Tee-Object -FilePath $logFilePath -Append
    } else {
        Write-Output "$ExtPath does not exist or no extensions found." | Tee-Object -FilePath $logFilePath -Append
    }
}
#endregion functions

if ($Report -or $RemoveAll -or $BlockAll -or $ClearBlocks) {
    $ExtensionIdAdd = "skip"
    $ExtensionIdBlock = "skip"
}

if ($ExtensionIdAdd -eq "skip") {
    $AddList = New-Object System.Collections.ArrayList
} elseif ($ExtensionIdAdd -eq "builtin") {
    $AddList = ConvertFrom-Csv @'
ID,Name
"nngceckbapebfimnlniiiahkandclblb","Bitwarden Password Manager"
"eimadpbcbfnmbkopoojfekhnkhdbieeh","Dark Reader"
"cjpalhdlnbpafiamejdnhcphjbkeiagm","uBlock Origin"
'@
} elseif ($ExtensionIdAdd -match ".csv") {
    $AddList = Import-Csv "$ExtensionIdAdd"
} else {
    $hash = @{
        ID  = "$ExtensionIdAdd"
        Name = ""
    }
    $AddList = [pscustomobject]$hash
}

if ($ExtensionIdBlock -eq "skip") {
    $BlockList = New-Object System.Collections.ArrayList
} elseif ($ExtensionIdBlock -eq "builtin") {
    $BlockList = ConvertFrom-Csv @'
ID,Name
"fmpomgllfigphmfffdmninpchjphngkh","Malware Extension (Name: Extension Optimizer)"
"mdaboflcmhejfihjcbmdiebgfchigjcf","Malware Extension (Name: Blipshot: one click full page screenshots)"
"gaoflciahikhligngeccdecgfjngejlh","Malware Extension (Name: Emojis - Emoji Keyboard)"
"fedimamkpgiemhacbdhkkaihgofncola","Malware Extension (Name: WAToolkit)"
"jlhgcomgldfapimdboelilfcipigkgik","Malware Extension (Name: Color Changer for YouTube)"
"jdjldbengpgdcfkljfdmakdgmfpneldd","Malware Extension (Name: Video Effects for YouTube And Audio Enhancer)"
"deljjimclpnhngmikaiiodgggdniaooh","Malware Extension (Name: Themes for Chrome and YouTube™ Picture in Picture)"
"giaoehhefkmchjbbdnahgeppblbdejmj","Malware Extension (Name: Mike Adblock für Chrome | Chrome-Werbeblocker)"
"hmooaemjmediafeacjplpbpenjnpcneg","Malware Extension (Name: Page Refresh)"
"acbiaofoeebeinacmcknopaikmecdehl","Malware Extension (Name: Wistia Video Downloader)"
"nlgphodeccebbcnkgmokeegopgpnjfkc","Malware Extension (Name: Super dark mode)"
"fbcgkphadgmbalmlklhbdagcicajenei","Malware Extension (Name: Emoji keyboard emojis for chrome)"
"alplpnakfeabeiebipdmaenpmbgknjce","Malware Extension (Name: Adblocker for Chrome - NoAds)"
"ogcaehilgakehloljjmajoempaflmdci","Malware Extension (Name: Adblock for You)"
"onomjaelhagjjojbkcafidnepbfkpnee","Malware Extension (Name: Adblock for Chrome)"
"bpconcjcammlapcogcnnelfmaeghhagj","Malware Extension (Name: Nimble capture)"
"gdocgbfmddcfnlnpmnghmjicjognhonm","Malware Extension (Name: KProxy)"
"odccobbfnngplckpongkahajfjpnbcck","Malware Extension (Secure Annex)"
"afefmfbcccnppcaiebpmbpmddhilkkdi","Malware Extension (Secure Annex)"
"oaljkhbgbedmfoiieocoenglpaeogjmf","Malware Extension (Secure Annex)"
"ndajnaaobjaganokllcgbapngenfbgkc","Malware Extension (Secure Annex)"
"okjdbeegldeilceaflghgfdemobmfhbd","Malware Extension (Secure Annex)"
"jhigofkbdbndeooldpdhmphldaglejlh","Malware Extension (Secure Annex)"
"pmgmbeeafpdjjhmeaalneginpmdhamhe","Malware Extension (Secure Annex)"
"eobcealmgdjeoheieiobkedbgddicaba","Malware Extension (Secure Annex)"
"lnedcnepmplnjmfdiclhbfhneconamoj","Malware Extension (Secure Annex)"
"gadjnphfolikkffmppnicebdfimlblkj","Malware Extension (Secure Annex)"
"njfkgeajknkffkngdmjmjninkbgjedlo","Malware Extension (Secure Annex)"
"eldjnmdpkecnjjkmmgndpcibgkfpodfh","Malware Extension (Secure Annex)"
"omieocempinhilcpbmnfdaamgomapded","Malware Extension (Secure Annex)"
"ilgbcnkedmncjlhpfconadpjnhlflejf","Malware Extension (Secure Annex)"
"okggiiagcegdfiajlkodohfkeemnjlnd","Malware Extension (Secure Annex)"
"jgajjllfidghjkjfipmjbaegafkdpfha","Malware Extension (Secure Annex)"
"gpibjjfllodpcfhcjpamonnblkbinbie","Malware Extension (Secure Annex)"
"hpdpddnfjaacnbcnoohlcipfafkbmdja","Malware Extension (Secure Annex)"
"lljnhidbljbfkejjcfogkhgmgdihjmlf","Malware Extension (Secure Annex)"
"gclgncjpanihjpbjbecgfmfnipggcckn","Malware Extension (Secure Annex)"
"cpehflfpgdgofpocagbdeecjlfhjfjdh","Malware Extension (Secure Annex)"
"mdenajpfccjjjnbochgkdahmnipfpelc","Malware Extension (Secure Annex)"
"eoclijfghiglinncpceohgaigfgnlbim","Malware Extension (Secure Annex)"
"cghdfcbncfjhleinblpalngjhojokjeo","Malware Extension (Secure Annex)"
"jeahgicmhigopdgilnmclihdjjlhnmop","Malware Extension (Secure Annex)"
"edbhdbhgdbanjhdnpjcianjgfmdkgbcf","Malware Extension (Secure Annex)"
"jjnfhbcilcppomkcmkbbmcadoihkkgah","Malware Extension (Secure Annex)"
"dmnajaiijohbndidolbdbpicdjanombo","Malware Extension (Secure Annex)"
"gpghebehjahceknfdcfifeifhdbongld","Malware Extension (Secure Annex)"
"gidejehfgombmkfflghejpncblgfkagj","Malware Extension (Secure Annex)"
"kjincgipkjkimkcmolmajgcfpdjbckgc","Malware Extension (Secure Annex)"
"koolcjajfdkjjfklmidahmcjhcmmkhma","Malware Extension (Secure Annex)"
"gijlkeaijpeaoihdajcgmiajeoonnkoj","Malware Extension (Secure Annex)"
"kldgaejigkhpgmfglbamggiglngkifck","Malware Extension (Secure Annex)"
"ojlhcbolfcndnojcjhhjgmdblnojgefm","Malware Extension (Secure Annex)"
"kiecdaoopedhfgapicmpebbhodepnbbp","Malware Extension (Secure Annex)"
"dmakkciciccnjgmfjflpbdfkdnmpfghp","Malware Extension (Secure Annex)"
"ebhcaliljppmelancooakfgcgcceiind","Malware Extension (Secure Annex)"
"eekblbhfmladafbmpgkdedmolbjkjbnc","Malware Extension (Secure Annex)"
"ejkdgndbgpfcaggpmnijcbddlnmdnpka","Malware Extension (Secure Annex)"
"fojomppheellamdaddnbgommepnlkooh","Malware Extension (Secure Annex)"
"gmbebpcapalekeaoekfhpbioilghcfmp","Malware Extension (Secure Annex)"
"ndcphhjcebhifabfmebineokbfdnbphm","Malware Extension (Secure Annex)"
"oghbffaoaooigagpockijkpfpgmnibkh","Malware Extension (Secure Annex)"
"oppeaknhldjjnfnflbcedipjbnbimhhf","Malware Extension (Secure Annex)"
"pcfapghfanllmbdfiipeiihpkojekckk","Malware Extension (Secure Annex)"
"lfmdddfdacgdimongmjclgijepoknmjm","Malware Extension (Secure Annex)"
"pmannhofeaiadkcdbcebhnkcnkjjnfpn","Malware Extension (Secure Annex)"
"lkbfbidpkbeicafnnhlaockggaknjolf","Malware Extension (Secure Annex)"
"adjpoipklnhlapjijccnemdhkcphcegd","Malware Extension (Secure Annex)"
"dkcjihabohaldgjkdmenepolojcjdaah","Malware Extension (Secure Annex)"
"iiegilogjnagependdonbfcmfmmaamon","Malware Extension (Secure Annex)"
"aiaaeimmjjeceodjpficfnjckenedbon","Malware Extension (Secure Annex)"
"alogdolelipkojjgggejccalcbdioolg","Malware Extension (Secure Annex)"
"fchgahponkgfomlgieipannlfanfbfak","Malware Extension (Secure Annex)"
"fojomppheellamdaddnbgommepnlkooh","Malware Extension (Secure Annex)"
"ldanhaibkdifncinbpjdjpambmofmpkf","Malware Extension (Secure Annex)"
"aehjmdkbfemaefoebbihbfcmhehgimcl","Malware Extension (Secure Annex)"
"acmnokigkgihogfbeooklgemindnbine","Malware Extension (mallorybowes)"
"apgohnlmnmkblgfplgnlmkjcpocgfomp","Malware Extension (mallorybowes)"
"apjnadhmhgdobcdanndaphcpmnjbnfng","Malware Extension (mallorybowes)"
"bahkljhhdeciiaodlkppoonappfnheoi","Malware Extension (mallorybowes)"
"bannaglhmenocdjcmlkhkcciioaepfpj","Malware Extension (mallorybowes)"
"bgffinjklipdhacmidehoncomokcmjmh","Malware Extension (mallorybowes)"
"bifdhahddjbdbjmiekcnmeiffabcfjgh","Malware Extension (mallorybowes)"
"bjpknhldlbknoidifkjnnkpginjgkgnm","Malware Extension (mallorybowes)"
"blngdeeenccpfjbkolalandfmiinhkak","Malware Extension (mallorybowes)"
"ccdfhjebekpopcelcfkpgagbehppkadi","Malware Extension (mallorybowes)"
"cceejgojinihpakmciijfdgafhpchigo","Malware Extension (mallorybowes)"
"cebjhmljaodmgmcaecenghhikkjdfabo","Malware Extension (mallorybowes)"
"chbpnonhcgdbcpicacolalkgjlcjkbbd","Malware Extension (mallorybowes)"
"cifafogcmckphmnbeipgkpfbjphmajbc","Malware Extension (mallorybowes)"
"clopbiaijcfolfmjebjinippgmdkkppj","Malware Extension (mallorybowes)"
"cpgoblgcfemdmaolmfhpoifikehgbjbf","Malware Extension (mallorybowes)"
"dcmjopnlojhkngkmagminjbiahokmfig","Malware Extension (mallorybowes)"
"deiiiklocnibjflinkfmefpofgcfhdga","Malware Extension (mallorybowes)"
"dipecofobdcjnpffbkmfkdbfmjfjfgmn","Malware Extension (mallorybowes)"
"dopkmmcoegcjggfanajnindneifffpck","Malware Extension (mallorybowes)"
"dopmojabcdlfbnppmjeaajclohofnbol","Malware Extension (mallorybowes)"
"edcepmkpdojmciieeijebkodahjfliif","Malware Extension (mallorybowes)"
"ekbecnhekcpbfgdchfjcfmnocdfpcanj","Malware Extension (mallorybowes)"
"elflophcopcglipligoibfejllmndhmp","Malware Extension (mallorybowes)"
"eogfeijdemimhpfhlpjoifeckijeejkc","Malware Extension (mallorybowes)"
"fcobokliblbalmjmahdebcdalglnieii","Malware Extension (mallorybowes)"
"fgafnjobnempajahhgebbbpkpegcdlbf","Malware Extension (mallorybowes)"
"fgcomdacecoimaejookmlcfogngmfmli","Malware Extension (mallorybowes)"
"fgmeppijnhhafacemgoocgelcflipnfd","Malware Extension (mallorybowes)"
"fhanjgcjamaagccdkanegeefdpdkeban","Malware Extension (mallorybowes)"
"flfkimeelfnpapcgmobfgfifhackkend","Malware Extension (mallorybowes)"
"fmahbaepkpdimfcjpopjklankbbhdobk","Malware Extension (mallorybowes)"
"foebfmkeamadbhjcdglihfijdaohomlm","Malware Extension (mallorybowes)"
"fpngnlpmkfkhodklbljnncdcmkiopide","Malware Extension (mallorybowes)"
"gdifegeihkihjbkkgdijkcpkjekoicbl","Malware Extension (mallorybowes)"
"gfcmbgjehfhemioddkpcipehdfnjmief","Malware Extension (mallorybowes)"
"gfdefkjpjdbiiclhimebabkmclmiiegk","Malware Extension (mallorybowes)"
"ggijmaajgdkdijomfipnpdfijcnodpip","Malware Extension (mallorybowes)"
"ghgjhnkjohlnmngbniijbkidigifekaa","Malware Extension (mallorybowes)"
"gllihgnfnbpdmnppfjdlkciijkddfohn","Malware Extension (mallorybowes)"
"gmmohhcojdhgbjjahhpkfhbapgcfgfne","Malware Extension (mallorybowes)"
"gofhadkfcffpjdbonbladicjdbkpickk","Malware Extension (mallorybowes)"
"hapicipmkalhnklammmfdblkngahelln","Malware Extension (mallorybowes)"
"hijipblimhboccjcnnjnjelcdmceeafa","Malware Extension (mallorybowes)"
"hmamdkecijcegebmhndhcihjjkndbjgk","Malware Extension (mallorybowes)"
"hodfejbmfdhcgolcglcojkpfdjjdepji","Malware Extension (mallorybowes)"
"hpfijbjnmddglpmogpaeofdbehkpball","Malware Extension (mallorybowes)"
"ianfonfnhjeidghdegbkbbjgliiciiic","Malware Extension (mallorybowes)"
"ibfjiddieiljjjccjemgnoopkpmpniej","Malware Extension (mallorybowes)"
"inhdgbalcopmbpjfincjponejamhaeop","Malware Extension (mallorybowes)"
"iondldgmpaoekbgabgconiajpbkebkin","Malware Extension (mallorybowes)"
"ipagcbjbgailmjeaojmpiddflpbgjngl","Malware Extension (mallorybowes)"
"jagbooldjnemiedoagckjomjegkopfno","Malware Extension (mallorybowes)"
"jdheollkkpfglhohnpgkonecdealeebn","Malware Extension (mallorybowes)"
"jfefcmidfkpncdkjkkghhmjkafanhiam","Malware Extension (mallorybowes)"
"jfgkpeobcmjlocjpfgocelimhppdmigj","Malware Extension (mallorybowes)"
"jghiljaagglmcdeopnjkfhcikjnddhhc","Malware Extension (mallorybowes)"
"jgjakaebbliafihodjhpkpankimhckdf","Malware Extension (mallorybowes)"
"jiiinmeiedloeiabcgkdcbbpfelmbaff","Malware Extension (mallorybowes)"
"jkdngiblfdmfjhiahibnnhcjncehcgab","Malware Extension (mallorybowes)"
"jkofpdjclecgjcfomkaajhhmmhnninia","Malware Extension (mallorybowes)"
"kbdbmddhlgckaggdapibpihadohhelao","Malware Extension (mallorybowes)"
"keceijnpfmmlnebgnkhojinbkopolaom","Malware Extension (mallorybowes)"
"khhemdcdllgomlbleegjdpbeflgbomcj","Malware Extension (mallorybowes)"
"kjdcopljcgiekkmjhinmcpioncofoclg","Malware Extension (mallorybowes)"
"kjgaljeofmfgjfipajjeeflbknekghma","Malware Extension (mallorybowes)"
"labpefoeghdmpbfijhnnejdmnjccgplc","Malware Extension (mallorybowes)"
"lameokaalbmnhgapanlloeichlbjloak","Malware Extension (mallorybowes)"
"lbeekfefglldjjenkaekhnogoplpmfin","Malware Extension (mallorybowes)"
"lbhddhdfbcdcfbbbmimncbakkjobaedh","Malware Extension (mallorybowes)"
"ldoiiiffclpggehajofeffljablcodif","Malware Extension (mallorybowes)"
"lhjdepbplpkgmghgiphdjpnagpmhijbg","Malware Extension (mallorybowes)"
"ljddilebjpmmomoppeemckhpilhmoaok","Malware Extension (mallorybowes)"
"ljnfpiodfojmjfbiechgkbkhikfbknjc","Malware Extension (mallorybowes)"
"lnedcnepmplnjmfdiclhbfhneconamoj","Malware Extension (mallorybowes)"
"lnlkgfpceclfhomgocnnenmadlhanghf","Malware Extension (mallorybowes)"
"loigeafmbglngofpkkddgobapkkcaena","Malware Extension (mallorybowes)"
"lpajppfbbiafpmbeompbinpigbemekcg","Malware Extension (mallorybowes)"
"majekhlfhmeeplofdolkddbecmgjgplm","Malware Extension (mallorybowes)"
"mapafdeimlgplbahigmhneiibemhgcnc","Malware Extension (mallorybowes)"
"mcfeaailfhmpdphgnheboncfiikfkenn","Malware Extension (mallorybowes)"
"mgkjakldpclhkfadefnoncnjkiaffpkp","Malware Extension (mallorybowes)"
"mhinpnedhapjlbgnhcifjdkklbeefbpa","Malware Extension (mallorybowes)"
"mihiainclhehjnklijgpokdpldjmjdap","Malware Extension (mallorybowes)"
"mmkakbkmcnchdopphcbphjioggaanmim","Malware Extension (mallorybowes)"
"mopkkgobjofbkkgemcidkndbglkcfhjj","Malware Extension (mallorybowes)"
"mpifmhgignilkmeckejgamolchmgfdom","Malware Extension (mallorybowes)"
"nabmpeienmkmicpjckkgihobgleppbkc","Malware Extension (mallorybowes)"
"nahhmpbckpgdidfnmfkfgiflpjijilce","Malware Extension (mallorybowes)"
"ncepfbpjhkahgdemgmjmcgbgnfdinnhk","Malware Extension (mallorybowes)"
"npaklgbiblcbpokaiddpmmbknncnbljb","Malware Extension (mallorybowes)"
"npdfkclmbnoklkdebjfodpendkepbjek","Malware Extension (mallorybowes)"
"nplenkhhmalidgamfdejkblbaihndkcm","Malware Extension (mallorybowes)"
"oalfdomffplbcimjikgaklfamodahpmi","Malware Extension (mallorybowes)"
"odnakbaioopckimfnkllgijmkikhfhhf","Malware Extension (mallorybowes)"
"oklejhdbgggnfaggiidiaokelehcfjdp","Malware Extension (mallorybowes)"
"omgeapkgiddakeoklcapboapbamdgmhp","Malware Extension (mallorybowes)"
"oonbcpdabjcggcklopgbdagbfnkhbgbe","Malware Extension (mallorybowes)"
"opahibnipmkjincplepgjiiinbfmppmh","Malware Extension (mallorybowes)"
"pamchlfnkebmjbfbknoclehcpfclbhpl","Malware Extension (mallorybowes)"
"pcfapghfanllmbdfiipeiihpkojekckk","Malware Extension (mallorybowes)"
"pchfjdkempbhcjdifpfphmgdmnmadgce","Malware Extension (mallorybowes)"
"pdpcpceofkopegffcdnffeenbfdldock","Malware Extension (mallorybowes)"
"pgahbiaijngfmbbijfgmchcnkipajgha","Malware Extension (mallorybowes)"
"pidohlmjfgjbafgfleommlolmbjdcpal","Malware Extension (mallorybowes)"
"pilplloabdedfmialnfchjomjmpjcoej","Malware Extension (mallorybowes)"
"pklmnoldkkoholegljdkibjjhmegpjep","Malware Extension (mallorybowes)"
"pknkncdfjlncijifekldbjmeaiakdbof","Malware Extension (mallorybowes)"
"plmgefkiicjfchonlmnbabfebpnpckkk","Malware Extension (mallorybowes)"
"pnciakodcdnehobpfcjcnnlcpmjlpkac","Malware Extension (mallorybowes)"
"ponodoigcmkglddlljanchegmkgkhmgb","Malware Extension (mallorybowes)"
"oanbpfkcehelcjjipodkaafialmfejmi","Malware Extension (mallorybowes)"
"lhfibgclamcffnddoicjmoopmgomknmb","Malware Extension (mallorybowes)"
"ilcbbngkolbclhlildojhgjdbkkehfia","Malware Extension (mallorybowes)"
"pnhjnmacgahapmnnifmneapinilajfol","Malware Extension (mallorybowes)"
"ocifcogajbgikalbpphmoedjlcfjkhgh","Malware Extension (mallorybowes)"
"peglehonblabfemopkgmfcpofbchegcl","Malware Extension (mallorybowes)"
"aaeohfpkhojgdhocdfpkdaffbehjbmmd","Malware Extension (mallorybowes)"
"lidnmohoigekohfmdpopgcpigjkpemll","Malware Extension (mallorybowes)"
"jmbmildjdmppofnohldicmnkojfhggmb","Malware Extension (mallorybowes)"
"jdoaaldnifinadckcbfkbiekgaebkeif","Malware Extension (mallorybowes)"
"ogjfhmgoalinegalajpmjoliipdibhdm","Malware Extension (mallorybowes)"
"lebmkjafnodbnhbahbgdollaaabcmpbh","Malware Extension (mallorybowes)"
"gjammdgdlgmoidmdfoefkeklnhmllpjp","Malware Extension (mallorybowes)"
"kdkpllchojjkbgephbbeacaahecgfpga","Malware Extension (mallorybowes)"
"jaehldonmiabhfohkenmlimnceapgpnp","Malware Extension (mallorybowes)"
"pmhlkgkblgeeigiegkmacefjoflennbn","Malware Extension (mallorybowes)"
"ofdfbeanbffehepagohhengmjnhlkich","Malware Extension (mallorybowes)"
"mjchijabihjkhmmaaihpgmhkklgakinl","Malware Extension (mallorybowes)"
"poppendnaoonepbkmjejdfebihohaalo","Malware Extension (mallorybowes)"
"eogoljjmndnjfikmcbmopmlhjnhbmdda","Malware Extension (mallorybowes)"
"gdnkjjhpffldmfljpbfemliidkeeecdj","Malware Extension (mallorybowes)"
"gelcjfdfebnabkielednfoogpbhdeoai","Malware Extension (mallorybowes)"
"ofpihhkeakgnnbkmcoifjkkhnllddbld","Malware Extension (mallorybowes)"
"pjjghngpidphgicpgdebpmdgdicepege","Malware Extension (mallorybowes)"
"nchdkdaknojhpimbfbejfcdnmjfbllhj","Malware Extension (mallorybowes)"
"blcfpeooekoekehdpbikibeblpjlehlh","Malware Extension (mallorybowes)"
"looclnmoilplejheganiloofamfilbcd","Malware Extension (mallorybowes)"
"oehimkphpeeeneindfeekidpmkpffkgc","Malware Extension (mallorybowes)"
"eebbihndkbkejmlgfoofigacgicamfha","Malware Extension (mallorybowes)"
"faopefnnleiebimhkldlplkgkjpbmcea","Malware Extension (mallorybowes)"
"obcfkcpejehknjdollnafpebkcpkklbl","Malware Extension (mallorybowes)"
"jepocknhdcgdmbiodbpopcbjnlgecdhf","Malware Extension (mallorybowes)"
"dehhfjanlmglmabomenmpjnnopigplae","Malware Extension (mallorybowes)"
"ekijhekekfckmkmbemiijdkihdibnbgh","Malware Extension (mallorybowes)"
"pjpjefgijnjlhgegceegmpecklonpdjp","Malware Extension (mallorybowes)"
"nlhocomjnfjedielocojomgfldbjmdjj","Malware Extension (mallorybowes)"
"opooaebceonakifaacigffdhogdgfadg","Malware Extension (mallorybowes)"
"ojofdaokgfdlbeomlelkiiipkocneien","Malware Extension (mallorybowes)"
"gpaaalbnkccgmmbkendiciheljgpdhob","Malware Extension (mallorybowes)"
"almfnpjmjpnknlgpipillhfmchjikkno","Malware Extension (mallorybowes)"
"eeacchjlmkcleifpppcjbmahcnlihamj","Malware Extension (mallorybowes)"
"lojgkcienjoiogbfkbjiidpfnabhkckf","Malware Extension (mallorybowes)"
"gkemhapalomnipjhminflfhjcjehjhmp","Malware Extension (mallorybowes)"
"icolkoeolaodpjogekifcidcdbgbdobc","Malware Extension (mallorybowes)"
"abjbfhcehjndcpbiiagdnlfolkbfblpb","Malware Extension (mallorybowes)"
"bbjilncoookdcjjnkcdaofiollndepla","Malware Extension (mallorybowes)"
"igpcgjcdhmdjhdlgoncfnpkdipanlida","Malware Extension (mallorybowes)"
"nfhpojfdhcdmimokleagkdcbkmcgfjkh","Malware Extension (mallorybowes)"
"jfnlkmaledafkdhdokgnhlcmeamakham","Malware Extension (mallorybowes)"
"dibjpjiifnahccnokciamjlfgdlgimmn","Malware Extension (mallorybowes)"
"fjclfmhapndgeabdcikbhemimpijpnah","Malware Extension (mallorybowes)"
"jpnamljnefhpbpcofcbonjjjkmfjbhdp","Malware Extension (mallorybowes)"
"iggmbfojpkfikoahlfghaalpbpkhfohc","Malware Extension (mallorybowes)"
"fkllfgoempnigpogkgkgmghkchmjcjni","Malware Extension (mallorybowes)"
"dealfjgnmkibkcldkcpbikenmajlglmc","Malware Extension (mallorybowes)"
"abghmipjfclfpgmmelbgolfgmhnigbma","Malware Extension (mallorybowes)"
"dcbfmglfdlgpnolgdjoioeocllioebpe","Malware Extension (mallorybowes)"
"obmbmalbahpfbckpcfbipooimkldgphm","Malware Extension (mallorybowes)"
"gbkmkgfjngebdcpklbkeccelcjaobblk","Malware Extension (mallorybowes)"
"ehibgcefkpbfkklbpahilhicidnhiboc","Malware Extension (mallorybowes)"
"gmljddfeipofcffbhhcpohkegndieeab","Malware Extension (mallorybowes)"
"dajgdhiemoaecngkpliephmheifopmjb","Malware Extension (mallorybowes)"
"fdbmoflclpmkmeobidcgmfamkicinnlg","Malware Extension (mallorybowes)"
"obbfndpanmiplgfcbeonoocobbnjdmdc","Malware Extension (mallorybowes)"
"lgljionbhcfbnpjgfnhhoadpdngkmfnh","Malware Extension (mallorybowes)"
"ddenjpheppdmfimooolgihimdgpilhfo","Malware Extension (mallorybowes)"
"bblkckhknhmalchbceidkmjalmcmnkfa","Malware Extension (mallorybowes)"
"fhkmacopackahlbnpcfijgphgoimpggb","Malware Extension (mallorybowes)"
"eohnfgagodblipmmalphhfepaonpnjgk","Malware Extension (mallorybowes)"
"emkkigmmpfbjmikfadmfeebomholoikg","Malware Extension (mallorybowes)"
"fekjbjbbdopogpamkmdjpjicapclgamj","Malware Extension (mallorybowes)"
"afephhbbcdlgdehhddfnehfndnkfbgnm","Malware Extension (mallorybowes)"
"agfjbfkpehcnceblmdahjaejpnnnkjdn","Malware Extension (mallorybowes)"
"ahikdohkiedoomaklnohgdnmfcmbabcn","Malware Extension (mallorybowes)"
"ahlfiinafajfmciaajgophipcfholmeh","Malware Extension (mallorybowes)"
"akglkgdiggmkilkhejagginkngocbpbj","Malware Extension (mallorybowes)"
"anihmmejabpaocacmeodiapbhpholaom","Malware Extension (mallorybowes)"
"bhkcgfbaokmhglgipbppoobmoblcomhh","Malware Extension (mallorybowes)"
"bkanfnnhokogflpnhnbfjdhbjdlgncdi","Malware Extension (mallorybowes)"
"bpfdhglfmfepjhgnhnmclbfiknjnfblb","Malware Extension (mallorybowes)"
"bpklfenmjhcjlocdicfadpfppcgojfjp","Malware Extension (mallorybowes)"
"ckelhijilmmlmnaljmjpigfopkmfkoeh","Malware Extension (mallorybowes)"
"dbcfhcelmjepboabieglhjejeolaopdl","Malware Extension (mallorybowes)"
"dbcfokmgampdedgcefjahloodbgakkpl","Malware Extension (mallorybowes)"
"ddohdfnenhipnhnbbfifknnhaomihcip","Malware Extension (mallorybowes)"
"dehindejipifeaikcgbkdijgkbjliojc","Malware Extension (mallorybowes)"
"dkhcmjfipgoapjamnngolidbcakpdhgf","Malware Extension (mallorybowes)"
"effhjobodhmkbgfpgcdabfnjlnphakhb","Malware Extension (mallorybowes)"
"egpnofbhgafhbkapdhedimohmainbiio","Malware Extension (mallorybowes)"
"ehlgimmlmmcocemjadeafmohiplmgmei","Malware Extension (mallorybowes)"
"epphnioigompfjaknnaokghgcncnjfbe","Malware Extension (mallorybowes)"
"gbbpilgcdcmfppjkdociebhmcnbfbmod","Malware Extension (mallorybowes)"
"glmbceclkhkaebcadgmbcjihllcnpmjh","Malware Extension (mallorybowes)"
"gpffceikmehgifkjjginoibpceadefih","Malware Extension (mallorybowes)"
"idnelecdpebmbpnmambnpcjogingdfco","Malware Extension (mallorybowes)"
"ifceimlckdanenfkfoomccpcpemphlbg","Malware Extension (mallorybowes)"
"ifmkfoeijeemajoodjfoagpbejmmnkhm","Malware Extension (mallorybowes)"
"igkljanmhbnhedgkmgpkcgpjmociceim","Malware Extension (mallorybowes)"
"ijhakgidfnlallpobldpbhandllbeobg","Malware Extension (mallorybowes)"
"ijohicfhndicpnmkaldafhbecijhdikd","Malware Extension (mallorybowes)"
"jbfponbaiamgjmfpfghcjjhddjdjdpna","Malware Extension (mallorybowes)"
"jfamimfejiccpbnghhjfcibhkgblmiml","Malware Extension (mallorybowes)"
"jlaaidmjgpgfkhehcljmeckhlaibgaol","Malware Extension (mallorybowes)"
"kjnmimfgphmcppjhombdhhegpjphpiol","Malware Extension (mallorybowes)"
"lfaahmcgahoalphllknbfcckggddoffj","Malware Extension (mallorybowes)"
"mcbcknmlpfkbpogpnfcimfgdmchchmmg","Malware Extension (mallorybowes)"
"mciddpldhpdpibckghnaoidpolnmighk","Malware Extension (mallorybowes)"
"mjbimaghobnkobfefccnnnjedoefbafl","Malware Extension (mallorybowes)"
"mnbhnjecaofgddbldmppbbdlokappkgk","Malware Extension (mallorybowes)"
"nicmhgecboifljcnbbjlajbpagmhcclp","Malware Extension (mallorybowes)"
"njhfmnfcoffkdjbgpannpgifnbgdihkl","Malware Extension (mallorybowes)"
"noilkpnilphojpjaimfcnldblelgllaa","Malware Extension (mallorybowes)"
"obcfoaeoidokjbaokikamaljjlpebofe","Malware Extension (mallorybowes)"
"oejafikjmfmejaafjjkoeejjpdfkdkpc","Malware Extension (mallorybowes)"
"ogaclpidpghafcnbchgpbigfegdbdikj","Malware Extension (mallorybowes)"
"opmelhjohnmenjibglddlpmbpbocohck","Malware Extension (mallorybowes)"
"pbilbjpkfbfbackdcejdmhdfgeldakkn","Malware Extension (mallorybowes)"
"pcmdfnnipgpilomfclbnjpbdnmbcgjaf","Malware Extension (mallorybowes)"
"pedokobimilhjemibclahcelgedmkgei","Malware Extension (mallorybowes)"
"plnlhldekkpgnngfdbdhocnjfplgnekg","Malware Extension (mallorybowes)"
"nonjdcjchghhkdoolnlbekcfllmednbl","Malware Extension (mallorybowes)"
"pgeolalilifpodheeocdmbhehgnkkbak","Malware Extension (mallorybowes)"
"gnamdgilanlgeeljfnckhboobddoahbl","Malware Extension (mallorybowes)"
"alecjlhgldihcjjcffgjalappiifdhae","Malware Extension (mallorybowes)"
"kelbkhobcfhdcfhohdkjnaimmicmhcbo","Malware Extension (mallorybowes)"
"dpglnfbihebejclmfmdcbgjembbfjneo","Malware Extension (mallorybowes)"
"lpjhpdcflkecpciaehfbpafflkeomcnb","Malware Extension (mallorybowes)"
"ckkgmccefffnbbalkmbbgebbojjogffn","Malware Extension (mallorybowes)"
"ppmibgfeefcglejjlpeihfdimbkfbbnm","Malware Extension (mallorybowes)"
"ginfoagmgomhccdaclfbbbhfjgmphkph","Malware Extension (mallorybowes)"
"mpneoicaochhlckfkackiigepakdgapj","Malware Extension (mallorybowes)"
"djffibmpaakodnbmcdemmmjmeolcmbae","Malware Extension (mallorybowes)"
"pejkmgfabkeddfcfldloonjbikjddapb","Malware Extension (mallorybowes)"
"gmddfjhfjgbmabkihepijkanhmlooajl","Malware Extension (mallorybowes)"
"kajjcgpohlkdcjfkcbkkbhapafcblaom","Malware Extension (mallorybowes)"
"anbnajjakpmfdofijejenaclbceejlll","Malware Extension (mallorybowes)"
"jkkmcoihchcflfjnigngdegbemipdlnl","Malware Extension (mallorybowes)"
"ajmchakbijebimbgcohecngliijaddin","Malware Extension (mallorybowes)"
"edpoobbacbcmfpnfpjoambjbihhobooi","Malware Extension (mallorybowes)"
"opfogdennafhaoihhkocppaajlkpbfbn","Malware Extension (mallorybowes)"
"ikojddbdekpboemgplhbloojlncbpmdd","Malware Extension (mallorybowes)"
"chlpbdodahbpifpjbcoocpfadoffdbpb","Malware Extension (mallorybowes)"
"flbcjbhgomclbhlchggbmnpekhfeacim","Malware Extension (mallorybowes)"
"aadmpgppfacognoeobmheghfiibdplcf","Malware Extension (mallorybowes)"
"abgfholnofpihncfdmombecmohpkojdb","Malware Extension (mallorybowes)"
"aciloeifdphkogbpagikkpiecbjkmedn","Malware Extension (mallorybowes)"
"acmgemnaochmalgkipbamjddcplkdmjm","Malware Extension (mallorybowes)"
"addpbbembilhmnkjpenjgcgmihlcofja","Malware Extension (mallorybowes)"
"adfjcmhegakkhojnallobfjbhenbkopj","Malware Extension (mallorybowes)"
"aeklcpmgaadjpglhjmcidlekijpnmdhc","Malware Extension (mallorybowes)"
"afifalglopajkmdkgnphpfkmgpgdngfj","Malware Extension (mallorybowes)"
"agldjlpmeladgadoikdbndmeljpmnajl","Malware Extension (mallorybowes)"
"ahmmgfhcokekfofjdndgmkffifklogbo","Malware Extension (mallorybowes)"
"aippaajbmefpjeajhgaahmicdpgepnnm","Malware Extension (mallorybowes)"
"akdpobnbjepjbnjklkkbdafemhnbfldj","Malware Extension (mallorybowes)"
"akhiflcfcbnheaofcaflofbmnkmjlnno","Malware Extension (mallorybowes)"
"aklklkifmplgnobmieahildcfbleamdb","Malware Extension (mallorybowes)"
"alppaffmlaefpmopolgpkgmncopkbbep","Malware Extension (mallorybowes)"
"amdnpfcpjglkdfcigaccfgmlmdepdpeo","Malware Extension (mallorybowes)"
"aomepndmhbbklcjcknnhdabaaofahjcj","Malware Extension (mallorybowes)"
"badbchbijjjadlpjkkhmefaghggjjeha","Malware Extension (mallorybowes)"
"bbbdfjdplonnggfjjbjhggobffkggnkm","Malware Extension (mallorybowes)"
"bbdldenhkjcoikalkfkgolomdpnncofc","Malware Extension (mallorybowes)"
"bcdjcbgogdomoebdcbniaifnacjbglil","Malware Extension (mallorybowes)"
"bcepmajicjlaoleoljbpaemkfghohmib","Malware Extension (mallorybowes)"
"bdbablmeheiahecklheciomhmkplcoml","Malware Extension (mallorybowes)"
"bfeecodfffgkdedfhmgbfindokikafid","Malware Extension (mallorybowes)"
"bhifimmocncplbnikchffepggmofkake","Malware Extension (mallorybowes)"
"blipiofdiknkllpajgepiiigfmfgnfep","Malware Extension (mallorybowes)"
"bmagbmnmkaknlnoohbmobfmlgndijecb","Malware Extension (mallorybowes)"
"bnecbeikepeloplclngelcgmgdnafhlp","Malware Extension (mallorybowes)"
"bpnmalopmgpilaoikaeafokedkkonhea","Malware Extension (mallorybowes)"
"cbncogjaakomibjcgdkpdjmlhfcjfojc","Malware Extension (mallorybowes)"
"ccgmdfdcnpcfmpceggggmnhbolkhlffi","Malware Extension (mallorybowes)"
"ccmnnlcciddhkdllgfmkojmmmpahdhlp","Malware Extension (mallorybowes)"
"cdpmhflbdaoifgkmlhpfkbfgcifchgpn","Malware Extension (mallorybowes)"
"cepgcjakdboolfkcbihdokfjjkeaddin","Malware Extension (mallorybowes)"
"cfadfngejcdogjkkdohpkgeodjooogip","Malware Extension (mallorybowes)"
"cgdmknakejoaompdmdeddpgmjffnniab","Malware Extension (mallorybowes)"
"cgodgjmdljiecnbcgdampafcmlgmfmid","Malware Extension (mallorybowes)"
"cibigjhoekijbagpgcgpgimebaiocdgm","Malware Extension (mallorybowes)"
"cjbdbomgdbdgdlainhobpjnfkoidcond","Malware Extension (mallorybowes)"
"clndgmolhlkchkbiinamamnbibkakiml","Malware Extension (mallorybowes)"
"cmbfgkkjfkmmhalhebnhmanbenfghkcm","Malware Extension (mallorybowes)"
"cncepimkmnhgbjmbcgoomegdkdhplihm","Malware Extension (mallorybowes)"
"cnfbbaddndiehkmhdmmngecaofaojaeo","Malware Extension (mallorybowes)"
"codilkcdacpeklilmgjknekfpminaieo","Malware Extension (mallorybowes)"
"dakenmmdlklnjdpdfmdjccpeapmijaad","Malware Extension (mallorybowes)"
"dapecdhpbakbfcoijjpdfoffnajhifej","Malware Extension (mallorybowes)"
"dckadbanpeemhkphnnllamgolhbbbebi","Malware Extension (mallorybowes)"
"ddodaoihhhohncjalnjgmgnlfhgckgdj","Malware Extension (mallorybowes)"
"dhbhgfiodedkhgocailljbhcfjhplibb","Malware Extension (mallorybowes)"
"dhcnonhheahlocjbbpkbammanpenpfop","Malware Extension (mallorybowes)"
"dhgmdjkeagnhamkedcejighocjkkijli","Malware Extension (mallorybowes)"
"dinlhhblgeikohhbfkcoeggglbjlanhg","Malware Extension (mallorybowes)"
"djjdjlbigcdjlghdioabbkjhdelmdhai","Malware Extension (mallorybowes)"
"dkcppkdodfegjkeefohjancleioblabi","Malware Extension (mallorybowes)"
"dkfbfgncahnfghoemhmmlfefhpolihom","Malware Extension (mallorybowes)"
"dmklpmfpkokephcjdmocddkhilglgajl","Malware Extension (mallorybowes)"
"dnimnhhaiphlclcocakkfgnnekoggjpl","Malware Extension (mallorybowes)"
"doecpeonnonddhfpabfgblijljennlcj","Malware Extension (mallorybowes)"
"dofbgmolpdoknlknfjddecnahgjpinpb","Malware Extension (mallorybowes)"
"dppogkehbpnikehcmadgkbimjnmhdnlo","Malware Extension (mallorybowes)"
"eapceolnilleaiiaapgionibccekkeom","Malware Extension (mallorybowes)"
"ecaejcfpngljeinjmahknbemhnddiioe","Malware Extension (mallorybowes)"
"ecgafllkghmmbnhacnpcobibalonhkkj","Malware Extension (mallorybowes)"
"edfmeionipdoohiagoaefljjhififgnl","Malware Extension (mallorybowes)"
"edgbooeklapanaclbchdiaekalebmfgb","Malware Extension (mallorybowes)"
"edohegfjelahakooigmnmkmjofcjgofe","Malware Extension (mallorybowes)"
"eeeiekjkpbneogggaajnjldadjmclhlo","Malware Extension (mallorybowes)"
"eejkpejdfojkbklnlnpgpojoidojbhnh","Malware Extension (mallorybowes)"
"efckalhlcogbdbfopffmbacghfoelaia","Malware Extension (mallorybowes)"
"efnaoofiidefjeefpnheopknaciohldg","Malware Extension (mallorybowes)"
"egdpmjnldpefdaiekiapjkanabfiaodp","Malware Extension (mallorybowes)"
"egicjjdcjhfdnejimnhngogjmoajffpm","Malware Extension (mallorybowes)"
"ejcefeinlmdmpnohebfckmodhdkhlgmk","Malware Extension (mallorybowes)"
"ejighbgeedkpcambhfkohdalcgckdein","Malware Extension (mallorybowes)"
"empoeejllbcgpkmghimibnapemegnihf","Malware Extension (mallorybowes)"
"enlaekiichndcbohopenblignipkjaoa","Malware Extension (mallorybowes)"
"enmomapaolnpbaenhilkjhmobpggjcpm","Malware Extension (mallorybowes)"
"eohabjkmhajbeaejogdikpgapkeigdki","Malware Extension (mallorybowes)"
"eoijplcnfnjgofchhdkkhpfcjkcefgkb","Malware Extension (mallorybowes)"
"facihnceaoboeoembnbmdlecmkpioacc","Malware Extension (mallorybowes)"
"fagaafjhdmoagacggplmbpganjfjjpcf","Malware Extension (mallorybowes)"
"fanonokndfeibplocpeipgfbopkigcce","Malware Extension (mallorybowes)"
"faokbgedcfhnfecloigcihpplicdnann","Malware Extension (mallorybowes)"
"fcdopghpidfdeglcheccmehiaedgpmkm","Malware Extension (mallorybowes)"
"fdacngbbemokpkmdkdefkoodndakgejc","Malware Extension (mallorybowes)"
"fdfffeipjpofnkmdkadjcjohdfoeblhk","Malware Extension (mallorybowes)"
"ffhamkjhfajcjlnobkogimnhiagohgfg","Malware Extension (mallorybowes)"
"fjnbjacfigdidgeeommhbdhnojamhpfg","Malware Extension (mallorybowes)"
"fjohhelccbogecmolmjemopgackpnmpg","Malware Extension (mallorybowes)"
"flagaiaajbikpfnnkodcphdcmgefmbcl","Malware Extension (mallorybowes)"
"flgfngbiaanimkhjkojnmilfalidpign","Malware Extension (mallorybowes)"
"fmngfipkcebejdconcibohjjgfmokhpa","Malware Extension (mallorybowes)"
"fnblapfcdifokdbkpcbhpkajlkgmcjii","Malware Extension (mallorybowes)"
"fpdjcfokkeooncckcolkmmppebjnfhgh","Malware Extension (mallorybowes)"
"fphafkamioonlcelldogidajbcmmicco","Malware Extension (mallorybowes)"
"fpjbgjpkfcanmdgjpmnnmoekkaahmafg","Malware Extension (mallorybowes)"
"fplmpcijomgjmfbjcidbgpjdmhmamlkf","Malware Extension (mallorybowes)"
"gdacidkmmbdpkedejaljplnfhjidomio","Malware Extension (mallorybowes)"
"gdoomgeeelkgcmmoibloelbodkpggdle","Malware Extension (mallorybowes)"
"geoolholooeeblajdjffdmknpecbkmah","Malware Extension (mallorybowes)"
"ghfgeefhkkoajgmnopaldgcagohakhmg","Malware Extension (mallorybowes)"
"ghhanhhegklhcoffmgkdbiekfhmbfbnc","Malware Extension (mallorybowes)"
"gjkigcdoljdojaaomnadffdhggoobdpc","Malware Extension (mallorybowes)"
"gkjkhpbembbjogoiejpkehohclfoljbp","Malware Extension (mallorybowes)"
"glibnbcgclecomknccifdaglefljfoej","Malware Extension (mallorybowes)"
"gllogphgdmclhfledlcgmdolngohamcl","Malware Extension (mallorybowes)"
"haagbldencigkgikfekmoaaofambnafp","Malware Extension (mallorybowes)"
"haglbigaalkckkedjamjibfnklbbodck","Malware Extension (mallorybowes)"
"hcgepcgbgnleafnfcepjbekchbdmekfa","Malware Extension (mallorybowes)"
"hdbchphkjjidcfidaelcpmonodhhaahp","Malware Extension (mallorybowes)"
"hdljgflalglmllbagpacjmkdiggliidk","Malware Extension (mallorybowes)"
"hdpnlijiblkmokbjljbahhgkpokgpkli","Malware Extension (mallorybowes)"
"heaphjoejcpdagahbnkkloiaicpadomp","Malware Extension (mallorybowes)"
"hjfmdhbmpagpfheceengkakdmpncmlif","Malware Extension (mallorybowes)"
"hjkjkmkoklbhjhlddialffkchddlncjb","Malware Extension (mallorybowes)"
"hjoihkjijjbkiglgeghbokincmidfped","Malware Extension (mallorybowes)"
"hncokbmdmbmmlkjhoagcpokehopdikhc","Malware Extension (mallorybowes)"
"hnhpnbajfmmopedidmiablkcdnlegkmd","Malware Extension (mallorybowes)"
"homdfmaeflodjknffbnhagmlhmgmbjac","Malware Extension (mallorybowes)"
"iccagibmclklcmiejfddepgffgkhnnib","Malware Extension (mallorybowes)"
"idkllmolbaiailjfidkjcidapkddidbg","Malware Extension (mallorybowes)"
"ifbffcgakkboaffkidggpcjolehhhbfd","Malware Extension (mallorybowes)"
"ifdebecchhapkfdbcbhpmjonmbpfpnck","Malware Extension (mallorybowes)"
"igbcfkjflkgamnoikcpiljglnmjnkjac","Malware Extension (mallorybowes)"
"iiblgogamkmdfojoclpdhainbndfpcci","Malware Extension (mallorybowes)"
"inkankpmoblmficechfgfinajifbfkdn","Malware Extension (mallorybowes)"
"ioejcipbmdjinhfciojiacdjolkabkmn","Malware Extension (mallorybowes)"
"iojhbljpppeociniiemjfelmdcgikmep","Malware Extension (mallorybowes)"
"ipgnnndhgeaclopjgiihppbbfnmkmjcm","Malware Extension (mallorybowes)"
"jckaglinbbflgcklfgacjdmgpnccmdng","Malware Extension (mallorybowes)"
"jfocahgaekfaemhfcfefcodphgpinnch","Malware Extension (mallorybowes)"
"jgbkgjepkeklblmlhnpjmnbinmifjenc","Malware Extension (mallorybowes)"
"jlbebokeclkofhchdepbojfhmocdlhfl","Malware Extension (mallorybowes)"
"jlbhkoohfmnikpalgglhpadlbeiobkaa","Malware Extension (mallorybowes)"
"jmlbnlcodmikhdpbjjdemgaebjgmpooa","Malware Extension (mallorybowes)"
"jnmckphflgdpioinbjaeckdajkbgcfgg","Malware Extension (mallorybowes)"
"kcjahchbheejjpdpohgfkaoknhcdjjnh","Malware Extension (mallorybowes)"
"kdihodbgfndblemlklkllhfjhiidbgih","Malware Extension (mallorybowes)"
"kefmhdhaebhmdeaabcgoaegmgodncebc","Malware Extension (mallorybowes)"
"kicmnilchjfefpceoaiopdpbpkicgjjm","Malware Extension (mallorybowes)"
"kigiheamdfmilbhkfdploghfnndcgkko","Malware Extension (mallorybowes)"
"kjgceeikbnmddoaggelkkpljdabhghkc","Malware Extension (mallorybowes)"
"kkeojhapoadcdlmkjlakdbhfkldbbmgi","Malware Extension (mallorybowes)"
"klblfmpeelmpnadjahhdakiomhaepogb","Malware Extension (mallorybowes)"
"kmfiklhdkhidbmofjbgmpeaogglkndpe","Malware Extension (mallorybowes)"
"knacgnmpceaffedmgegknkfcnejjhdpp","Malware Extension (mallorybowes)"
"kppjffaccdlhfeleafnohmfkgimdjmgg","Malware Extension (mallorybowes)"
"lbbegfjhlhpikmhbdcfcoadegdldmaen","Malware Extension (mallorybowes)"
"lbjgbekokephmmfllmpglefmoaihklpn","Malware Extension (mallorybowes)"
"lblnngjkgcpplmddebmefokmccpflhip","Malware Extension (mallorybowes)"
"lcdabcbanafchdlcbdjgngcplnkijala","Malware Extension (mallorybowes)"
"lcgjhoonomcmjpbnijfohbdhhjmhjlal","Malware Extension (mallorybowes)"
"ldkienofjncecbbnmhpngiiidekfcdoe","Malware Extension (mallorybowes)"
"lemhpidjofhodofghkakoglahdafpcbe","Malware Extension (mallorybowes)"
"lgekbdjboenacbkiabfkkcpjgacmjcdg","Malware Extension (mallorybowes)"
"lggmpibegkcnfogpophgnchognofcdgo","Malware Extension (mallorybowes)"
"ljppknljdefmnkckkdjaokhlncbiehgo","Malware Extension (mallorybowes)"
"lkdahidfbdadmblpkopllegopldfbhge","Malware Extension (mallorybowes)"
"llngndcpphncgeledehpklbeheadnoan","Malware Extension (mallorybowes)"
"lmmdoemglmnjenhfcjkhgpkgiedcejmn","Malware Extension (mallorybowes)"
"lniooknjghghdjoehegcoinmbhdbhcck","Malware Extension (mallorybowes)"
"makliapgjjpdkkaikobcmdhkfbfcoafk","Malware Extension (mallorybowes)"
"maohnjppabopdhfkholcdkpehdojnpoc","Malware Extension (mallorybowes)"
"mcadalidfbmnponoamfdjlahdeheommb","Malware Extension (mallorybowes)"
"mcafdholbcjhepgnpfdogaiagjmlfcon","Malware Extension (mallorybowes)"
"meioomnaphfjchjidcfnbadkbaaoanok","Malware Extension (mallorybowes)"
"mjbmelinkhpkmbjnocdklkjpiilpikba","Malware Extension (mallorybowes)"
"mkghdamdheccacmkmnchkaoljoflpoek","Malware Extension (mallorybowes)"
"mkjcnnfcmmniieaidfadidepdgfppfdj","Malware Extension (mallorybowes)"
"mmhaojkmpbmgbkojlagnhmjlfmnaglla","Malware Extension (mallorybowes)"
"mmlhchoolkdnmnddgmoohigffekjnofo","Malware Extension (mallorybowes)"
"mmmapklofkmbcahafjmiogdbmpagimlp","Malware Extension (mallorybowes)"
"mngcfgonjbdbdbifcbhmdiddloganbcc","Malware Extension (mallorybowes)"
"mnnpffgmgkbdllleeihdgfgleomdhacm","Malware Extension (mallorybowes)"
"moalaminambcgbljenplldelnhnaikke","Malware Extension (mallorybowes)"
"moljhdcbomchgdffhddpicbokacnbjoj","Malware Extension (mallorybowes)"
"mpdpjfobafahmgicjmpnfklbphhlacel","Malware Extension (mallorybowes)"
"mpfleoaldoclbjhfkgbmnelkkbolbegl","Malware Extension (mallorybowes)"
"nafbodmhgaabbfchodpkmpnibgjmeeei","Malware Extension (mallorybowes)"
"naofchadlleomaipaienfedidkiodamo","Malware Extension (mallorybowes)"
"nbbeiofjfjmnicfhkfbjdggbclmbaioc","Malware Extension (mallorybowes)"
"nbblafbmmogmlhejjondcclcgbkdmjln","Malware Extension (mallorybowes)"
"nbekcbebginchflfegofcjjmojpppnad","Malware Extension (mallorybowes)"
"nbhjdcacphemibgeamjkmeknfeffgngk","Malware Extension (mallorybowes)"
"nchffcpkbehklpbdodlakgdbnkdcnpbi","Malware Extension (mallorybowes)"
"nckldhnoondmiheikhblobkgcfchcbld","Malware Extension (mallorybowes)"
"ncnonnloajjbpdpgnelmlbflmbhlilid","Malware Extension (mallorybowes)"
"ncpjlhellnlcjnjmablbaingipdemidh","Malware Extension (mallorybowes)"
"ndchgkeilnpiefnoagcbnlellpcfmjic","Malware Extension (mallorybowes)"
"ndeejbgcbhehjpjmngniokeleedmjmap","Malware Extension (mallorybowes)"
"ndihciopmidkbamcfgpdmojcpalolfgo","Malware Extension (mallorybowes)"
"neafafemicnbclhpojeoiemihogeejhl","Malware Extension (mallorybowes)"
"nekimocmhfdimckbgchifahcgafhnagb","Malware Extension (mallorybowes)"
"nenaiblmmandfgaiifppcegejpinkebl","Malware Extension (mallorybowes)"
"neplbnhjlkmpekfcjibdidioejnhejfl","Malware Extension (mallorybowes)"
"nepnhilmahdmejhghfbjhhabaioioeel","Malware Extension (mallorybowes)"
"nfanjklinojeimbhmfliomdihldjhfpm","Malware Extension (mallorybowes)"
"nfebelgoldoapjgfkekcmbddpljakakp","Malware Extension (mallorybowes)"
"nfhbpopnbgigkljgmelpfncnghjpdopf","Malware Extension (mallorybowes)"
"nfpnclghflfcgkgdjcbpoljlafndbomk","Malware Extension (mallorybowes)"
"ngaccohdjpkgnghichikgcpfagnoeeim","Malware Extension (mallorybowes)"
"ngajighkghnbfnleddljedblnjaggebo","Malware Extension (mallorybowes)"
"ngchnhjdpgpkapghgpncmommhelegfbh","Malware Extension (mallorybowes)"
"ngeofnobniohmdmdkliflkeppfgbjpgn","Malware Extension (mallorybowes)"
"nglggaejaflihehbajhppedepephbfae","Malware Extension (mallorybowes)"
"nhnemamgicdjigoedllaicngcfihkmhf","Malware Extension (mallorybowes)"
"nhneoegahiihkkgdindfdnobhhhlpfnm","Malware Extension (mallorybowes)"
"njablodeioakdgahodegclphmnbaphin","Malware Extension (mallorybowes)"
"njdegihoinoiplfpbcckmjahlnpeipii","Malware Extension (mallorybowes)"
"njliieipbkencklladfemkkipmfcjiom","Malware Extension (mallorybowes)"
"nklckhbegicdajpehmmpbnpelkdjmdoc","Malware Extension (mallorybowes)"
"nkopnpaipcceikcmfcjlacgkjoglodag","Malware Extension (mallorybowes)"
"nldffbaphciaaophmdnikgkengbmigli","Malware Extension (mallorybowes)"
"nmkfcjaghjoedelgkomoifnpdejjpcbj","Malware Extension (mallorybowes)"
"nmlmdkblidkckbhidgfgghajlkgjijkp","Malware Extension (mallorybowes)"
"nnceiipjfkdobpenbmnajbkdfiklajgl","Malware Extension (mallorybowes)"
"noiinnecebffnjggilfhailhhgdilbld","Malware Extension (mallorybowes)"
"nojmjafalbmmoohpmjphalepmfnmhfao","Malware Extension (mallorybowes)"
"npcndkopgafkjggoledlgfblodppnckj","Malware Extension (mallorybowes)"
"nphiadicgehlpbniemnkhinphngoeaeg","Malware Extension (mallorybowes)"
"oaihijkoodmmaibfhojdinffpinmhdji","Malware Extension (mallorybowes)"
"oanlnaeipdakcmafockfiekhdklfidjb","Malware Extension (mallorybowes)"
"oanplobhgngkpkpeihcdojkongpiheci","Malware Extension (mallorybowes)"
"obahibdkmhmnenkcdpakilchcppihopl","Malware Extension (mallorybowes)"
"obgdpcjbebcaphmigjhogcikejnlbjgl","Malware Extension (mallorybowes)"
"ocfpmgbbkjeblbhdehminjdjffhcidbi","Malware Extension (mallorybowes)"
"ocgfhclcahimdhfjgmakmfdnhomofljo","Malware Extension (mallorybowes)"
"ocponkhpfikgnggeflddgkfcmhjejedo","Malware Extension (mallorybowes)"
"odoenahafpbigcelejhbkkhnjfleanok","Malware Extension (mallorybowes)"
"oehamnhnpejphgpkgnenefolepinadjj","Malware Extension (mallorybowes)"
"oejbnchocabaoicconfnbjghebmbfemc","Malware Extension (mallorybowes)"
"oejmcobpfiiladgbfpknibppfnekbolo","Malware Extension (mallorybowes)"
"oemkcngaaomgokaclafmkcgcpbfelmnb","Malware Extension (mallorybowes)"
"ofbfieekadnmifbaoigkcffobkkjblep","Malware Extension (mallorybowes)"
"ofgihclaiecmjbfjnajjimdbjnbiimkk","Malware Extension (mallorybowes)"
"ofkjndegefemablfmefngnpchlhapdmi","Malware Extension (mallorybowes)"
"ofockibbbgfclddbpbhhohdldgkomhgm","Malware Extension (mallorybowes)"
"ogegpnamjdpcadpldhijjlhkicgbnkjj","Malware Extension (mallorybowes)"
"ogiaghccmoklogdlbchapejmjnnlichn","Malware Extension (mallorybowes)"
"ohjoklkmollkbcibgddolpmpgaoophfl","Malware Extension (mallorybowes)"
"ohobkendnpiijpeiaimjbannfcmhaogi","Malware Extension (mallorybowes)"
"ohoingjkmkkoffkdmbpipdncbkhaaefd","Malware Extension (mallorybowes)"
"oihecidjnjpjfeefkambkjgebbmpahgn","Malware Extension (mallorybowes)"
"oilikkahlcnchaipbojfgejapechblbl","Malware Extension (mallorybowes)"
"ojfjgkolegfhneacbgcjaoajfgcfoapf","Malware Extension (mallorybowes)"
"ojhlagjgjbjfgllocdhlpnkbdlcipnmo","Malware Extension (mallorybowes)"
"ojmpgbcmiimbkmjfgmcneplkneleehcc","Malware Extension (mallorybowes)"
"ojnlggfhmoioajgmnelfdpjojaeknjog","Malware Extension (mallorybowes)"
"okgnpdnekilbcgcfeheanbpbhnhmopfc","Malware Extension (mallorybowes)"
"okjdiicjoeloipmgdopdmhpebnnfadih","Malware Extension (mallorybowes)"
"okphhehkikoonipdjmhglcmlgccjcblp","Malware Extension (mallorybowes)"
"olochidfgadpdbdmdfbhgimiffnllaij","Malware Extension (mallorybowes)"
"ombenndgcnmcnfohnbbjcmbmfmpefojc","Malware Extension (mallorybowes)"
"omclahaofiigfggelbcleagcphjhabmp","Malware Extension (mallorybowes)"
"onjjlcdmafgcjdbhmlnpmheobbfeilah","Malware Extension (mallorybowes)"
"onnmfhejbikffoenamcfglpjnmmbkdeg","Malware Extension (mallorybowes)"
"oonheecobachpkogdjjnemiipogpgnmg","Malware Extension (mallorybowes)"
"opbobdfddmiemhekjiglckcenhpfdbjm","Malware Extension (mallorybowes)"
"opjpfngjbdmgkilopbnapbkbngedcpmj","Malware Extension (mallorybowes)"
"oplhjpchbbngmpgcpjcbijhfehbhodgi","Malware Extension (mallorybowes)"
"oppbpkjmehgijcpeddkpbadoidfpcblg","Malware Extension (mallorybowes)"
"paddichbcfehpelokpidnagccddbpkin","Malware Extension (mallorybowes)"
"pajbempmgmalnfpbnpclkelnhfccikal","Malware Extension (mallorybowes)"
"pboddlnfegdnifbhepjegnokocjpadpd","Malware Extension (mallorybowes)"
"pcbpmbmpjjibcmodpaomahiokikjomgc","Malware Extension (mallorybowes)"
"pcembleiffdccjkcebaodmhgkopipdan","Malware Extension (mallorybowes)"
"pcgcmplcfdfkkkmaggghdghnlddkpbbo","Malware Extension (mallorybowes)"
"pdhibfagbndnidgfjkhdhlfibdoofbji","Malware Extension (mallorybowes)"
"pdloaiifhmlbhhppajjmfpijopfeenoo","Malware Extension (mallorybowes)"
"pehnljkefahmlhifockljagcfcpljclc","Malware Extension (mallorybowes)"
"pelnnoacfeaanpmnmacjjnnpgfggekig","Malware Extension (mallorybowes)"
"pfekelemlpmelhipncgddloaflehglmb","Malware Extension (mallorybowes)"
"pfepcffcdodcancalckiencamnonoebl","Malware Extension (mallorybowes)"
"pfpgpbfndacjjjdlgefggndhionakfmb","Malware Extension (mallorybowes)"
"pghkmhmjldklacabcgkaaboikfaaogmi","Malware Extension (mallorybowes)"
"pgilbgknfcnjjblfnjojmcpkggipblci","Malware Extension (mallorybowes)"
"pgleokbigapafgjodffamlhdkhiagdgb","Malware Extension (mallorybowes)"
"phkafpikdokjpogdhjpkcgfjpfgnlgeo","Malware Extension (mallorybowes)"
"phmogllmicehmpglfobbihoelfidjnpd","Malware Extension (mallorybowes)"
"pihogmfmhefemijkgmbimkngninbkkce","Malware Extension (mallorybowes)"
"pilmbpeapchjcnldfomimmcfoigoenoc","Malware Extension (mallorybowes)"
"pinfndnjmdocmimbeonilpahdaldopjc","Malware Extension (mallorybowes)"
"pinkcaefpkjpljfflabpkcgbkpbomdfk","Malware Extension (mallorybowes)"
"pjabdohmcokffcednbgpeoifpdbfgfbj","Malware Extension (mallorybowes)"
"pjjmcpmjocebmjmhdclbiheoideefiad","Malware Extension (mallorybowes)"
"plcdglhlbmlnfoghfhmbhehapfadedod","Malware Extension (mallorybowes)"
"pmdakkjbaeioodmomlmnklahihodjcjk","Malware Extension (mallorybowes)"
"pmnpldnflfopbhndkjndecojdpgecckf","Malware Extension (mallorybowes)"
"pnamonkagicmlnalnlcdaoeenhlgdklf","Malware Extension (mallorybowes)"
"poeokidblnamjkagggonidcigafaobki","Malware Extension (mallorybowes)"
"pofffhlknjbjolmfoeagdmbbdbjjmeki","Malware Extension (mallorybowes)"
"polgnkadhhhmlahkhhbicledbpklnake","Malware Extension (mallorybowes)"
"ppicajcmopaimnnikbafgknffbdmomfk","Malware Extension (mallorybowes)"
"ppmbiomgjfenipmnjiiaemcaboaeljil","Malware Extension (mallorybowes)"
"bmngkajcejghcgafbobemkpjboikmgfi","Malware Extension (mallorybowes)"
"deciloopcooglpjhomblbbjeeenohbpg","Malware Extension (mallorybowes)"
"gabbbocakeomblphkmmnoamkioajlkfo","Malware Extension (mallorybowes)"
"ggolfgbegefeeoocgjbmkembbncoadlb","Malware Extension (mallorybowes)"
"mdpgppkombninhkfhaggckdmencplhmg","Malware Extension (mallorybowes)"
"fgaapohcdolaiaijobecfleiohcfhdfb","Malware Extension (mallorybowes)"
"iibnodnghffmdcebaglfgnfkgemcbchf","Malware Extension (mallorybowes)"
"olkpikmlhoaojbbmmpejnimiglejmboe","Malware Extension (mallorybowes)"
"bhfoemlllidnfefgkeaeocnageepbael","Malware Extension (mallorybowes)"
"nilbfjdbacfdodpbdondbbkmoigehodg","Malware Extension (mallorybowes)"
"eikbfklcjampfnmclhjeifbmfkpkfpbn","Malware Extension (mallorybowes)"
"pfnmibjifkhhblmdmaocfohebdpfppkf","Malware Extension (mallorybowes)"
"cgpbghdbejagejmciefmekcklikpoeel","Malware Extension (mallorybowes)"
"klejifgmmnkgejbhgmpgajemhlnijlib","Malware Extension (mallorybowes)"
"ceoldlgkhdbnnmojajjgfapagjccblib","Malware Extension (mallorybowes)"
"mnafnfdagggclnaggnjajohakfbppaih","Malware Extension (mallorybowes)"
"oknpgmaeedlbdichgaghebhiknmghffa","Malware Extension (mallorybowes)"
"pcaaejaejpolbbchlmbdjfiggojefllp","Malware Extension (mallorybowes)"
"lmcajpniijhhhpcnhleibgiehhicjlnk","Malware Extension (mallorybowes)"
"lnocaphbapmclliacmbbggnfnjojbjgf","Malware Extension (mallorybowes)"
"bhcpgfhiobcpokfpdahijhnipenkplji","Malware Extension (mallorybowes)"
"dambkkeeabmnhelekdekfmabnckghdih","Malware Extension (mallorybowes)"
"dgjmdlifhbljhmgkjbojeejmeeplapej","Malware Extension (mallorybowes)"
"emechknidkghbpiodihlodkhnljplpjm","Malware Extension (mallorybowes)"
"hajlccgbgjdcjaommiffaphjdndpjcio","Malware Extension (mallorybowes)"
"dljdbmkffjijepjnkonndbdiakjfdcic","Malware Extension (mallorybowes)"
"cjmpdadldchjmljhkigoeejegmghaabp","Malware Extension (mallorybowes)"
"jlkfgpiicpnlbmmmpkpdjkkdolgomhmb","Malware Extension (mallorybowes)"
"njdkgjbjmdceaibhngelkkloceihelle","Malware Extension (mallorybowes)"
"phoehhafolaebdpimmbmlofmeibdkckp","Malware Extension (mallorybowes)"
"pccfaccnfkjmdlkollpiaialndbieibj","Malware Extension (mallorybowes)"
"fbhbpnjkpcdmcgcpfilooccjgemlkinn","Malware Extension (mallorybowes)"
"dppilebghcniomddkpphiminideiajff","Malware Extension (mallorybowes)"
"ojmbbkdflpfjdceflikpkbbmmbfagglg","Malware Extension (mallorybowes)"
"chmaijbnjdnkjknoigffoohjhpejjppd","Malware Extension (mallorybowes)"
"jhcfnojahmdghhebdaoijngclknfkbjn","Malware Extension (mallorybowes)"
"akdbogfpgohikflhccclloneidjkogog","Malware Extension (mallorybowes)"
"lgjogljbnbfjcaigalbhiagkboajmkkj","Malware Extension (mallorybowes)"
"aemaecahdckfllfldhgimjhdgiaahean","Malware Extension (mallorybowes)"
"klbibkeccnjlkjkiokjodocebajanakg","Malware Extension (mallorybowes)"
"fmfjhicbjecfchfmpelfnifijeigelme","Malware Extension (mallorybowes)"
"acdfdofofabmipgcolilkfhnpoclgpdd","Malware Extension (mallorybowes)"
"oobppndjaabcidladjeehddkgkccfcpn","Malware Extension (mallorybowes)"
"aonedlchkbicmhepimiahfalheedjgbh","Malware Extension (mallorybowes)"
"aoeacblfmdamdejeiaepojbhohhkmkjh","Malware Extension (mallorybowes)"
"eoeoincjhpflnpdaiemgbboknhkblome","Malware Extension (mallorybowes)"
"onbkopaoemachfglhlpomhbpofepfpom","Malware Extension (mallorybowes)"
"inlgdellfblpplcogjfedlhjnpgafnia","Malware Extension (mallorybowes)"
"ejfajpmpabphhkcacijnhggimhelopfg","Malware Extension (mallorybowes)"
"pgjndpcilbcanlnhhjmhjalilcmoicjc","Malware Extension (mallorybowes)"
"napifgkjbjeodgmfjmgncljmnmdefpbf","Malware Extension (mallorybowes)"
"glgemekgfjppocilabhlcbngobillcgf","Malware Extension (mallorybowes)"
"klmjcelobglnhnbfpmlbgnoeippfhhil","Malware Extension (mallorybowes)"
"ldbfffpdfgghehkkckifnjhoncdgjkib","Malware Extension (mallorybowes)"
"mbacbcfdfaapbcnlnbmciiaakomhkbkb","Malware Extension (mallorybowes)"
"mdnmhbnbebabimcjggckeoibchhckemm","Malware Extension (mallorybowes)"
"lfedlgnabjompjngkpddclhgcmeklana","Malware Extension (mallorybowes)"
"mdpljndcmbeikfnlflcggaipgnhiedbl","Malware Extension (mallorybowes)"
"npdpplbicnmpoigidfdjadamgfkilaak","Malware Extension (mallorybowes)"
"ibehiiilehaakkhkigckfjfknboalpbe","Malware Extension (mallorybowes)"
"lalpacfpfnobgdkbbpggecolckiffhoi","Malware Extension (mallorybowes)"
"hdbipekpdpggjaipompnomhccfemaljm","Malware Extension (mallorybowes)"
"gfjocjagfinihkkaahliainflifnlnfc","Malware Extension (mallorybowes)"
"ickfamnaffmfjgecbbnhecdnmjknblic","Malware Extension (mallorybowes)"
"bmcnncbmipphlkdmgfbipbanmmfdamkd","Malware Extension (mallorybowes)"
"miejmllodobdobgjbeonandkjhnhpjbn","Malware Extension (mallorybowes)"
"mabdjppmcjpjploliggpbonahnjjlgkf","Malware Extension (mallorybowes)"
"lgjdgmdbfhobkdbcjnpnlmhnplnidkkp","Malware Extension (palant)"
"chmfnmjfghjpdamlofhlonnnnokkpbao","Malware Extension (palant)"
"lklmhefoneonjalpjcnhaidnodopinib","Malware Extension (palant)"
"ciifcakemmcbbdpmljdohdmbodagmela","Malware Extension (palant)"
"meljmedplehjlnnaempfdoecookjenph","Malware Extension (palant)"
"lipmdblppejomolopniipdjlpfjcojob","Malware Extension (palant)"
"lmcboojgmmaafdmgacncdpjnpnnhpmei","Malware Extension (palant)"
"icnekagcncdgpdnpoecofjinkplbnocm","Malware Extension (palant)"
"bahogceckgcanpcoabcdgmoidngedmfo","Malware Extension (palant)"
"bkpdalonclochcahhipekbnedhklcdnp","Malware Extension (palant)"
"magnkhldhhgdlhikeighmhlhonpmlolk","Malware Extension (palant)"
"edadmcnnkkkgmofibeehgaffppadbnbi","Malware Extension (palant)"
"ajneghihjbebmnljfhlpdmjjpifeaokc","Malware Extension (palant)"
"nadenkhojomjfdcppbhhncbfakfjiabp","Malware Extension (palant)"
"pbdpfhmbdldfoioggnphkiocpidecmbp","Malware Extension (palant)"
"hdgdghnfcappcodemanhafioghjhlbpb","Malware Extension (palant)"
"fbjfihoienmhbjflbobnmimfijpngkpa","Malware Extension (palant)"
"kjeffohcijbnlkgoaibmdcfconakaajm","Malware Extension (palant)"
"djmpbcihmblfdlkcfncodakgopmpgpgh","Malware Extension (palant)"
"obeokabcpoilgegepbhlcleanmpgkhcp","Malware Extension (palant)"
"mcmdolplhpeopapnlpbjceoofpgmkahc","Malware Extension (palant)"
"dppnhoaonckcimpejpjodcdoenfjleme","Malware Extension (palant)"
"idgncaddojiejegdmkofblgplkgmeipk","Malware Extension (palant)"
"deebfeldnfhemlnidojiiidadkgnglpi","Malware Extension (palant)"
"gfbgiekofllpkpaoadjhbbfnljbcimoh","Malware Extension (palant)"
"pbebadpeajadcmaoofljnnfgofehnpeo","Malware Extension (palant)"
"flmihfcdcgigpfcfjpdcniidbfnffdcf","Malware Extension (palant)"
"pinnfpbpjancnbidnnhpemakncopaega","Malware Extension (palant)"
"iicpikopjmmincpjkckdngpkmlcchold","Malware Extension (palant)"
"bjlcpoknpgaoaollojjdnbdojdclidkh","Malware Extension (palant)"
"okclicinnbnfkgchommiamjnkjcibfid","Malware Extension (palant)"
"pcjmcnhpobkjnhajhhleejfmpeoahclc","Malware Extension (palant)"
"hinhmojdkodmficpockledafoeodokmc","Malware Extension (palant)"
"gcnceeflimggoamelclcbhcdggcmnglm","Malware Extension (palant)"
"kacljcbejojnapnmiifgckbafkojcncf","Malware Extension (palant)"
"jhkhlgaomejplkanglolfpcmfknnomle","Malware Extension (palant)"
"nkmooloiipfcknccapehflmampkaniji","Malware Extension (palant)"
"kgddnoifhgfdhcpbkkjdgokfnkkmdcen","Malware Extension (palant)"
"gbdjcgalliefpinpmggefbloehmmknca","Malware Extension (palant)"
"eggeoellnjnnglaibpcmggjnjifeebpi","Malware Extension (palant)"
"ionpbgeeliajehajombdeflogfpgmmel","Malware Extension (palant)"
"jaekigmcljkkalnicnjoafgfjoefkpeg","Malware Extension (palant)"
"aeilijiaejfdnbagnpannhdoaljpkbhe","Malware Extension (palant)"
"afdfpkhbdpioonfeknablodaejkklbdn","Malware Extension (palant)"
"anflghppebdhjipndogapfagemgnlblh","Malware Extension (palant)"
"anmbbeeiaollmpadookgoakpfjkbidaf","Malware Extension (palant)"
"bebmphofpgkhclocdbgomhnjcpelbenh","Malware Extension (palant)"
"bmkgbgkneealfabgnjfeljaiegpginpl","Malware Extension (palant)"
"ccjlpblmgkncnnimcmbanbnhbggdpkie","Malware Extension (palant)"
"cclhgechkjghfaoebihpklmllnnlnbdb","Malware Extension (palant)"
"cfegchignldpfnjpodhcklmgleaoanhi","Malware Extension (palant)"
"cfllfglbkmnbkcibbjoghimalbileaic","Malware Extension (palant)"
"cjljdgfhkjbdbkcdkfojleidpldagmao","Malware Extension (palant)"
"coabfkgengacobjpmdlmmihhhfnhbjdm","Malware Extension (palant)"
"dcaffjpclkkjfacgfofgpjbmgjnjlpmh","Malware Extension (palant)"
"djekgpcemgcnfkjldcclcpcjhemofcib","Malware Extension (palant)"
"dkbccihpiccbcheieabdbjikohfdfaje","Malware Extension (palant)"
"dlpimjmonhbmamocpboifndnnakgknbf","Malware Extension (palant)"
"dmbjkidogjmmlejdmnecpmfapdmidfjg","Malware Extension (palant)"
"dneifdhdmnmmlobjbimlkcnhkbidmlek","Malware Extension (palant)"
"doiiaejbgndnnnomcdhefcbfnbbjfbib","Malware Extension (palant)"
"dpfofggmkhdbfcciajfdphofclabnogo","Malware Extension (palant)"
"eabhkjojehdleajkbigffmpnaelncapp","Malware Extension (palant)"
"ealojglnbikknifbgleaceopepceakfn","Malware Extension (palant)"
"ebdbcfomjliacpblnioignhfhjeajpch","Malware Extension (palant)"
"edlifbnjlicfpckhgjhflgkeeibhhcii","Malware Extension (palant)"
"ehmneimbopigfgchjglgngamiccjkijh","Malware Extension (palant)"
"ehpgcagmhpndkmglombjndkdmggkgnge","Malware Extension (palant)"
"ejllkedmklophclpgonojjkaliafeilj","Malware Extension (palant)"
"ekjogkoigkhbgdgpolejnjfmhdcgaoof","Malware Extension (palant)"
"elpdbicokgbedckgblmbhoamophfbchi","Malware Extension (palant)"
"emeokgokialpjadjaoeiplmnkjoaegng","Malware Extension (palant)"
"eokjikchkppnkdipbiggnmlkahcdkikp","Malware Extension (palant)"
"epeigjgefhajkiiallmfblgglmdbhfab","Malware Extension (palant)"
"eplfglplnlljjpeiccbgnijecmkeimed","Malware Extension (palant)"
"fbbjijdngocdplimineplmdllhjkaece","Malware Extension (palant)"
"fbjhgeaafhlbjiejehpjdnghinlcceak","Malware Extension (palant)"
"fedchalbmgfhdobblebblldiblbmpgdj","Malware Extension (palant)"
"fobaamfiblkoobhjpiigemmdegbmpohd","Malware Extension (palant)"
"gaiceihehajjahakcglkhmdbbdclbnlf","Malware Extension (palant)"
"gceehiicnbpehbbdaloolaanlnddailm","Malware Extension (palant)"
"ggacghlcchiiejclfdajbpkbjfgjhfol","Malware Extension (palant)"
"gjjbmfigjpgnehjioicaalopaikcnheo","Malware Extension (palant)"
"gpdfpljioapjogbnlpmganakfjcemifk","Malware Extension (palant)"
"hjlekdknhjogancdagnndeenmobeofgm","Malware Extension (palant)"
"hlbdhflagoegglpdminhlpenkdgloabe","Malware Extension (palant)"
"hnfabcchmopgohnhkcojhocneefbnffg","Malware Extension (palant)"
"iabflonngmpkalkpbjonemaamlgdghea","Malware Extension (palant)"
"ibppednjgooiepmkgdcoppnmbhmieefh","Malware Extension (palant)"
"icchadngbpkcegnabnabhkjkfkfflmpj","Malware Extension (palant)"
"ielooaepfhfcnmihgnabkldnpddnnldl","Malware Extension (palant)"
"ifdepgnnjpnbkcgempionjablajancjc","Malware Extension (palant)"
"ijejnggjjphlenbhmjhhgcdpehhacaal","Malware Extension (palant)"
"iklgljbighkgbjoecoddejooldolenbj","Malware Extension (palant)"
"imopknpgdihifjkjpmjaagcagkefddnb","Malware Extension (palant)"
"jchmabokofdoabocpiicjljelmackhho","Malware Extension (palant)"
"jdlkkmamiaikhfampledjnhhkbeifokk","Malware Extension (palant)"
"jglemppahimembneahjbkhjknnefeeio","Malware Extension (palant)"
"jiaopkfkampgnnkckajcbdgannoipcne","Malware Extension (palant)"
"jjgnkfncaadmaobenjjpmngdpgalemho","Malware Extension (palant)"
"jlbpahgopcmomkgegpbmopfodolajhbl","Malware Extension (palant)"
"jpefmbpcbebpjpmelobfakahfdcgcmkl","Malware Extension (palant)"
"khdnaopfklkdcloiinccnaflffmfcioa","Malware Extension (palant)"
"kjgkmceledmpdnmgmppiekdbnamccdjp","Malware Extension (palant)"
"laameccjpleogmfhilmffpdbiibgbekf","Malware Extension (palant)"
"lagdcjmbchphhndlbpfajelapcodekll","Malware Extension (palant)"
"lbohagbplppjcpllnhdichjldhfgkicb","Malware Extension (palant)"
"ledkggjjapdgojgihnaploncccgiadhg","Malware Extension (palant)"
"lgecddhfcfhlmllljooldkbbijdcnlpe","Malware Extension (palant)"
"lkahpjghmdhpiojknppmlenngmpkkfma","Malware Extension (palant)"
"lkciiknpgglgbbcgcpbpobjabglmpkle","Malware Extension (palant)"
"lkhhagecaghfakddbncibijbjmgfhfdm","Malware Extension (palant)"
"lknpbgnookklokdjomiildnlalffjmma","Malware Extension (palant)"
"lojpdfjjionbhgplcangflkalmiadhfi","Malware Extension (palant)"
"mdkiofbiinbmlblcfhfjgmclhdfikkpm","Malware Extension (palant)"
"meffljleomgifbbcffejnmhjagncfpbd","Malware Extension (palant)"
"mejjgaogggabifjfjdbnobinfibaamla","Malware Extension (palant)"
"mhpcabliilgadobjpkameggapnpeppdg","Malware Extension (palant)"
"mkjjckchdfhjbpckippbnipkdnlidbeb","Malware Extension (palant)"
"mldaiedoebimcgkokmknonjefkionldi","Malware Extension (palant)"
"mlkjjjmhjijlmafgjlpkiobpdocdbncj","Malware Extension (palant)"
"mndiaaeaiclnmjcnacogaacoejchdclp","Malware Extension (palant)"
"mnlohknjofogcljbcknkakphddjpijak","Malware Extension (palant)"
"nhnfcgpcbfclhfafjlooihdfghaeinfc","Malware Extension (palant)"
"ninecedhhpccjifamhafbdelibdjibgd","Malware Extension (palant)"
"nmigaijibiabddkkmjhlehchpmgbokfj","Malware Extension (palant)"
"npdkkcjlmhcnnaoobfdjndibfkkhhdfn","Malware Extension (palant)"
"npmjjkphdlmbeidbdbfefgedondknlaf","Malware Extension (palant)"
"oakbcaafbicdddpdlhbchhpblmhefngh","Malware Extension (palant)"
"obdhcplpbliifflekgclobogbdliddjd","Malware Extension (palant)"
"ocginjipilabheemhfbedijlhajbcabh","Malware Extension (palant)"
"oepjogknopbbibcjcojmedaepolkghpb","Malware Extension (palant)"
"ofpnikijgfhlmmjlpkfaifhhdonchhoi","Malware Extension (palant)"
"ogadflejmplcdhcldlloonbiekhnlopp","Malware Extension (palant)"
"ogfjgagnmkiigilnoiabkbbajinanlbn","Malware Extension (palant)"
"okkffdhbfplmbjblhgapnchjinanmnij","Malware Extension (palant)"
"oodkhhminilgphkdofffddlgopkgbgpm","Malware Extension (palant)"
"pegfdldddiilihjahcpdehhhfcbibipg","Malware Extension (palant)"
"phfkifnjcmdcmljnnablahicoabkokbg","Malware Extension (palant)"
"phjbepamfhjgjdgmbhmfflhnlohldchb","Malware Extension (palant)"
"pjbgfifennfhnbkhoidkdchbflppjncb","Malware Extension (palant)"
"plmlopfeeobajiecodiggabcihohcnge","Malware Extension (palant)"
"pmilcmjbofinpnbnpanpdadijibcgifc","Malware Extension (palant)"
"pmnphobdokkajkpbkajlaiooipfcpgio","Malware Extension (palant)"
"pnanegnllonoiklmmlegcaajoicfifcm","Malware Extension (palant)"
"pnlphjjfielecalmmjjdhjjninkbjdod","Malware Extension (palant)"
"pooaemmkohlphkekccfajnbcokjlbehk","Malware Extension (palant)"
"fmlpbbognkocpajihchioognkmdeeldo","Malware Extension (palant)"
"goaebigflkhjjblmofhoggdhebgnielo","Malware Extension (palant)"
"igkkmokkmlbkkgdnkkancbonkbbmkioc","Malware Extension (palant)"
"lopnbnfpjmgpbppclhclehhgafnifija","Malware Extension (palant)"
"kgfeiebnfmmfpomhochmlfmdmjmfedfj","Malware Extension (palant)"
"pmlcjncilaaaemknfefmegedhcgelmee","Malware Extension (palant)"
"ohdgnoepeabcfdkboidmaedenahioohf","Malware Extension (palant)"
"dnbipceilikdgjmeiagblfckeialaela","Malware Extension (palant)"
"aciipkgmbljbcokcnhjbjdhilpngemnj","Malware Extension (palant)"
"nlmjpeojbncdmlfkpppngdnolhfgiehn","Malware Extension (palant)"
"phjhbkdgnjaokligmkimgnlagccanodn","Malware Extension (palant)"
"fkhpfgpmejefmjaeelgoopkcglgafedm","Malware Extension (palant)"
"kekdpkbijjffmohdaonbpeeaiknhbkhj","Malware Extension (palant)"
"mcmmiinopedfbaoongoclagidncaacbd","Malware Extension (palant)"
"ndcokkmfmiaecmndbpohaogmpmchfpkk","Malware Extension (palant)"
"cpmpjapeeidaikiiemnddfgfdfjjhgif","Malware Extension (palant)"
"ajefbooiifdkmgkpjkanmgbjbndfbfhg","Malware Extension (palant)"
'@
} elseif ($ExtensionIdBlock -match ".csv") {
    $BlockList = Import-Csv "$ExtensionIdBlock"
} else {
    $hash = @{
        ID  = "$ExtensionIdBlock"
        Name = ""
    }
    $BlockList = [pscustomobject]$hash
}


# Get current list of Chrome force-installed extensions
$RegKeyForceInstallChrome = "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist"
$ForceListChrome = Get-ExtensionList -RegPath $RegKeyForceInstallChrome
if ($ForceListChrome) {
    Write-Output "`nChrome machine-wide force-installed extension list" | Tee-Object -FilePath $logFilePath -Append
    $ForceListChrome | Tee-Object -FilePath $logFilePath -Append
} else {
    Write-Output "`nNo entries in Chrome machine-wide force-installed extension list" | Tee-Object -FilePath $logFilePath -Append
}
if ($($ForceListChrome.name | Measure-Object).Count -eq 0) { [int]$ForceListChromeIndex = 1 } else { $ForceListChrome = $ForceListChrome | Sort-Object @{e={$_.Name -as [int]}} ; [int]$ForceListChromeIndex = [int]$ForceListChrome[-1].name + 1 }

# Get current list of Chrome allowed extensions
$RegKeyAllowedInstallChrome = "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallAllowlist"
$AllowListChrome = Get-ExtensionList -RegPath $RegKeyAllowedInstallChrome
if ($AllowListChrome) {
    Write-Output "`nChrome machine-wide allowed extension list" | Tee-Object -FilePath $logFilePath -Append
    $AllowListChrome | Tee-Object -FilePath $logFilePath -Append
} else {
    Write-Output "`nNo entries in Chrome machine-wide allowed extension list" | Tee-Object -FilePath $logFilePath -Append
}
if ($($AllowListChrome.name | Measure-Object).Count -eq 0) { [int]$AllowListChromeIndex = 1 } else { $AllowListChrome = $AllowListChrome | Sort-Object @{e={$_.Name -as [int]}} ; [int]$AllowListChromeIndex = [int]$AllowListChrome[-1].name + 1 }

# Get current list of Chrome blocked extensions
$RegKeyBlockInstallChrome = "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist"
$BlockListChrome = Get-ExtensionList -RegPath $RegKeyBlockInstallChrome
if ($BlockListChrome) {
    Write-Output "`nChrome machine-wide blocked extension list" | Tee-Object -FilePath $logFilePath -Append
    $BlockListChrome | Tee-Object -FilePath $logFilePath -Append
} else {
    Write-Output "`nNo entries in Chrome machine-wide blocked extension list" | Tee-Object -FilePath $logFilePath -Append
}
if ($($BlockListChrome.name | Measure-Object).Count -eq 0) { [int]$BlockListChromeIndex = 1 } else { $BlockListChrome = $BlockListChrome | Sort-Object @{e={$_.Name -as [int]}} ; [int]$BlockListChromeIndex = [int]$BlockListChrome[-1].name + 1 }

# Get current list of Edge force-installed extensions
$RegKeyForceInstallEdge = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist"
$ForceListEdge = Get-ExtensionList -RegPath $RegKeyForceInstallEdge
if ($ForceListEdge) {
    Write-Output "`nEdge machine-wide force-installed extension list" | Tee-Object -FilePath $logFilePath -Append
    $ForceListEdge | Tee-Object -FilePath $logFilePath -Append
} else {
    Write-Output "`nNo entries in Edge machine-wide force-installed extension list" | Tee-Object -FilePath $logFilePath -Append
}
if ($($ForceListEdge.name | Measure-Object).Count -eq 0) { [int]$ForceListEdgeIndex = 1 } else { $ForceListEdge = $ForceListEdge | Sort-Object @{e={$_.Name -as [int]}} ; [int]$ForceListEdgeIndex = [int]$ForceListEdge[-1].name + 1 }

# Get current list of Edge allowed extensions
$RegKeyAllowedInstallEdge = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallAllowlist"
$AllowListEdge = Get-ExtensionList -RegPath $RegKeyAllowedInstallEdge
if ($AllowListEdge) {
    Write-Output "`nEdge machine-wide allowed extension list" | Tee-Object -FilePath $logFilePath -Append
    $AllowListEdge | Tee-Object -FilePath $logFilePath -Append
} else {
    Write-Output "`nNo entries in Edge machine-wide allowed extension list" | Tee-Object -FilePath $logFilePath -Append
}
if ($($AllowListEdge.name | Measure-Object).Count -eq 0) { [int]$AllowListEdgeIndex = 1 } else { $AllowListEdge = $AllowListEdge | Sort-Object @{e={$_.Name -as [int]}} ; [int]$AllowListEdgeIndex = [int]$AllowListEdge[-1].name + 1 }

# Get current list of Edge blocked extensions
$RegKeyBlockInstallEdge = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist"
$BlockListEdge = Get-ExtensionList -RegPath $RegKeyBlockInstallEdge
if ($BlockListEdge) {
    Write-Output "`nEdge machine-wide blocked extension list" | Tee-Object -FilePath $logFilePath -Append
    $BlockListEdge | Tee-Object -FilePath $logFilePath -Append
} else {
    Write-Output "`nNo entries in Edge machine-wide blocked extension list" | Tee-Object -FilePath $logFilePath -Append
}
if ($($BlockListEdge.name | Measure-Object).Count -eq 0) { [int]$BlockListEdgeIndex = 1 } else { $BlockListEdge = $BlockListEdge | Sort-Object @{e={$_.Name -as [int]}} ; [int]$BlockListEdgeIndex = [int]$BlockListEdge[-1].name + 1 }


# Force-install extensions
if ($($AddList.ID | Measure-Object).Count -eq 0) {
    Write-Output "`nNo extension ID(s) specified to be added to Chrome." | Tee-Object -FilePath $logFilePath -Append
} else {
    # Add extensions to Chrome
    foreach ($Extension in $AddList) {
        Write-Output "`nAdding $($Extension.Name) - $($Extension.ID)" | Tee-Object -FilePath $logFilePath -Append
        $ExtensionIdAdd = "$($Extension.ID);https://clients2.google.com/service/update2/crx"
        $extensionCheck = $ForceListChrome | Where-Object {$_.Value -eq $ExtensionIdAdd}
        if ($extensionCheck) {
            Write-Output "Extension already exists in Chrome force-install list" | Tee-Object -FilePath $logFilePath -Append
        } else {
            [int]$newExtensionId = [int]$ForceListChromeIndex
            New-ItemProperty $RegKeyForceInstallChrome -PropertyType String -Name $newExtensionId -Value $ExtensionIdAdd
            Write-Output "Extension added to Chrome force-install list" | Tee-Object -FilePath $logFilePath -Append
            [int]$ForceListChromeIndex = [int]$ForceListChromeIndex + 1
        }
    }
    # To add extensions to Edge the extension would need to be present in the Microsoft Store and the pattern would be:
    # "$($Extension.ID);https://edge.microsoft.com/extensionwebstorebase/v1/crx"
}


if ($($BlockList.ID | Measure-Object).Count -eq 0) {
    Write-Output "`nNo extension ID(s) specified to be blocked in Chrome/Edge." | Tee-Object -FilePath $logFilePath -Append
} else {
    foreach ($Extension in $BlockList) {
        Write-Output "`nBlocking $($Extension.Name) - $($Extension.ID)" | Tee-Object -FilePath $logFilePath -Append
        if (!(Test-Path $RegKeyBlockInstallChrome)) {
            New-Item $RegKeyBlockInstallChrome -Force
            Write-Output "Created Reg Key $RegKeyBlockInstallChrome" | Tee-Object -FilePath $logFilePath -Append
        }
        # Block Extension from Chrome
        $extensionCheck = $BlockListChrome | Where-Object {$_.Value -eq $Extension.ID}
        if ($extensionCheck){
            Write-Output "Extension already blocked in Chrome." | Tee-Object -FilePath $logFilePath -Append
        } else {
            [int]$newExtensionId = [int]$BlockListChromeIndex
            New-ItemProperty $RegKeyBlockInstallChrome -PropertyType String -Name $newExtensionId -Value $Extension.ID
            Write-Output "Extension added to Chrome block list" | Tee-Object -FilePath $logFilePath -Append
            [int]$BlockListChromeIndex = [int]$BlockListChromeIndex + 1
        }
        # Remove From Force Install List
        $extensionCheck = $ForceListChrome | Where-Object {$_.Value -match $Extension.ID}
        if ($extensionCheck) {
            Write-Output "Extension found in Chrome force install list - Removing" | Tee-Object -FilePath $logFilePath -Append
            Remove-ItemProperty $RegKeyForceInstallChrome -Name $extensionCheck.name -Force
        }
        # Remove From Allowed Install List
        $extensionCheck = $AllowListChrome | Where-Object {$_.Value -eq $Extension.ID}
        if ($extensionCheck) {
            Write-Output "Extension found in Chrome allowed install list - Removing" | Tee-Object -FilePath $logFilePath -Append
            Remove-ItemProperty $RegKeyAllowedInstallChrome -Name $extensionCheck.name -Force
        }
        if (!(Test-Path $RegKeyBlockInstallEdge)) {
            New-Item $RegKeyBlockInstallEdge -Force
            Write-Output "Created Reg Key $RegKeyBlockInstallEdge" | Tee-Object -FilePath $logFilePath -Append
        }
        # Block Extension from Edge
        $extensionCheck = $BlockListEdge | Where-Object {$_.Value -eq $Extension.ID}
        if ($extensionCheck){
            Write-Output "Extension already blocked in Edge." | Tee-Object -FilePath $logFilePath -Append
        } else {
            [int]$newExtensionId = [int]$BlockListEdgeIndex
            New-ItemProperty $RegKeyBlockInstallEdge -PropertyType String -Name $newExtensionId -Value $Extension.ID
            Write-Output "Extension added to Edge block list" | Tee-Object -FilePath $logFilePath -Append
            [int]$BlockListEdgeIndex = [int]$BlockListEdgeIndex + 1
        }
        # Remove From Force Install List
        $extensionCheck = $ForceListEdge | Where-Object {$_.Value -match $Extension.ID}
        if ($extensionCheck) {
            Write-Output "Extension found in Edge force install list - Removing" | Tee-Object -FilePath $logFilePath -Append
            Remove-ItemProperty $RegKeyForceInstallEdge -Name $extensionCheck.name -Force
        }
        # Remove From Allowed Install List
        $extensionCheck = $AllowListChrome | Where-Object {$_.Value -eq $Extension.ID}
        if ($extensionCheck) {
            Write-Output "Extension found in Edge allowed install list - Removing" | Tee-Object -FilePath $logFilePath -Append
            Remove-ItemProperty $RegKeyAllowedInstallEdge -Name $extensionCheck.name -Force
        }
    }
}


if ($Report) {
    Write-Output "`nSaving report of all machine-wide extension lists in registry..." | Tee-Object -FilePath $logFilePath -Append
    $Output = "C:\temp\$($env:computername)-RegistryExtensionPolicyLists-$($(Get-Date).ToString('yyyyMMddhhmm')).txt"
    Write-Output "`nMachine-wide Chrome force-install extension list:" | Out-File -FilePath $Output -Append
    $ForceListChrome | Out-File -FilePath $Output -Append
    Write-Output "`nMachine-wide Chrome allowed extension list:" | Out-File -FilePath $Output -Append
    $AllowListChrome | Out-File -FilePath $Output -Append
    Write-Output "`nMachine-wide Chrome blocked extension list:" | Out-File -FilePath $Output -Append
    $BlockListChrome | Out-File -FilePath $Output -Append
    Write-Output "`nMachine-wide Edge force-install extension list:" | Out-File -FilePath $Output -Append
    $ForceListEdge | Out-File -FilePath $Output -Append
    Write-Output "`nMachine-wide Edge allowed extension list:" | Out-File -FilePath $Output -Append
    $AllowListEdge | Out-File -FilePath $Output -Append
    Write-Output "`nMachine-wide Edge blocked extension list:" | Out-File -FilePath $Output -Append
    $BlockListEdge | Out-File -FilePath $Output -Append
    Write-Output "Report written to: $Output." | Tee-Object -FilePath $logFilePath -Append
} else {
    # Write-Output "`nNot exporting report." | Tee-Object -FilePath $logFilePath -Append
}


if ($RemoveAll) {
    Write-Output "`nRemoving ALL Chrome/Edge extensions for all users..." | Tee-Object -FilePath $logFilePath -Append
    $ChromeExtPath = "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Extensions"
    # $ChromeCanaryExtPath = "C:\Users\*\AppData\Local\Google\Chrome SxS\User Data\Default\Extensions" Chrome Canary extension folder path
    $EdgeExtPath = "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\Extensions"

    Remove-BrowserExtensions -extPath $ChromeExtPath
    # Remove-BrowserExtensions -extPath $ChromeCanaryExtPath # Uncomment to remove extensions from Chrome Canary as well
    Remove-BrowserExtensions -extPath $EdgeExtPath

    Write-Output "All browser extensions removed for Chrome and Edge." | Tee-Object -FilePath $logFilePath -Append
} else {
    # Write-Output "`nNot removing Chrome/Edge extensions." | Tee-Object -FilePath $logFilePath -Append
}


if ($BlockAll) {
    Write-Output "`nBlocking ALL Chrome/Edge extensions..." | Tee-Object -FilePath $logFilePath -Append
    if (!(Test-Path $RegKeyBlockInstallChrome)){
        New-Item $RegKeyBlockInstallChrome -Force
        Write-Output "Created Reg Key $RegKeyBlockInstallChrome" | Tee-Object -FilePath $logFilePath -Append
        New-ItemProperty –Path $RegKeyBlockInstallChrome -Name "1" -Value "*"
        Write-Output "Created Chrome extension blocks at Local Machine level in registry." | Tee-Object -FilePath $logFilePath -Append
    } else {
        Remove-Item $RegKeyBlockInstallChrome -Force
        New-Item $RegKeyBlockInstallChrome -Force
        New-ItemProperty –Path $RegKeyBlockInstallChrome -Name "1" -Value "*"
        Write-Output "Recreated Chrome extension blocks at Local Machine level in registry." | Tee-Object -FilePath $logFilePath -Append
    }
    if (!(Test-Path $RegKeyBlockInstallEdge)){
        New-Item $RegKeyBlockInstallEdge -Force
        Write-Output "Created Reg Key $RegKeyBlockInstallEdge" | Tee-Object -FilePath $logFilePath -Append
        New-ItemProperty –Path $RegKeyBlockInstallEdge -Name "1" -Value "*"
        Write-Output "Created Edge extension blocks at Local Machine level in registry." | Tee-Object -FilePath $logFilePath -Append
    } else {
        Remove-Item $RegKeyBlockInstallEdge -Force
        New-Item $RegKeyBlockInstallEdge -Force
        New-ItemProperty –Path $RegKeyBlockInstallEdge -Name "1" -Value "*"
        Write-Output "Recreated Edge extension blocks at Local Machine level in registry." | Tee-Object -FilePath $logFilePath -Append
    }
} else {
    # Write-Output "`nNot disabling all Chrome/Edge extensions." | Tee-Object -FilePath $logFilePath -Append
}


if ($ClearBlocks) {
    Write-Output "`nRemoving all Chrome/Edge extension install blocks..." | Tee-Object -FilePath $logFilePath -Append
    if (!(Test-Path $RegKeyBlockInstallChrome)){
        Write-Output "No Chrome extension blocks found at Local Machine level in registry." | Tee-Object -FilePath $logFilePath -Append
    } else {
        Remove-Item $RegKeyBlockInstallChrome -Force
        Write-Output "Removed Chrome extension blocks at Local Machine level in registry." | Tee-Object -FilePath $logFilePath -Append
    }
    if (!(Test-Path $RegKeyBlockInstallEdge)){
        Write-Output "No Edge extension blocks found at Local Machine level in registry." | Tee-Object -FilePath $logFilePath -Append
    } else {
        Remove-Item $RegKeyBlockInstallEdge -Force
        Write-Output "Removed Edge extension blocks at Local Machine level in registry." | Tee-Object -FilePath $logFilePath -Append
    }
} else {
    # Write-Output "`nNot clearing all Chrome/Edge extension install blocks." | Tee-Object -FilePath $logFilePath -Append
}

Write-Output "`nScript complete." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Seconds elapsed for script execution: $($sw.elapsed.totalseconds)" | Tee-Object -FilePath $logFilePath -Append

Write-Output "`nDone!" | Tee-Object -FilePath $logFilePath -Append

Exit