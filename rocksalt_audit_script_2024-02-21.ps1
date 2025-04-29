#Requires -RunAsAdministrator

<# INITIAL SETUP #>

$Directory = 'C:\Audit\'
$File = 'audit.txt'
$Path = $Directory + $File

# Create directory for audit output
New-Item -ItemType Directory -Path $Directory -Force > $null

# Create new text file for audit output
New-Item -ItemType File -Path $Path -Force > $null

# Run various 'Get' functions and save to local variables
# (e.g. so that we only have to call Get-ComputerInfo once - it is a very slow function!)
$ComputerInfo = Get-ComputerInfo
Write-Output 'Got computer info'
$RamInfo = Get-WmiObject -Class Win32_PhysicalMemory
Write-Output 'Got RAM'
$Users = Get-WmiObject -Class Win32_UserAccount
Write-Output 'Got users'
$AdminGroup = Get-WmiObject -Class Win32_Group -Filter "Name='Administrators'"
Write-Output 'Got admin group'
$Admins = Get-WmiObject -Query "ASSOCIATORS OF {$AdminGroup} where Role = GroupComponent"
Write-Output 'Got admins'
$TeamViewerInfo = Get-ItemProperty -Path HKLM:\Software\Teamviewer
Write-Output 'Got TeamViewer'
$KeyProtectors = try { (Get-BitLockerVolume).KeyProtector } catch { null } # REQUIRES ADMIN PERMISSIONS
Write-Output 'Got BitLocker'
$PhysicalDisks = Get-PhysicalDisk
Write-Output 'Got disks'
$Date = Get-Date -Format 'dddd dd MMMM yyyy HH:mm'
Write-Output 'Got date'
$InstalledSoftware = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
Write-Output 'Got software'

# Special character variables
$br = "`n"
$t = "`t"
$t2 = "$t$t"


<# CUSTOM FUNCTIONS #>

# (Form Factor and Type from https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.4.0a.pdf)
Function Convert-RamFormFactor([Parameter(Mandatory=$true)]$FormFactorDecimal){
    switch ($FormFactorDecimal){
        00 {'Unknown'}
        01 {'Other'}
        02 {'SIP'}
        03 {'DIP'}
        04 {'ZIP'}
        05 {'SOJ'}
        06 {'Proprietary'}
        07 {'SIMM'}
        08 {'DIMM'}
        09 {'TSOP'}
        10 {'PGA'}
        11 {'RIMM'}
        12 {'SODIMM'}
        13 {'SRIMM'}
        14 {'SMD'}
        15 {'SSMP'}
        16 {'QFP'}
        17 {'TQFP'}
        18 {'SOIC'}
        19 {'LCC'}
        20 {'PLCC'}
        21 {'BGA'}
        22 {'FPBGA'}
        23 {'LGA'}
        Default {'Unknown'}
    }
}

Function Convert-RamMemoryType([Parameter(Mandatory=$true)]$MemoryTypeDecimal){
    switch ($MemoryTypeDecimal){
      00 {'Unknown'}
      01 {'Other'}
      02 {'DRAM'}
      03 {'Synchronous DRAM'}
      04 {'Cache DRAM'}
      05 {'EDO'}
      06 {'EDRAM'}
      07 {'VRAM'}
      08 {'SRAM'}
      09 {'RAM'}
      10 {'ROM'}
      11 {'FLASH'}
      12 {'EEPROM'}
      13 {'FEPROM'}
      14 {'EPROM'}
      15 {'CDRAM'}
      16 {'3DRAM'}
      17 {'SDRAM'}
      18 {'SGRAM'}
      19 {'RDRAM'}
      20 {'DDR'}
      21 {'DDR2'}
      22 {'DDR FB-DIMM'}
      24 {'DDR3'}
      25 {'FBD2'}
      26 {'DDR4'}
      27 {'LPDDR'}
      28 {'LPDDR2'}
      29 {'LPDDR3'}
      30 {'LPDDR4'}
      31 {'Logical non-volatile device'}
      32 {'HBM'}
      33 {'HBM2'}
      34 {'DDR5'}
      35 {'LPDDR5'}
      Default {'Unknown'}
    }
}


<# MAIN HEADER #>

Add-Content -Path $Path -Value "--- ROCKSALT SYSTEM AUDIT ---"
Add-Content -Path $Path -Value "[$Date] $br"
Add-Content -Path $Path -Value "COMPUTER NAME:$t2 $($ComputerInfo.CsName) $br"


<# COMPUTER HARDWARE #>

# Add heading to output file
Add-Content -Path $Path -Value '---------------------'
Add-Content -Path $Path -Value '1.0 COMPUTER HARDWARE'
Add-Content -Path $Path -Value '---------------------'

# Computer hardware details
Add-Content -Path $Path -Value "Device Manufacturer:$t $($ComputerInfo.CsManufacturer)"
Add-Content -Path $Path -Value "System Family:$t2 $($ComputerInfo.CsSystemFamily)"
Add-Content -Path $Path -Value "Model Number:$t2 $($ComputerInfo.CsModel)"

# Processors
Add-Content -Path $Path -Value 'Processor(s):' -NoNewline
$ComputerInfo.CsProcessors.foreach{ Add-Content -Path $Path -Value "$t2 $($_.Name.Trim()) [$($_.Architecture) Architecture, $($_.NumberOfCores) Cores]" }

# RAM
$RamSize = $ComputerInfo.CsPhyicallyInstalledMemory/(1024*1024)
$RamSpeed = $RamInfo[0].Speed
$RamFormFactor = Convert-RamFormFactor -FormFactorDecimal ($RamInfo[0].FormFactor)
$RamMemoryType = Convert-RamMemoryType -MemoryTypeDecimal ($RamInfo[0].SMBIOSMemoryType)
Add-Content -Path $Path -Value "Installed RAM:$t2 $($RamSize)GB [$($RamSpeed)MHz, $RamMemoryType, $RamFormFactor]"

# BIOS
Add-Content -Path $Path -Value "BIOS Serial Number:$t $($ComputerInfo.BiosSeralNumber) $br"

Write-Output 'Processed computer hardware'


<# OPERATING SYSTEM #>

# Add heading to output file
Add-Content -Path $Path -Value '--------------------'
Add-Content -Path $Path -Value '2.0 OPERATING SYSTEM'
Add-Content -Path $Path -Value '--------------------'

# OS
Add-Content -Path $Path -Value "Operating System:$t $($ComputerInfo.OSName) [Build $($ComputerInfo.OSDisplayVersion)] $br"

Write-Output 'Processed operating system'


<# BROWSERS #>

# Add heading to output file
Add-Content -Path $Path -Value '----------------------'
Add-Content -Path $Path -Value '3.0 INSTALLED BROWSERS'
Add-Content -Path $Path -Value '----------------------'

# Match software in uninstall list to browser names
$Names = 'Firefox', 'Chrome', 'Microsoft Edge', 'Opera', 'Safari', 'Brave', 'Vivaldi', 'Chromium', 'DuckDuckGo', 'Epic', 'Pale Moon'
$MatchingSoftware = foreach($Item in $Names) 
{ 
  $InstalledSoftware | 
  Where-Object -Property DisplayName -Match -Value $Item | 
  Select-Object -Property @{Name = 'NAME'; Expression = {$_.DisplayName}}, @{Name = 'VERSION'; Expression = {$_.DisplayVersion}}
}
$MatchingSoftware = $MatchingSoftware | Sort-Object -Property 'NAME'

# Add to output file
$MatchingSoftware.foreach{ Add-Content -Path $Path -Value "- $($_.NAME) [Version $($_.VERSION)]" }
Add-Content -Path $Path -Value ''

Write-Output 'Processed browsers'


<# ALL SOFTWARE #>

# Add heading to output file
Add-Content -Path $Path -Value '----------------------'
Add-Content -Path $Path -Value '3.1 INSTALLED SOFTWARE'
Add-Content -Path $Path -Value '----------------------'

# Produce software table
$InstalledSoftware | 
Where-Object -Property DisplayName -ne $null |
Sort-Object -Property DisplayName, DisplayVersion | 
Format-Table @{Label = 'Name'; Expression = {"$($_.DisplayName)"}},
@{Label = 'Version'; Expression = {"$($_.DisplayVersion)"}},
@{Label = 'Publisher'; Expression = {"$($_.Publisher)"}},
@{Label = 'Install Date'; Expression = {"$($_.InstallDate)"}}, -AutoSize | 
Out-File -FilePath $Path -Encoding 'ASCII' -Append

Write-Output 'Processed software'

<# USER ACCOUNTS #>

# Add heading to output file
Add-Content -Path $Path -Value '-----------------'
Add-Content -Path $Path -Value '4.0 USER ACCOUNTS'
Add-Content -Path $Path -Value '-----------------'

# Domain
Add-Content -Path $Path -Value "Domain:$t $($ComputerInfo.CsDomain) [Role: $($ComputerInfo.CsDomainRole)] $br"

# Check for local Rocksalt account
$RocksaltUser = "NO"
$Admins | ?{$_.Caption -in "$($ComputerInfo.CsName)\Rocksalt"} | %{ $RocksaltUser = "YES" }
Add-Content -Path $Path -Value "Local Rocksalt Admin Account: $RocksaltUser" 

# Users table
$Users | 
Select-Object -Property Caption, Disabled, @{Name = 'Admin'; Expression = {$(if($Admins.Contains($_)){1} else {0})}} | 
Sort-Object -Property Disabled,Admin | 
Format-Table @{Label = 'DOMAIN\User Account'; Expression = {"$($_.Caption)"}},
@{Label = 'Administrator?'; Expression = {$(if($_.Admin){"YES"})}},
@{Label = 'Disabled?'; Expression = {$(if($_.Disabled){"YES"})}} -AutoSize | 
Out-File -FilePath $Path -Encoding 'ASCII' -Append

Write-Output 'Processed user accounts'


<# PHYSICAL DISKS #>

# Add heading to output file
Add-Content -Path $Path -Value '------------------'
Add-Content -Path $Path -Value '5.0 PHYSICAL DISKS'
Add-Content -Path $Path -Value '------------------'

# Output disk table
$PhysicalDisks | 
Sort-Object -Property DeviceID | 
Format-Table -Property @{Name = 'ID'; Expression = {$_.DeviceID}}, 
@{Name = 'Model'; Expression = {"$($_.Model)"}},
@{Name = 'Size (GiB)'; Expression = {'{0:n2}' -f $($($_.Size)/(1024*1024*1024)) }},
@{Name = 'Size (GB)'; Expression = {'{0:n2}' -f $($($_.Size)/(1000*1000*1000)) }},
@{Name = 'Disk Type'; Expression = {"$($_.MediaType) [$($_.BusType)]"}},
@{Name = 'Serial Number'; Expression = {"$($_.SerialNumber.Trim('.').Replace('_', ''))"}} -AutoSize | 
Out-File -FilePath $Path -Encoding 'ASCII' -Append

Write-Output 'Processed disks'


<# TEAM VIEWER #>

# Add heading to output file
Add-Content -Path $Path -Value '----------------------'
Add-Content -Path $Path -Value '6.0 TEAMVIEWER DETAILS'
Add-Content -Path $Path -Value '----------------------'

# Format TeamViewer details and output
$TeamViewerInfo | 
Format-Table @{Name = 'TeamViewer ID'; Expression = {$_.ClientID}},
@{Name = 'Version'; Expression = {$_.Version}}, 
@{Name = 'Installation Directory'; Expression = {$_.InstallationDirectory}} -AutoSize | 
Out-File -FilePath $Path -Encoding 'ASCII' -Append

Write-Output 'Processed TeamViewer'


<# BITLOCKER #>

# Add heading to output file
Add-Content -Path $Path -Value '---------------------'
Add-Content -Path $Path -Value '7.0 BITLOCKER DETAILS'
Add-Content -Path $Path -Value '---------------------'

if ( $KeyProtectors -eq $null )
{
    Add-Content -Path $Path -Value "No BitLocker details found $br"
}
else
{
    $KeyProtector = $KeyProtectors | Where-Object -Property KeyProtectorType -Match -Value 'RecoveryPassword'
    Add-Content -Path $Path -Value "Key ID: $t$($KeyProtector.KeyProtectorId.Replace('{', '').Replace('}', ''))"
    Add-Content -Path $Path -Value "Key Password: $t$($KeyProtector.RecoveryPassword) $br"
}


<# BRUTE FORCE PROTECTION #>

# Add heading to output file
Add-Content -Path $Path -Value '--------------------------'
Add-Content -Path $Path -Value '8.0 BRUTE FORCE PROTECTION'
Add-Content -Path $Path -Value '--------------------------'

# Turn on brute force protection
net accounts /lockoutthreshold:10 > $null
net accounts /lockoutwindow:5 > $null
net accounts /lockoutduration:30 > $null

Add-Content -Path $Path -Value "Brute force protection enabled $br"


<# DISABLE AUTORUN #>

# Add heading to output file
Add-Content -Path $Path -Value '---------------------'
Add-Content -Path $Path -Value '9.0 AUTO RUN DISABLED'
Add-Content -Path $Path -Value '---------------------'

# Create or modify registry entries which disable autorun for all drive types
$AutoRunPath ='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
Set-ItemProperty $AutoRunPath -Name NoDriveTypeAutorun -Type DWord -Value 0xFF
Set-ItemProperty $AutoRunPath -Name NoAutorun -Type DWord -Value 0x01

Add-Content -Path $Path -Value "Auto-run disabled $br"


Add-Content -Path $Path -Value '---------------'
Add-Content -Path $Path -Value 'AUDIT COMPLETED'
Add-Content -Path $Path -Value '---------------'