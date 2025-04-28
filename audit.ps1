#Requires -RunAsAdministrator

<# INITIAL SETUP #>

$outputDirectory = "C:\Rocksalt"
$outputFile = Join-Path $outputDirectory "Audit.txt"

# Create the directory if it doesn't exist
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory
    Write-Host "Directory created: $outputDirectory"
} else {
    Write-Host "Directory already exists: $outputDirectory"
}

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
$InstalledSoftware = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
Write-Output 'Got software'


<# HELPER FUNCTIONS #>

# (from https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.4.0a.pdf)
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

function Read-YesNo($prompt) {
  return if ((Read-Host "$prompt (y/N)") -match '^y$') { "Yes" } else { "No" }
}

<# BRUTE FORCE PROTECTION #>

Write-Host "Running brute force commands"
net accounts /lockoutthreshold:10
net accounts /lockoutwindow:5
net accounts /lockoutduration:30


<# AUDIT INFORMATION #>

$clientAdmin = $Admins | Where-Object { $_.LocalAccount -eq $true } | Select-Object -ExpandProperty Name
# $ramType = Get-CimInstance -ClassName Win32_PhysicalMemory | Select-Object @{Name="MemoryType"; Expression={if ($memoryType[$_.MemoryType]) {$memoryType[$_.MemoryType]} else {"-"}}}

$auditer         = Read-Host "RS (initials)"
$date            = Get-Date -Format "yyyy-MM-dd"
$done            = "Part"
$users           = Read-Host "Users"
$gi              = Read-Host "GI (numbers)"
$pcName          = $env:COMPUTERNAME
$manufacturer    = $ComputerInfo.CsManufacturer
$model           = $ComputerInfo.CsModel
$type            = if ($ComputerInfo.CsPCSystemType -eq 2) { "Laptop" } else { "Desktop" }
$serialNumber    = $ComputerInfo.BiosSeralNumber
$os              = $ComputerInfo.OSName
$win11Comp       = if ($os -match "11") { "Yes" } else { "No" }
$updates         = Read-YesNo "Updates (y/N)"
$drivers         = Read-YesNo "Drivers (y/N)"
$antiVirus       = Read-YesNo "Antivirus (y/N)"
$rocksaltExists  = if (Get-LocalUser -Name "Rocksalt" -ErrorAction SilentlyContinue) { "Yes" } else { "No" }
$clientAdmin     = $Admins | Where-Object { $_.LocalAccount -eq $true } | Select-Object -ExpandProperty Name
$userName        = Read-Host "Username (Account they use)"
$domainName      = $ComputerInfo.CsDomain
$processor       = $ComputerInfo.CsProcessors
$ram             = [math]::Round($ComputerInfo.CsPhysicallyInstalledMemory / 1GB)
$ramType         = Convert-RamMemoryType -MemoryTypeDecimal ($RamInfo[0].SMBIOSMemoryType)
$diskSize        = [math]::Round((Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'").Size / 1GB)
$diskType        = "$($PhysicalDisks.MediaType) $($PhysicalDisks.BusType)"
$bitlocker       = if ($bitlockerStatus -eq 1) { "Yes" } else { "No" }
$teamViewer      = $TeamViewerInfo.ClientID
$bruteForce      = "Yes"
$notes           = Read-Host "Notes"



$lineTable = [PSCustomObject]@{
  Auditer         = $auditer
  Date            = $date
  Done            = $done
  Users           = $users
  GI              = "GI$gi"
  PCName          = $pcName
  Manufacturer    = $manufacturer
  Model           = $model
  Type            = $type
  SerialNumber    = $serialNumber
  OS              = $os
  Win11Compatible = $win11Comp
  Updates         = $updates
  Drivers         = $drivers
  AntiVirus       = $antiVirus
  RocksaltExists  = $rocksaltExists
  ClientAdmin     = $clientAdmin
  UserName        = $userName
  DomainName      = $domainName
  Processor       = $processor
  RAM             = $ram
  RAMType         = $ramType
  DiskSize        = $diskSize
  DiskType        = $diskType
  Empty1          = ""
  Empty2          = ""
  Bitlocker       = $bitlocker
  TeamViewer      = $teamviewer
  BruteForce      = $bruteForce
  Notes           = $notes
}

<# OUTPUT #>

$line = ($lineTable.PSObject.Properties | ForEach-Object { $_.Value }) -join "`t"

Write-Host "`n=== Tab-separated Line ==="
Write-Host $line

Write-Host "`n=== Vertical Table ==="
$lineTable | Format-List


<# SAVE OUTPUT #>

$line | Out-File -Append -FilePath $outputFile

Read-Host -Prompt "System information has been appended to $outputFile (Enter to exit)"
