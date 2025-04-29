#Requires -RunAsAdministrator

<# OPTIONS #>

param (
  [string]$auditMode = "NORMAL" # NORMAL, UNATTEND, USB
)

$outputDirectory = "C:\Rocksalt"
$exeDirectory = Split-Path -Parent ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)
Write-Host "Script directory: $exeDirectory"

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
  if ((Read-Host "$prompt (y/N)") -eq 'y') {
    return "Yes"
  } else {
    return "No"
  }
}

function Get-TeamViewerInfo {
  $possiblePaths = @(
      "HKLM:\SOFTWARE\TeamViewer",
      "HKLM:\SOFTWARE\Wow6432Node\TeamViewer"
  )

  $TeamViewerInfo = $null
  foreach ($path in $possiblePaths) {
    if (Test-Path $path) {
      $TeamViewerInfo = Get-ItemProperty -Path $path
      if ($?) {
        Write-Host "Got TeamViewer info from: $path"
        return $TeamViewerInfo
      }
    }
  }
  return $null
}

function Create-RocksaltUser {
  if ((Read-Host "Create local Rocksalt user? (Y/n)") -ne 'n') {
    $password = Read-Host "Enter password" -AsSecureString
    New-LocalUser -Name "Rocksalt" -Password $password -FullName "Rocksalt" -Description "Rocksalt" | Out-Null
    Add-LocalGroupMember -Group "Administrators" -Member "Rocksalt" | Out-Null
    Write-Host "Rocksalt user created"
    return "Yes"
  }
  return "No"
}


<# INITIAL SETUP #>

# Ensure directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null
    Write-Host "Output directory created: $outputDirectory"
} else {
    Write-Host "Output directory already exists: $outputDirectory"
}

# Run various 'Get' functions and save to local variables
# (e.g. so that we only have to call Get-ComputerInfo once - it is a very slow function!)
Write-Host "`n=== Getting system information ===`n" -ForegroundColor DarkYellow

$ComputerName = $env:COMPUTERNAME
$ComputerInfo = Get-ComputerInfo; if ($?) { Write-Host 'Got computer info' }
$RamInfo = Get-WmiObject -Class Win32_PhysicalMemory; if ($?) { Write-Host 'Got RAM' }
$Admins = Get-LocalGroupMember -Group "Administrators" | Select-Object -ExpandProperty Name; if ($?) { Write-Host 'Got admins' }
$Users = Get-LocalGroupMember -Group "Users" | Where-Object {
  $Admins -notcontains $_.Name -and
  $_.Name -notmatch "^NT AUTHORITY" -and
  $_.Name -notmatch "^BUILTIN"
} | Select-Object -ExpandProperty Name; if ($?) { Write-Host 'Got users' }
$TeamViewerInfo = Get-TeamViewerInfo
$PhysicalDisks = Get-PhysicalDisk; if ($?) { Write-Host 'Got disks' }
$InstalledSoftware = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*; if ($?) { Write-Host 'Got software' }


<# AUDIT INFORMATION #>

$date            = Get-Date -Format "yyyy-MM-dd"
$manufacturer    = $ComputerInfo.CsManufacturer
$model           = $ComputerInfo.CsModel
$type            = if ($ComputerInfo.CsPCSystemType -eq 2) { "Laptop" } else { "Desktop" }
$serialNumber    = $ComputerInfo.BiosSeralNumber
$os              = $ComputerInfo.OSName
$win11Comp       = if ($os -match "11") { "Yes" } else { "No" }
$domainName      = $ComputerInfo.CsDomain
$processor       = $ComputerInfo.CsProcessors.Name -join ', '
$ram             = [math]::Round($ComputerInfo.CsTotalPhysicalMemory / 1GB)
try {
  $ramType       = Convert-RamMemoryType -MemoryTypeDecimal ($RamInfo[0].SMBIOSMemoryType)
} catch {
  $ramType       = "Unknown"
}
$disk1Size       = [math]::Round($PhysicalDisks[0].Size / 1GB)
$disk1Type       = "$($PhysicalDisks[0].MediaType) $($PhysicalDisks[0].BusType)"
$disk2Size       = if ($PhysicalDisks.Count -gt 1) { [math]::Round($PhysicalDisks[1].Size / 1GB) } else { "" }
$disk2Type       = if ($PhysicalDisks.Count -gt 1) { "$($PhysicalDisks[1].MediaType) $($PhysicalDisks[1].BusType)" } else { "" }
$bitlocker       = if ($bitlockerStatus -eq 1) { "Yes" } else { "No" }
$teamViewer      = $TeamViewerInfo.ClientID
$chromeVersion   = ($InstalledSoftware | Where-Object { $_.DisplayName -eq "Google Chrome" }).DisplayVersion
$firefoxVersion  = ($InstalledSoftware | Where-Object { $_.DisplayName -eq "Mozilla Firefox" }).DisplayVersion
$edgeVersion     = ($InstalledSoftware | Where-Object { $_.DisplayName -eq "Microsoft Edge" }).DisplayVersion

if ($physicalDisks.Count -gt 2) {
  Write-Host "More than 2 disks detected" -ForegroundColor Yellow
}


<# BRUTE FORCE PROTECTION #>

Write-Host "`n=== Running brute force commands ===`n" -ForegroundColor DarkYellow 
net accounts /lockoutthreshold:10
net accounts /lockoutwindow:5
net accounts /lockoutduration:30


<# TEAMVIEWER #>

if (-not $TeamViewerInfo) {
  Write-Host "TeamViewer not installed" -ForegroundColor Red
  if ((Read-Host "Install TeamViewer? (Y/n)") -ne 'n') {
    $teamviewerInstaller = Join-Path -Path $outputDirectory -ChildPath "TeamViewer_Host_Setup.exe"
    # Download TeamViewer
    Invoke-WebRequest -Uri "https://rocksalt.cc/tv" -OutFile $teamviewerInstaller
    if ($?) {
      Write-Host "TeamViewer installer downloaded to $teamviewerInstaller"

      # Install TeamViewer silently
      Start-Process $teamviewerInstaller -ArgumentList "/S", "/ACCEPTEULA=1" -WindowStyle Hidden -Wait

      if ($?) {
        Write-Host "TeamViewer installed successfully"
        $TeamViewerInfo = Get-TeamViewerInfo
      } else {
        Write-Host "Failed to install TeamViewer" -ForegroundColor Red
      }
    } else {
      Write-Host "Failed to download TeamViewer installer" -ForegroundColor Red
    }
  }
}


<# ROCKSALT USER #>

if ($Admins -contains "$computerName\Rocksalt") {
  Write-Host "Local Rocksalt user exits and is administrator"
  $rocksaltExists = "Yes"
} elseif ($Admins -match '\\Rocksalt$') {
  Write-Host "Rocksalt is an administrator, but it's a domain account" -ForegroundColor Yellow

  $rocksaltExists = Create-RocksaltUser
} elseif (Get-LocalUser -Name "Rocksalt" -ErrorAction SilentlyContinue) {
  Write-Host "Local Rocksalt user is not administrator" -ForegroundColor Red

  if ((Read-Host "Make Rocksalt admin? (Y/n)") -ne 'n') {
    Add-LocalGroupMember -Group "Administrators" -Member "Rocksalt"
    Write "Local Rocksalt user added to Administrators group"
    $rocksaltExists = "Yes"
  } else {
    $rocksaltExists = "No"
  }
} else {
  Write-Host "Local Rocksalt user does not exist" -ForegroundColor Red

  $rocksaltExists = Create-RocksaltUser
}


<# WINDOWS 11 COMPLIANT #>

if ($win11Comp -eq "No") {
  Write-Host "Not on Windows 11" -ForegroundColor Red

  $HardwareReadiness = & "$exeDirectory\HardwareReadiness.ps1" 2>&1 | Out-String | ConvertFrom-Json

  if ($HardwareReadiness.returnResult -eq "CAPABLE") {
    Write-Host "Windows 11 compatible" -ForegroundColor Green
    $win11Comp = "Yes"
  } else {
    Write-Host "Not Windows 11 compatible" -ForegroundColor Red
    $win11Comp = "No"
    Write-Host "Reason: $($HardwareReadiness.returnReason)" -ForegroundColor Red
  }
}


<# AUDITER INPUT #>

if ($auditMode -ne "UNATTEND") {
  Write-Host "`n=== Audit information ===`n" -ForegroundColor DarkYellow

  $auditer       = Read-Host "RS (initials)"
  $name          = Read-Host "Name"
  $gi            = Read-Host "GI (numbers)"
  $updates       = Read-YesNo "Updates"
  $drivers       = Read-YesNo "Drivers"
  $antiVirus     = Read-YesNo "Antivirus"
  Write-Host "Admin Accounts: $Admins"
  $clientAdmin   = Read-Host "Client Admin"
  Write-Host "User Accounts: $Users"
  $userName      = Read-Host "Username (Account they use)"

  Write-Host "`nChrome version: $chromeVersion`nFirefox version: $firefoxVersion`nEdge version: $edgeVersion"

  $InstalledSoftware |
  Where-Object { $_.DisplayName -ne $null } |
  Sort-Object DisplayName, DisplayVersion |
  Format-Table @{Label = 'Name'; Expression = { $_.DisplayName }},
                @{Label = 'Version'; Expression = { $_.DisplayVersion }},
                @{Label = 'Publisher'; Expression = { $_.Publisher }},
                @{Label = 'Install Date'; Expression = { $_.InstallDate }} -AutoSize
  $otherBrowsers = Read-Host "Other browsers"
  $softwareValid = Read-YesNo "Software valid?"
  $notes         = Read-Host "Notes"
}


<# OUTPUT #>

$lineTable = [PSCustomObject]@{
  Auditer         = $auditer
  Date            = $date
  Done            = "Part"
  Users           = $name
  GI              = "GI$gi"
  PCName          = $ComputerName
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
  RAM             = "$ram GB"
  RAMType         = $ramType
  DiskSize        = "$disk1Size GB"
  DiskType        = $disk1Type
  Disk2Size       = "$disk2Size GB"
  Disk2Type       = $disk2Type
  Bitlocker       = $bitlocker
  TeamViewer      = $teamviewer
  BruteForce      = "Yes"
  ChromeVersion   = $chromeVersion
  FirefoxVersion  = $firefoxVersion
  EdgeVersion     = $edgeVersion
  OtherBrowsers   = $otherBrowsers
  SoftwareValid   = $softwareValid
  Notes           = $notes
}

$line = ($lineTable.PSObject.Properties | ForEach-Object { $_.Value }) -join "`t"

Write-Host "`n=== Tab-separated Line ===`n" -ForegroundColor DarkYellow
Write-Host $line

Write-Host "`n=== Vertical Table ===`n" -ForegroundColor DarkYellow
$lineTable | Format-List


<# SAVE OUTPUT #>

$outputFile = Join-Path $outputDirectory "Audit.txt"

$line | Out-File -Append -FilePath $outputFile

Write-Host "System information has been appended to $outputFile"

if ($outputDirectory -ne "$exeDirectory") {
  $outputFile = Join-Path $exeDirectory "Audit.txt"
  $line | Out-File -Append -FilePath $outputFile

  Write-Host "System information has been appended to $outputFile"
}

Read-Host -Prompt "Press Enter to exit"