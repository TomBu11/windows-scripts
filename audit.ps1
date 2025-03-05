# Define output file path
$outputDirectory = "C:\Rocksalt"
$outputFile = "$outputDirectory\Audit.txt"

# Create the directory if it doesn't exist
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory
    Write-Host "Directory created: $outputDirectory"
}

$memoryType = @{
  21 = "DDR 2"
  24 = "DDR 3"
  26 = "DDR 4"
}

# Set Brute Force rules
Write-Host "Running brute force commands"
net accounts /lockoutthreshold:10
net accounts /lockoutwindow:5
net accounts /lockoutduration:30

# Get audit information
$auditer = Read-Host "RS (initials)"
$date = Get-Date -Format "yyyy-MM-dd"
$users = Read-Host "Users"
$done = "No"
$gi = Read-Host "GI (numbers)"
$pcName = $env:COMPUTERNAME
$manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
$model = (Get-WmiObject -Class Win32_ComputerSystem).Model
$type = Read-Host "Type (Laptop or Desktop)"
$serialNumber = (Get-WmiObject -Class Win32_BIOS).SerialNumber
$os = (Get-WmiObject -Class Win32_OperatingSystem).Caption
$win11Comp = if ($os -match "11") { "Yes" } else { "No" }
$updates = Read-Host "Updates"
$drivers = Read-Host "Drivers"
$antiVirus = Read-Host "Antivirus"
# Check if the local Rocksalt exists
$rocksaltExists = if (Get-LocalUser -Name "Rocksalt" -ErrorAction SilentlyContinue) {
  "Yes"
} else {
  "No"
}
$clientAdmin = Read-Host "Client Admin"
$domainName = (Get-WmiObject -Class Win32_ComputerSystem).Domain
$userName = Read-Host "Username (Account they use)"
$processor = (Get-WmiObject -Class Win32_Processor).Name
$ram = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB
# $ramType = Get-CimInstance -ClassName Win32_PhysicalMemory | Select-Object @{Name="MemoryType"; Expression={if ($memoryType[$_.MemoryType]) {$memoryType[$_.MemoryType]} else {"-"}}}
$diskSize = [math]::Round((Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'").Size / 1GB)
$diskType = Get-PhysicalDisk | Select-Object -ExpandProperty MediaType
$bitlocker = Read-Host "Bitlocker"
$teamviewer = Read-Host "Teamviewer ID"
$bruteForce = "Yes"
$notes = Read-Host "Notes"

# Prepare tab-separated line
$line = "$auditer`t$date`t$users`t$done`tGI$gi`t$pcName`t$manufacturer`t$model`t$type`t$serialNumber`t$os`t$win11Comp`t$updates`t$drivers`t$antiVirus`t$rocksaltExists`t$clientAdmin`t$domainName`t$userName`t$processor`t$ram`t$ramType`t$diskSize`t$diskType`t$bitlocker`t$teamviewer`t$bruteForce`t$notes"

# Append to the output file
$line | Out-File -Append -FilePath $outputFile

Write-Host "System information has been appended to $outputFile"

# Wait for user input before exiting
Read-Host -Prompt "Press Enter to exit"
