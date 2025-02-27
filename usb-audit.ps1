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
$name = Read-Host "Enter Name"
$gi = Read-Host "Enter GI (numbers)"
$date = Get-Date -Format "yyyy-MM-dd"
$pcName = $env:COMPUTERNAME
$manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
$model = (Get-WmiObject -Class Win32_ComputerSystem).Model
$serialNumber = (Get-WmiObject -Class Win32_BIOS).SerialNumber
$os = (Get-WmiObject -Class Win32_OperatingSystem).Caption
# Check if the local Rocksalt exists
$rocksaltExists = if (Get-LocalUser -Name "Rocksalt" -ErrorAction SilentlyContinue) {
  "Yes"
} else {
  "No"
}
$domainName = (Get-WmiObject -Class Win32_ComputerSystem).Domain
$processor = (Get-WmiObject -Class Win32_Processor).Name
$ram = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB
# $ramType = Get-CimInstance -ClassName Win32_PhysicalMemory | Select-Object @{Name="MemoryType"; Expression={if ($memoryType[$_.MemoryType]) {$memoryType[$_.MemoryType]} else {"-"}}}
$diskSize = [math]::Round((Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'").Size / 1GB)
$diskType = Get-PhysicalDisk | Select-Object -ExpandProperty MediaType

# Prepare tab-separated line
$line = "`t$Date`tno`tGI$gi`t$pcName`t$manufacturer`t$model`t`t$serialNumber`t$os`t`t`t`t`t$rocksaltExists`t`t$domainName`t`t$name`t$processor`t$ram`t`t$diskSize`t$diskType`t`t`tYes"

# Append to the output file
$line | Out-File -Append -FilePath $outputFile

Write-Host "System information has been appended to $outputFile"

$driveLetter = Split-Path -Path $MyInvocation.MyCommand.Definition -Qualifier
$outputFile = "$driveLetter\Audit.txt"
$line | Out-File -Append -FilePath $outputFile

Write-Host "System information has been appended to $outputFile"

# Wait for user input before exiting
Read-Host -Prompt "Press Enter to exit"
