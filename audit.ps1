# Define output file path
$outputFile = "C:\Rocksalt\Audit.txt"
$outputDirectory = [System.IO.Path]::GetDirectoryName($outputFile)

# Create the directory if it doesn't exist
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory
    Write-Host "Directory created: $outputDirectory"
}

$memoryType = @{
  20 = "DDR"
  21 = "DDR2"
  24 = "DDR3"
  26 = "DDR4"
  32 = "LPDDR"
  33 = "LPDDR2"
  34 = "LPDDR3"
  35 = "LPDDR4"
}

# Get system information
$pcName = $env:COMPUTERNAME
$manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
$model = (Get-WmiObject -Class Win32_ComputerSystem).Model
$serialNumber = (Get-WmiObject -Class Win32_BIOS).SerialNumber
$os = (Get-WmiObject -Class Win32_OperatingSystem).Caption
$processor = (Get-WmiObject -Class Win32_Processor).Name
$ram = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB
$ramType = Get-CimInstance -ClassName Win32_PhysicalMemory | Select-Object @{Name="MemoryType"; Expression={$memoryType[$_.MemoryType]}}
$diskSize = [math]::Round((Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'").Size / 1GB)
$diskType = Get-CimInstance -ClassName Win32_DiskDrive | Select-Object Model

# Prepare tab-separated line
$line = "$pcName`t$manufacturer`t$model`t$serialNumber`t$os`t$processor`t$ram`t$diskSize"

# Append to the output file
$line | Out-File -Append -FilePath $outputFile

Write-Host "System information has been appended to $outputFile"

# Wait for user input before exiting
Read-Host -Prompt "Press Enter to exit"
