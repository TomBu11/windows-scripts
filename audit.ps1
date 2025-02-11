# Define output file path
$outputFile = "C:\Rocksalt\Audit.txt"

# Get system information
$pcName = $env:COMPUTERNAME
$manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
$model = (Get-WmiObject -Class Win32_ComputerSystem).Model
$serialNumber = (Get-WmiObject -Class Win32_BIOS).SerialNumber
$os = (Get-WmiObject -Class Win32_OperatingSystem).Caption
$processor = (Get-WmiObject -Class Win32_Processor).Name
$ram = (Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory / 1GB
$diskSize = (Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'").Size / 1GB

# Prepare tab-separated line
$line = "$pcName`t$manufacturer`t$model`t$serialNumber`t$os`t$processor`t$ram`t$diskSize"

# Append to the output file
$line | Out-File -Append -FilePath $outputFile

Write-Host "System information has been appended to $outputFile"
wait