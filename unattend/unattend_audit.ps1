# Define output file path
$outputDirectory = "C:\Rocksalt"
$outputFile = "$outputDirectory\Audit.txt"

New-Item -ItemType Directory -Path $outputDirectory
Write-Host "Directory created: $outputDirectory"

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
$rocksaltExists = "Yes"
$clientAdmin = Read-Host "Client Admin"
$domainName = (Get-WmiObject -Class Win32_ComputerSystem).Domain
$createUser = Read-Host "Create standard user? (Y/n)"
if ($createUser -eq "Y" -or $createUser -eq "") {
    # Prompt for the username and password
    $username = Read-Host "Username:"
    $password = Read-Host "Password:" -AsSecureString

    # Create the new user
    New-LocalUser -Name $username -Password $password -FullName $username
}
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
$line = "$auditer`t$date`t$users`t$done`tGI$gi`t$pcName`t$manufacturer`t$model`t$type`t$serialNumber`t$os`t$win11Comp`t$updates`t$drivers`t$antiVirus`t$rocksaltExists`t$clientAdmin`t$domainName`t$username`t$processor`t$ram`t$ramType`t$diskSize`t$diskType`t$bitlocker`t$teamviewer`t$bruteForce`t$notes"

# Append to the output file
$line | Out-File -Append -FilePath $outputFile

Write-Host "System information has been appended to $outputFile"

# Wait for user input before exiting
Read-Host -Prompt "Press Enter to exit"
