$rootDirectory = "C:\Rocksalt"

# Install TeamViewer silently
Start-Process (Join-Path -Path $rootDirectory -ChildPath "TeamViewer_Host_Setup.exe") -ArgumentList "/S", "/ACCEPTEULA=1" -WindowStyle Hidden -Wait

# Ensure Chocolatey is installed
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
  Write-Host "Chocolatey is not installed. Installing now..." -ForegroundColor Yellow
  Set-ExecutionPolicy Bypass -Scope Process -Force
  [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
  Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
  Write-Host "Chocolatey installed successfully." -ForegroundColor Green
}

# Define the list of apps to install/update
$apps = @("googlechrome", "7zip", "notepadplusplus", "foxitreader")

# Install or update each app
foreach ($app in $apps) {
  Write-Host "Installing/updating $app..." -ForegroundColor Cyan
  choco install $app -y --force
}

# Install all apps in the Installers folder
$exeDirectory = Join-Path -Path $rootDirectory -ChildPath "Installers"
$exeFiles = Get-ChildItem -Path $exeDirectory -Filter "*.exe"

foreach ($exe in $exeFiles) {
  Write-Host "Installing: $($exe.Name)"
  Start-Process -FilePath $exe.FullName -ArgumentList "/S", "/quiet", "/norestart" -NoNewWindow -Wait
}

# Wait for user input before exiting
Read-Host -Prompt "Press Enter to exit"
