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

Write-Host "All applications installed/updated successfully." -ForegroundColor Green

# Wait for user input before exiting
Read-Host -Prompt "Press Enter to exit"