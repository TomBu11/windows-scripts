$rootDirectory = "C:\Rocksalt"

# Install TeamViewer silently
Start-Process (Join-Path -Path $rootDirectory -ChildPath "TeamViewer_Host_Setup.exe") -ArgumentList "/S", "/ACCEPTEULA=1" -WindowStyle Hidden -Wait

# Install all apps in the Installers folder
$exeDirectory = Join-Path -Path $rootDirectory -ChildPath "Installers"
$exeFiles = Get-ChildItem -Path $exeDirectory -Filter "*.exe"

foreach ($exe in $exeFiles) {
  Start-Process -FilePath $exe.FullName -ArgumentList "/S", "/quiet", "/norestart" -NoNewWindow -Wait
}
