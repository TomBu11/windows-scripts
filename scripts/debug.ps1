$exeDirectory = Split-Path -Parent ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)
$scriptToRun = Join-Path -Path $exeDirectory -ChildPath "audit.ps1"

try {
    & $scriptToRun
} catch {
  Write-Host "Error in script: $scriptToRun" -ForegroundColor Red
  Write-Host "File: $($_.InvocationInfo.ScriptName)" -ForegroundColor Yellow
  Write-Host "Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line)" -ForegroundColor Yellow
  Write-Host "Message: $($_.Exception.Message)" -ForegroundColor Red
  Read-Host -Prompt "Press Enter to exit"
  exit 1
}