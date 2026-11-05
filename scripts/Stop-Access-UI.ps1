$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$state = Get-Content (Join-Path $repo 'target/access-ui-process.json') -Raw | ConvertFrom-Json
$process = Get-Process -Id $state.pid -ErrorAction SilentlyContinue
if (-not $process) { Write-Output 'Access UI is already stopped.'; return }
if ($process.ProcessName -ne 'node' -or $process.StartTime.ToUniversalTime() -ne ([datetime]$state.started).ToUniversalTime())
{
   throw 'The saved PID is no longer this access UI; refusing to stop it.'
}
# Next's development server has a child process; stop only this verified process tree.
& taskkill /PID $process.Id /T /F
if ($LASTEXITCODE -ne 0) { throw 'Could not stop the access UI process tree.' }
