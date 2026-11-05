$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$state = Get-Content (Join-Path $repo 'target/review-process.json') -Raw | ConvertFrom-Json
$process = Get-Process -Id $state.pid -ErrorAction SilentlyContinue
if ($process -and ($process.StartTime.ToUniversalTime() -ne ([datetime]$state.started).ToUniversalTime() -or $process.ProcessName -ne 'java'))
{
   throw 'The PID no longer belongs to this review server; refusing to stop it.'
}
if ($process) { Stop-Process -Id $process.Id }
$manifestPath = Join-Path $repo 'target/review-containers.json'
if (Test-Path $manifestPath)
{
   $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
   foreach ($id in $manifest.containers)
   {
      if ($id -notmatch '^[a-f0-9]{64}$') { throw 'Invalid container identity in review manifest.' }
      $owner = & docker inspect --format '{{index .Config.Labels "io.qrun.qbit.project"}}' $id 2>$null
      if ($LASTEXITCODE -ne 0) { continue }
      if ($owner -ne 'qbit-authentik') { throw 'Container ownership does not match this review.' }
      & docker rm -f $id | Out-Null
   }
   # Docker refuses removal if another container is still attached.
   if ($manifest.network -match '^[a-f0-9]{64}$') { & docker network rm $manifest.network 2>$null | Out-Null }
}
Write-Output 'Review server and its owned containers stopped; review data is not retained.'
