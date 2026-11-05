param(
   [string]$FrontendPath = (Join-Path $env:USERPROFILE '.cache/qqq-authentik-access-ui'),
   [int]$Port = 18301,
   [int]$BackendPort = 18300
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$frontend = (Resolve-Path -LiteralPath $FrontendPath).Path
$cli = Join-Path $frontend 'node_modules/next/dist/bin/next'
if (-not (Test-Path -LiteralPath $cli)) { throw "Install the frontend's pinned dependencies first: pnpm install --frozen-lockfile" }
$stateFile = Join-Path $repo 'target/access-ui-process.json'
if (Test-Path $stateFile)
{
   $previous = Get-Content $stateFile -Raw | ConvertFrom-Json
   $running = Get-Process -Id $previous.pid -ErrorAction SilentlyContinue
   if ($running -and $running.StartTime.ToUniversalTime() -eq ([datetime]$previous.started).ToUniversalTime())
   {
      throw "Access UI is already running at http://127.0.0.1:$($previous.port)."
   }
}
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
try { $listener.Start() } finally { $listener.Stop() }
$env:QQQ_BACKEND_URL = "http://127.0.0.1:$BackendPort"
$env:NEXT_PUBLIC_MOCK_API = 'false'
$process = Start-Process -FilePath (Get-Command node).Source -ArgumentList @(('"' + $cli + '"'), 'dev', '--hostname', '127.0.0.1', '--port', $Port) -WorkingDirectory $frontend -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $repo 'target/access-ui.log') -RedirectStandardError (Join-Path $repo 'target/access-ui-error.log')
@{pid=$process.Id;started=$process.StartTime.ToUniversalTime().ToString('o');port=$Port} | ConvertTo-Json | Set-Content $stateFile
Write-Output "Access UI: http://127.0.0.1:$Port/app/authentikAdmin"
