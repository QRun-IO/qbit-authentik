param([int]$Port = 18300, [string]$FrontendJar)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Push-Location $repo
try
{
   New-Item -ItemType Directory -Force target | Out-Null
   if (Test-Path target/review-process.json)
   {
      $previous = Get-Content target/review-process.json -Raw | ConvertFrom-Json
      $running = Get-Process -Id $previous.pid -ErrorAction SilentlyContinue
      if ($running -and $running.StartTime.ToUniversalTime() -eq ([datetime]$previous.started).ToUniversalTime())
      {
         throw "Review server is already running (PID $($previous.pid))."
      }
   }
   $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
   try { $listener.Start() } finally { $listener.Stop() }
   & ./mvnw.cmd test-compile dependency:build-classpath '-Dmdep.outputFile=target/review-classpath.txt' *> target/review-build.log
   if ($LASTEXITCODE -ne 0) { throw 'Review build failed; see target/review-build.log.' }
   $dependencies = (Get-Content target/review-classpath.txt -Raw).Trim().Split(';')
   $frontendHash = $null
   if ($FrontendJar)
   {
      $FrontendJar = (Resolve-Path -LiteralPath $FrontendJar).Path
      $archive = [System.IO.Compression.ZipFile]::OpenRead($FrontendJar)
      try
      {
         if (-not $archive.GetEntry('next-dashboard/index.html')) { throw 'Frontend JAR has no static dashboard entry point.' }
      }
      finally { $archive.Dispose() }
      # Serve this exact artifact; old dependency assets must not fill missing files.
      $dependencies = @($FrontendJar) + @($dependencies | Where-Object { [System.IO.Path]::GetFileName($_) -notlike 'qqq-frontend-next-*.jar' })
      $frontendHash = (Get-FileHash -LiteralPath $FrontendJar -Algorithm SHA256).Hash
   }
   $classpath = (Join-Path $repo 'target/test-classes') + ';' + (Join-Path $repo 'target/classes') + ';' + ($dependencies -join ';')
   $arguments = @('-XX:ActiveProcessorCount=4', '-cp', ('"' + $classpath.Replace('\', '/') + '"'), 'com.kingsrook.qbits.authentik.contract.AuthentikReviewServer', "$Port")
   Set-Content target/review-java.args $arguments -Encoding utf8NoBOM
   # A manual review must outlive an idle Ryuk connection. Stop-Review owns cleanup.
   $previousRyuk = $env:TESTCONTAINERS_RYUK_DISABLED
   $env:TESTCONTAINERS_RYUK_DISABLED = 'true'
   $process = Start-Process -FilePath (Get-Command java).Source -ArgumentList '@target/review-java.args' -WorkingDirectory $repo -WindowStyle Hidden -PassThru -RedirectStandardOutput target/review-server.log -RedirectStandardError target/review-server-error.log
   $env:TESTCONTAINERS_RYUK_DISABLED = $previousRyuk
   @{ pid = $process.Id; started = $process.StartTime.ToUniversalTime().ToString('o'); port = $Port; frontendJar = $FrontendJar; frontendSha256 = $frontendHash } | ConvertTo-Json | Set-Content target/review-process.json
   Write-Output "Review starting at http://localhost:$Port/app/authentikAdmin (PID $($process.Id)). First boot can take several minutes."
   Write-Output 'Read target/review-server.log for readiness and the Authentik/Mailpit URLs. Run scripts/Stop-Review.ps1 when done.'
}
finally { Pop-Location }
