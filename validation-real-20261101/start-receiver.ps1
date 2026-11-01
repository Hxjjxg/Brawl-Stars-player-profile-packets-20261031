$ErrorActionPreference = 'Stop'
$python = (Get-Command python -ErrorAction Stop).Source
$receiver = Join-Path $PSScriptRoot 'receiver.py'
$config = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'receiver-config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if (Get-NetTCPConnection -LocalPort $config.port -State Listen -ErrorAction SilentlyContinue) {
    & $python $receiver --status
    if ($LASTEXITCODE -ne 0) { throw 'Port is occupied by a different service; not starting another receiver.' }
    exit 0
}
$process = Start-Process -FilePath $python -ArgumentList @('-u', ('"' + $receiver + '"'), '--serve') -WindowStyle Hidden -PassThru -WorkingDirectory $PSScriptRoot -RedirectStandardOutput (Join-Path $PSScriptRoot 'receiver.stdout.log') -RedirectStandardError (Join-Path $PSScriptRoot 'receiver.stderr.log')
Set-Content -LiteralPath (Join-Path $PSScriptRoot 'receiver.pid') -Value $process.Id
Start-Sleep -Milliseconds 500
& $python $receiver --status
if ($LASTEXITCODE -ne 0) { throw 'Receiver did not become ready; inspect receiver.stderr.log.' }
