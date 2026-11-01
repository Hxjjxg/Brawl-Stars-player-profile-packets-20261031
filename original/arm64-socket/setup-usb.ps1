param([string]$Serial = '10AF182G2600122')
$ErrorActionPreference = 'Stop'
$adb = 'D:\Android-DevTools\sdk\platform-tools\adb.exe'
& $adb -s $Serial get-state
if ($LASTEXITCODE -ne 0) { throw 'Phone is not connected/authorized; connect USB and retry.' }
$routes = & $adb -s $Serial reverse --list
if ($LASTEXITCODE -ne 0) { throw 'Cannot read ADB reverse mappings.' }
$existing = @($routes | Where-Object { $_ -match '\stcp:28469\s' })
if ($existing.Count -eq 0) {
    & $adb -s $Serial reverse --no-rebind tcp:28469 tcp:28469
    if ($LASTEXITCODE -ne 0) { throw 'Cannot create reverse mapping.' }
} elseif ($existing.Count -ne 1 -or $existing[0] -notmatch '\stcp:28469\s+tcp:28469\s*$') {
    throw 'Phone port 28469 already maps elsewhere; not replacing it.'
}
& $adb -s $Serial reverse --list
Write-Output 'USB route ready. No game launch or script injection performed.'
