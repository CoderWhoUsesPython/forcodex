$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
Get-CimInstance Win32_OperatingSystem |
  Select-Object Caption, Version, BuildNumber, OSArchitecture |
  ConvertTo-Json | Set-Content out/windows.json
Get-CimInstance Win32_Processor |
  Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors |
  ConvertTo-Json | Set-Content out/cpu.json
Push-Location out
try {
  foreach ($name in @('accuracy', 'context-O0', 'context-O2', 'cpu-state', 'pool-tags')) {
    & ".\$name.exe" 2>&1 | Tee-Object "$name.log"
    $code = $LASTEXITCODE
    "$name=$code" | Add-Content exit-codes.txt
  }
} finally {
  Pop-Location
}
# Baseline discrepancies are observations, not infrastructure failures.
exit 0
