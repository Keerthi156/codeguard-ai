$py = ".\.venv\Scripts\python.exe"
$prov = "baseten"
New-Item -ItemType Directory -Force check_logs | Out-Null
$results = @()

function Run($name, $expected, [scriptblock]$cmd, $pattern = $null) {
  $out = & $cmd 2>&1 | Out-String
  $code = $LASTEXITCODE
  $file = "check_logs\" + ($name -replace '[^a-zA-Z0-9]', '_') + ".txt"
  Set-Content -Path $file -Value $out
  $ok = ($code -eq $expected)
  if ($ok -and $pattern) { $ok = ($out -match $pattern) }
  $script:results += [pscustomobject]@{
    Check = $name; Expected = $expected; Got = $code
    Result = $(if ($ok) { "PASS" } else { "FAIL" })
  }
}

function Info($name, [scriptblock]$cmd) {
  $out = & $cmd 2>&1 | Out-String
  $code = $LASTEXITCODE
  $file = "check_logs\" + ($name -replace '[^a-zA-Z0-9]', '_') + ".txt"
  Set-Content -Path $file -Value $out
  $first = ($out -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
  $script:results += [pscustomobject]@{
    Check = $name; Expected = "info"; Got = $code; Result = $first
  }
}

# Unit tests
Run "pytest" 0 { & $py -m pytest -q }

# Demo path: document fixtures
Run "scan fixtures vulnerable" 1 { & $py -m app.cli scan --config fixtures/codeguard.vulnerable.yaml --provider $prov } "Confirmed"
Run "scan fixtures secure" 0 { & $py -m app.cli scan --config fixtures/codeguard.secure.yaml --provider $prov }
Run "regress vs original vulnerable app" 1 { & $py -m app.cli regress --config fixtures/codeguard.vulnerable.yaml } "vulnerable again"
Run "report" 0 { & $py -m app.cli report --config fixtures/codeguard.vulnerable.yaml --out reports/latest.html }

# Benchmark apps (vulnerable must exit 1, secure must exit 0)
foreach ($app in "helper_check", "dependency_check", "uuid_ids", "nested_resource") {
  Run "scan $app vulnerable" 1 { & $py -m app.cli scan --config "benchmarks\$app\vulnerable\codeguard.yaml" --provider $prov } "Confirmed"
  Run "scan $app secure" 0 { & $py -m app.cli scan --config "benchmarks\$app\secure\codeguard.yaml" --provider $prov }
}
Run "uuid_ids DELETE confirmed" 1 { & $py -m app.cli scan --config benchmarks\uuid_ids\vulnerable\codeguard.yaml --provider $prov } "DELETE /documents/\{id\}\s+Confirmed"

# Safety greps (findstr and git grep exit 1 when nothing matches, which is what we want)
Run "no exec/eval in analyzer" 1 { findstr /s /i /n /c:"import_module" /c:"exec(" /c:"eval(" /c:"__import__" app\analyzer\*.py }
Run "no key-shaped strings in tracked files" 1 { git grep -I -n -E "b10_[A-Za-z0-9]{6,}\.[A-Za-z0-9]{20,}|fw_[A-Za-z0-9]{20,}" }
Run ".env is git-ignored" 0 { git check-ignore .env }

# The five AI-written apps that errored: record the first line of each error
foreach ($d in "expenses", "invoices", "notes", "recipes", "support-tickets") {
  Info "AI app scan $d" { & $py -m app.cli scan --config "experiments\ai_written\$d\codeguard.yaml" --provider $prov }
}

Info "git status (should be empty or reports only)" { git status --short }

$results | Format-Table -AutoSize -Wrap
$results | Format-Table -AutoSize -Wrap | Out-String | Set-Content check_logs\summary.txt
Write-Host "Logs are in check_logs\. Paste summary.txt (no keys in it)."
