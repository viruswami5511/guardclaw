# cross_lang_proof/run_proof.ps1
#
# GEF Cross-Language Proof Runner
# Runs Python emitter → Go verifier → prints final verdict.
#
# Usage:
#   cd cross_lang_proof
#   .\run_proof.ps1

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$bar = "=" * 64

Write-Host ""
Write-Host $bar
Write-Host "  GEF Cross-Language Proof Runner"
Write-Host $bar

# ── Step 1: Python emitter ────────────────────────────────────
Write-Host ""
Write-Host "  [1/3] Running Python emitter..."
Write-Host ""

Set-Location $PSScriptRoot
python emit_proof.py
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "  FATAL: Python emitter failed (exit code $LASTEXITCODE)" -ForegroundColor Red
    exit 1
}

# ── Step 2: Go dependencies ───────────────────────────────────
Write-Host ""
Write-Host "  [2/3] Resolving Go dependencies..."
Write-Host ""

go mod tidy
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "  FATAL: go mod tidy failed (exit code $LASTEXITCODE)" -ForegroundColor Red
    Write-Host "  Is Go installed? Run: go version"
    exit 1
}

# ── Step 3: Go verifier ───────────────────────────────────────
Write-Host ""
Write-Host "  [3/3] Running Go verifier..."
Write-Host ""

go run verify_proof.go
$goExitCode = $LASTEXITCODE

# ── Final verdict ─────────────────────────────────────────────
Write-Host ""
Write-Host $bar
if ($goExitCode -eq 0) {
    Write-Host "  VERDICT: ✅  PROOF PASSED — GEF is a protocol." -ForegroundColor Green
} else {
    Write-Host "  VERDICT: ❌  PROOF FAILED — see output above." -ForegroundColor Red
}
Write-Host $bar
Write-Host ""

exit $goExitCode
