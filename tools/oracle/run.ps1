# Builds the upstream C oracle if needed, then runs the differential tests
# against it. These tests are `#[ignore]`d so the ordinary suite stays fast and
# free of a C toolchain; this script is the command that actually runs them.
#
# Usage:
#   pwsh -File tools/oracle/run.ps1            # build if missing, then diff
#   pwsh -File tools/oracle/run.ps1 -Rebuild   # always rebuild the oracle first
#
# Exit code is the test result, so a pipeline can gate on it.

[CmdletBinding()]
param(
    [switch] $Rebuild,
    [string] $Filter = ''
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$oracle = Join-Path $PSScriptRoot 'oracle.exe'

if ($Rebuild -or -not (Test-Path $oracle)) {
    Write-Host 'building the upstream oracle...' -ForegroundColor Cyan
    & (Join-Path $PSScriptRoot 'build.ps1')
    if ($LASTEXITCODE -ne 0) {
        throw "the oracle did not build (exit $LASTEXITCODE)"
    }
}
else {
    Write-Host "using the oracle at $oracle" -ForegroundColor Cyan
}

Push-Location $root
try {
    # The differential tests locate the oracle through this variable, so a caller
    # does not have to know where it was built.
    $env:AIRPLAY_UPSTREAM_ORACLE = $oracle
    # `--ignored` runs exactly the differential tests: the vectors in
    # tests/upstream_oracle.rs and the SRP verifier one in src/srp.rs.
    $arguments = @('test', '--workspace', '--all-targets', '--no-fail-fast', '--', '--ignored', '--nocapture')
    if ($Filter) {
        # A filter narrows the ignored set to the tests whose name matches.
        $arguments = @('test', '--workspace', '--all-targets', '--no-fail-fast', $Filter, '--', '--ignored', '--nocapture')
    }
    Write-Host "cargo $($arguments -join ' ') (AIRPLAY_UPSTREAM_ORACLE=$oracle)" -ForegroundColor Cyan
    & cargo @arguments
    $result = $LASTEXITCODE
    if ($result -eq 0) {
        Write-Host 'the port matches the upstream implementation for every vector the oracle prints' -ForegroundColor Green
    }
    else {
        Write-Host 'a differential test failed: the port and upstream disagree' -ForegroundColor Red
    }
    exit $result
}
finally {
    Pop-Location
}
