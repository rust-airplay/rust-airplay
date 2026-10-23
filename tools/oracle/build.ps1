#!/usr/bin/env pwsh
# Builds the upstream differential oracle with the MSYS2/UCRT64 toolchain.
#
# The oracle compiles upstream C sources into one test binary; it is never part
# of the Rust product. Run it, then check the port against its vectors with:
#   $env:AIRPLAY_UPSTREAM_ORACLE = "$PWD/tools/oracle/oracle.exe"
#   cargo test -p airplay-core --test upstream_oracle -- --ignored --nocapture
[CmdletBinding()]
param(
    [string]$Upstream = (Join-Path $PSScriptRoot '..\..\upstream\UxPlay'),
    [string]$Msys = 'C:\msys64\ucrt64'
)

$ErrorActionPreference = 'Stop'
$lib = Join-Path $Upstream 'lib'
if (-not (Test-Path (Join-Path $lib 'srp.c'))) {
    throw "upstream sources not found under $lib (clone FDH2/UxPlay there first)"
}

$sources = @(
    (Join-Path $PSScriptRoot 'oracle.c'),
    (Join-Path $lib 'srp.c'),
    (Join-Path $lib 'crypto.c'),
    (Join-Path $lib 'pairing.c'),
    (Join-Path $lib 'utils.c'),
    (Join-Path $lib 'logger.c'),
    (Join-Path $lib 'compat.c'),
    (Join-Path $lib 'mirror_buffer.c'),
    (Join-Path $lib 'fairplay_playfair.c'),
    (Join-Path $lib 'playfair/hand_garble.c'),
    (Join-Path $lib 'playfair/modified_md5.c'),
    (Join-Path $lib 'playfair/omg_hax.c'),
    (Join-Path $lib 'playfair/playfair.c'),
    (Join-Path $lib 'playfair/sap_hash.c')
)

$output = Join-Path $PSScriptRoot 'oracle.exe'
$gcc = Join-Path $Msys 'bin\gcc.exe'
# -DWIN32 selects the Windows branches of upstream's compatibility code: its
# POSIX branch reads /dev/urandom, which does not exist here and would crash the
# oracle the first time it needs randomness of its own.
& $gcc -O1 -g -std=gnu11 -DWIN32 -o $output `
    -I $lib -I (Join-Path $lib 'playfair') -I (Join-Path $Msys 'include') `
    $sources `
    -L (Join-Path $Msys 'lib') -lcrypto -ladvapi32
if ($LASTEXITCODE -ne 0) {
    throw "oracle build failed with $LASTEXITCODE"
}
Write-Output "built $output"
