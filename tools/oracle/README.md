# The differential oracle

A small C program that links upstream sources and prints their intermediate values, so this
implementation can be compared with the code it follows instead of with a description of it.

## Building it

It needs a UxPlay checkout at commit `517cbb1240d9b9f69330c55b957cdd52b4175b2a` in
`upstream/UxPlay`, and MSYS2 UCRT64:

```powershell
pwsh -File tools/oracle/build.ps1
```

The sources it compiles are listed in `build.ps1`. Nothing from that list is linked into the
Rust product; the oracle exists only to print values for the tests to compare against.

## Running it

```powershell
pwsh -File tools/oracle/run.ps1            # build if missing, then diff
pwsh -File tools/oracle/run.ps1 -Rebuild   # rebuild first
```

The exit code is the test result, so a pipeline can gate on it. It is equivalent to setting
`AIRPLAY_UPSTREAM_ORACLE` to the built executable and running the ignored test:

```powershell
$env:AIRPLAY_UPSTREAM_ORACLE = "$PWD/tools/oracle/oracle.exe"
cargo test -p rust-airplay --test upstream_oracle -- --ignored
```

## What it prints

| Mode | Values |
| --- | --- |
| `srp` | SRP-6a intermediate values |
| `pairing` | the `/pair-verify` and `/pair-setup` vectors |
| `fairplay` | the FairPlay transforms |
| `mirror` | where the mirror decryptor takes its keystream from, packet by packet, and the counter value at a given block |

The mirror mode is the one to reach for when a picture is wrong. It prints the counter and
the position the decryptor reads from, so a disagreement says which of the two rules is
wrong, rather than only that the output differs.

Chinese: [README.zh-CN.md](README.zh-CN.md).