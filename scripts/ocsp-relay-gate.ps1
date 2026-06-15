# Windows half of the MITM OCSP-stapling gate.
#
# Proves the actual customer scenario: cargo on Windows (libcurl + schannel, with
# http.check-revoke on by default) accepts a re-signed leaf that the relay staples,
# talking through the CONNECT proxy to the *real* crates.io. If the staple were
# missing/invalid, schannel would fail with CRYPT_E_NO_REVOCATION_CHECK.
#
# The curl/Linux hermetic matrix + the no-staple negative control live in
# ocsp-relay-gate.sh; this script is cargo-on-Windows only.

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

function Fail($msg) { Write-Error "FAIL: $msg"; exit 1 }

# Trusting the CA requires writing the LocalMachine Root store, which needs
# elevation (see the Import-Certificate note below). Fail fast and clearly when
# not elevated rather than dying mid-run on an access-denied. CI runners are
# already elevated; run this script from an elevated shell locally.
$admin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $admin) { Fail "must run elevated (administrator) to trust the MITM CA in LocalMachine\Root" }

cargo build --example mitm_ocsp_relay_gate --features=http-full,boring
if ($LASTEXITCODE -ne 0) { Fail "failed to build the harness" }
$bin = "target\debug\examples\mitm_ocsp_relay_gate.exe"

$work = Join-Path $env:TEMP ("ocsp-gate-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $work | Out-Null
$ca = Join-Path $work "ca.pem"
$log = Join-Path $work "harness.log"

$proc = $null
$thumb = $null
try {
    $proc = Start-Process -FilePath $bin -ArgumentList @("--connect", "--ca-out", $ca) `
        -RedirectStandardOutput $log -NoNewWindow -PassThru

    # Wait for "READY proxy=127.0.0.1:PORT ...".
    $addr = $null
    for ($i = 0; $i -lt 100; $i++) {
        if (Test-Path $log) {
            $m = Select-String -Path $log -Pattern '^READY proxy=(\S+) ' | Select-Object -First 1
            if ($m) { $addr = $m.Matches[0].Groups[1].Value; break }
        }
        if ($proc.HasExited) { Get-Content $log -ErrorAction SilentlyContinue; Fail "harness exited early" }
        Start-Sleep -Milliseconds 100
    }
    if (-not $addr) { Get-Content $log -ErrorAction SilentlyContinue; Fail "harness never became READY" }
    Write-Host "[connect] proxy=$addr -> real crates.io"

    # Trust the MITM CA in the machine Root store; schannel reads it for chain
    # building + revocation. Must be LocalMachine, not CurrentUser: adding to the
    # CurrentUser Root store always raises an interactive "Security Warning"
    # consent dialog (CryptUI) that nothing can click in CI, hanging the job.
    # LocalMachine requires elevation and is therefore prompt-free. Captured for
    # cleanup.
    $cert = Import-Certificate -FilePath $ca -CertStoreLocation Cert:\LocalMachine\Root
    $thumb = $cert.Thumbprint

    # A real crate resolved through the MITM. Windows enforces revocation by
    # default, so this only succeeds if our staple is good.
    $proj = Join-Path $work "cargo-probe"
    New-Item -ItemType Directory -Force -Path (Join-Path $proj "src") | Out-Null
    Set-Content -Path (Join-Path $proj "src\lib.rs") -Value ""
    @"
[package]
name = "gate-probe"
version = "0.0.0"
edition = "2021"

[dependencies]
itoa = "1"
"@ | Set-Content -Path (Join-Path $proj "Cargo.toml")

    $env:CARGO_HOME = Join-Path $work "cargo-home"
    $env:CARGO_HTTP_PROXY = "http://$addr"
    $env:CARGO_HTTP_CHECK_REVOKE = "true" # default on Windows; explicit for clarity
    cargo generate-lockfile --manifest-path (Join-Path $proj "Cargo.toml")
    if ($LASTEXITCODE -ne 0) { Fail "cargo rejected the stapled crates.io mirror (revocation/trust)" }
    if (-not (Select-String -Path (Join-Path $proj "Cargo.lock") -Pattern 'name = "itoa"' -Quiet)) {
        Fail "cargo did not resolve itoa through the MITM"
    }

    Write-Host "[connect] OK - cargo (schannel + check-revoke) trusts the stapled crates.io mirror"
    Write-Host "OCSP RELAY GATE (WINDOWS/CARGO) PASSED"
}
finally {
    if ($thumb) { Remove-Item -Path ("Cert:\LocalMachine\Root\" + $thumb) -ErrorAction SilentlyContinue }
    if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
