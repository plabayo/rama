# Windows half of the MITM revocation gate.
#
# Proves the actual customer scenario: cargo on Windows (libcurl + schannel, with
# http.check-revoke on by default) accepts a re-signed leaf, talking through the
# CONNECT proxy to the *real* crates.io. libcurl + schannel ignores stapled OCSP
# and resolves revocation from the cert's own pointers, so the relay re-points the
# leaf's CRL DP / AIA OCSP at a proxy-hosted CA-signed responder. Without it
# schannel fails with CRYPT_E_NO_REVOCATION_CHECK.
#
# Runs all three leaf-revocation modes (crl, ocsp, both) — crates.io's issuer
# advertises both OCSP and a CRL, so each stamps a resolvable pointer schannel
# can follow back to us. The curl/openssl Linux hermetic matrix lives in
# ocsp-relay-gate.sh; this script is cargo-on-Windows only.

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

function Fail($msg) { Write-Error "FAIL: $msg"; exit 1 }

# Trusting the CA requires writing the LocalMachine Root store, which needs
# elevation. Fail fast and clearly when not elevated rather than dying mid-run on
# an access-denied. CI runners are already elevated; run this elevated locally.
$admin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $admin) { Fail "must run elevated (administrator) to trust the MITM CA in LocalMachine\Root" }

cargo build --example mitm_ocsp_relay_gate --features=http-full,boring
if ($LASTEXITCODE -ne 0) { Fail "failed to build the harness" }
$bin = "target\debug\examples\mitm_ocsp_relay_gate.exe"

$work = Join-Path $env:TEMP ("revoc-gate-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $work | Out-Null

# Drive one --leaf-revocation mode: start the relay, trust its (fresh) CA, then
# fetch a real crate through the CONNECT proxy under schannel revocation checking.
# Each mode uses its own CA + CARGO_HOME so the index is genuinely re-fetched.
function Invoke-Variant($variant) {
    $ca = Join-Path $work "ca-$variant.pem"
    $log = Join-Path $work "harness-$variant.log"
    $errlog = Join-Path $work "harness-$variant.err"
    $proc = $null
    $thumb = $null
    try {
        $proc = Start-Process -FilePath $bin `
            -ArgumentList @("--connect", "--leaf-revocation", $variant, "--ca-out", $ca) `
            -RedirectStandardOutput $log -RedirectStandardError $errlog -NoNewWindow -PassThru

        # Wait for "READY proxy=127.0.0.1:PORT ...".
        $addr = $null
        for ($i = 0; $i -lt 100; $i++) {
            if (Test-Path $log) {
                $m = Select-String -Path $log -Pattern '^READY proxy=(\S+) ' | Select-Object -First 1
                if ($m) { $addr = $m.Matches[0].Groups[1].Value; break }
            }
            if ($proc.HasExited) { Get-Content $log -ErrorAction SilentlyContinue; Fail "[$variant] harness exited early" }
            Start-Sleep -Milliseconds 100
        }
        if (-not $addr) { Get-Content $log -ErrorAction SilentlyContinue; Fail "[$variant] harness never became READY" }
        $revoc = $null
        $rm = Select-String -Path $log -Pattern 'revoc=(\S+)' | Select-Object -First 1
        if ($rm) { $revoc = $rm.Matches[0].Groups[1].Value }
        Write-Host "[$variant] proxy=$addr revoc=$revoc -> real crates.io"

        # Diagnostic: prove the loopback responder serves a CRL in user space.
        # schannel fetches this mid-handshake; if even this probe fails, the
        # responder (not schannel) is the problem.
        if ($revoc -and $variant -ne "ocsp") {
            try {
                $crl = Invoke-WebRequest -Uri "http://$revoc/crl" -TimeoutSec 10 -UseBasicParsing
                Write-Host "[$variant] responder /crl reachable: $($crl.RawContentLength) bytes"
            }
            catch {
                Write-Host "[$variant] responder /crl probe FAILED: $($_.Exception.Message)"
            }
        }

        # Trust the MITM CA in the machine Root store; schannel reads it for chain
        # building + revocation. Must be LocalMachine, not CurrentUser: the latter
        # always raises an interactive CryptUI consent dialog that nothing can
        # click in CI, hanging the job. LocalMachine requires elevation and is
        # therefore prompt-free. Captured for cleanup.
        $cert = Import-Certificate -FilePath $ca -CertStoreLocation Cert:\LocalMachine\Root
        $thumb = $cert.Thumbprint

        $proj = Join-Path $work "cargo-probe-$variant"
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

        $env:CARGO_HOME = Join-Path $work "cargo-home-$variant"
        $env:CARGO_HTTP_PROXY = "http://$addr"
        $env:CARGO_HTTP_CHECK_REVOKE = "true" # default on Windows; explicit for clarity
        $env:CARGO_HTTP_TIMEOUT = "25" # fail fast with signal instead of the 60s default
        cargo generate-lockfile --manifest-path (Join-Path $proj "Cargo.toml")
        if ($LASTEXITCODE -ne 0) {
            Write-Host "---- relay stdout ($variant) ----"
            Get-Content $log -ErrorAction SilentlyContinue
            Write-Host "---- relay stderr ($variant) ----"
            Get-Content $errlog -ErrorAction SilentlyContinue
            Fail "[$variant] cargo rejected the crates.io mirror (revocation/trust)"
        }
        if (-not (Select-String -Path (Join-Path $proj "Cargo.lock") -Pattern 'name = "itoa"' -Quiet)) {
            Fail "[$variant] cargo did not resolve itoa through the MITM"
        }
        Write-Host "[$variant] OK - cargo (schannel + check-revoke) resolved revocation via our responder"
    }
    finally {
        if ($thumb) { Remove-Item -Path ("Cert:\LocalMachine\Root\" + $thumb) -ErrorAction SilentlyContinue }
        if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    }
}

try {
    foreach ($variant in @("crl", "ocsp", "both")) { Invoke-Variant $variant }
    Write-Host "MITM REVOCATION GATE (WINDOWS/CARGO) PASSED"
}
finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
