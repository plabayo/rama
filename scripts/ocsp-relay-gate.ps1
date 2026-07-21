# Windows half of the MITM revocation gate.
#
# Two legs:
# - HERMETIC (must-pass): for each leaf-revocation mode, start the relay against
#   a local upstream that advertises the matching revocation source, harvest the
#   re-signed leaf via openssl s_client, then run `certutil -verify -urlfetch` —
#   which forces schannel/crypt32 to fetch revocation from the embedded loopback
#   CDP/AIA, the exact code path libcurl+schannel takes for cargo. No internet.
# - CARGO END-TO-END (best-effort): drive cargo through the relay to real
#   crates.io. Useful as a real-world soak test when the runner network is
#   healthy; soft-skipped when it isn't, so unrelated network flakes (DNS,
#   AAAA/IPv6 timeouts, throttling, CDN slowness) don't fail the PR.
#
# The Linux openssl/curl matrix (incl. revoked-serial control and OCSP POST/GET)
# lives in ocsp-relay-gate.sh.

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

function Fail($msg) { Write-Error "FAIL: $msg"; exit 1 }

function Dump-HarnessLogs($variant, $proc, $log, $errlog) {
    $code = if ($proc -and $proc.HasExited) { $proc.ExitCode } else { "running" }
    Write-Host "---- harness ($variant) exit=$code ----"
    Write-Host "---- harness ($variant) stdout ($log) ----"
    if (Test-Path $log) { Get-Content $log | ForEach-Object { Write-Host $_ } } else { Write-Host "(no stdout file)" }
    Write-Host "---- harness ($variant) stderr ($errlog) ----"
    if (Test-Path $errlog) { Get-Content $errlog | ForEach-Object { Write-Host $_ } } else { Write-Host "(no stderr file)" }
    Write-Host "---- end harness ($variant) logs ----"
}

# Wait for the harness to print "READY proxy=127.0.0.1:PORT ..." or die.
function Wait-Ready($proc, $log, $errlog, $label) {
    for ($i = 0; $i -lt 100; $i++) {
        if (Test-Path $log) {
            $m = Select-String -Path $log -Pattern '^READY proxy=(\S+) ' | Select-Object -First 1
            if ($m) { return $m.Matches[0].Groups[1].Value }
        }
        if ($proc.HasExited) { Dump-HarnessLogs $label $proc $log $errlog; throw "[$label] harness exited early" }
        Start-Sleep -Milliseconds 100
    }
    Dump-HarnessLogs $label $proc $log $errlog
    throw "[$label] harness never became READY"
}

# Trusting the CA requires writing the LocalMachine Root store, which needs
# elevation. Fail fast and clearly rather than dying mid-run on access-denied.
# CI runners are already elevated; run elevated locally.
$admin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $admin) { Fail "must run elevated (administrator) to trust the MITM CA in LocalMachine\Root" }

# Locate an openssl binary (Git for Windows ships one).
$openssl = $null
foreach ($p in @("C:\Program Files\Git\usr\bin\openssl.exe",
        "C:\Program Files\Git\mingw64\bin\openssl.exe")) {
    if (Test-Path $p) { $openssl = $p; break }
}
if (-not $openssl) {
    $cmd = Get-Command openssl.exe -ErrorAction SilentlyContinue
    if ($cmd) { $openssl = $cmd.Source }
}
if (-not $openssl) { Fail "openssl.exe not found (looked under Git for Windows + PATH)" }
Write-Host "openssl: $openssl"

cargo build -p rama-examples --bin mitm_ocsp_relay_gate --features=http-full,boring
if ($LASTEXITCODE -ne 0) { Fail "failed to build the harness" }
$bin = "target\debug\mitm_ocsp_relay_gate.exe"

$work = Join-Path $env:TEMP ("revoc-gate-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $work | Out-Null

# An empty file used as stdin for openssl s_client so it exits on EOF instead of
# waiting for interactive input.
$nullin = Join-Path $work "nullin.txt"
Set-Content -Path $nullin -Value ""

# Drive one leaf-revocation mode against a local upstream and prove schannel
# accepts the re-signed leaf, with revocation fetched from our loopback
# responder. No internet, no cargo — `certutil -verify -urlfetch` exercises the
# same crypt32 path libcurl+schannel uses inside cargo.
function Invoke-Hermetic-Variant($variant) {
    $label = "h-$variant"
    $ca = Join-Path $work "ca-$label.pem"
    $log = Join-Path $work "harness-$label.log"
    $errlog = Join-Path $work "harness-$label.err"
    $proc = $null
    $thumb = $null
    try {
        # The local upstream must advertise the source matching the leaf
        # variant, else the mirror gate strips it and no pointer is stamped.
        $up = if ($variant -eq "ocsp") { "ocsp" } else { "crl" }
        $procArgs = @("--upstream-revocation", $up, "--leaf-revocation", $variant, "--ca-out", $ca)
        $proc = Start-Process -FilePath $bin -ArgumentList $procArgs `
            -RedirectStandardOutput $log -RedirectStandardError $errlog -NoNewWindow -PassThru

        $addr = Wait-Ready $proc $log $errlog $label
        $port = $addr.Split(':')[-1]
        Write-Host "[$label] proxy=$addr (hermetic)"

        $cert = Import-Certificate -FilePath $ca -CertStoreLocation Cert:\LocalMachine\Root
        $thumb = $cert.Thumbprint

        # Clear any cached revocation from a prior run so the fetch is real.
        & certutil -urlcache "*" delete 2>$null | Out-Null

        # Harvest the mirrored leaf via openssl s_client → write as DER for certutil.
        $sclientOut = Join-Path $work "sclient-$label.txt"
        $leafCer = Join-Path $work "leaf-$label.cer"
        $sp = Start-Process -FilePath $openssl `
            -ArgumentList @("s_client", "-connect", "127.0.0.1:$port", "-servername", "upstream.example") `
            -RedirectStandardInput $nullin -RedirectStandardOutput $sclientOut `
            -RedirectStandardError ($sclientOut + ".err") -NoNewWindow -Wait -PassThru
        if (-not (Test-Path $sclientOut)) {
            Dump-HarnessLogs $label $proc $log $errlog
            throw "[$label] openssl s_client produced no output (exit=$($sp.ExitCode))"
        }
        & $openssl x509 -in $sclientOut -outform DER -out $leafCer 2>$null
        if (-not (Test-Path $leafCer) -or (Get-Item $leafCer).Length -eq 0) {
            Write-Host "---- openssl s_client output ($label) ----"
            Get-Content $sclientOut | ForEach-Object { Write-Host $_ }
            Dump-HarnessLogs $label $proc $log $errlog
            throw "[$label] could not parse the mirrored leaf from s_client output"
        }

        # certutil -verify -urlfetch forces schannel/crypt32 to fetch revocation
        # from the embedded loopback CDP/AIA — the same path cargo+schannel uses.
        # We require exit 0 *and* a "Revocation check" line that doesn't read
        # "unable to download" / "offline", so a silent failure can't pass.
        $cuOut = & certutil -verify -urlfetch $leafCer 2>&1
        $cuExit = $LASTEXITCODE
        $cuText = ($cuOut | Out-String)
        $checkedRev = $cuText -match 'Revocation check'
        $offline = $cuText -match 'CRYPT_E_NO_REVOCATION_CHECK|CRYPT_E_REVOCATION_OFFLINE|unable to download'
        if ($cuExit -ne 0 -or -not $checkedRev -or $offline) {
            Write-Host "---- certutil output ($label) ----"
            $cuOut | ForEach-Object { Write-Host $_ }
            Dump-HarnessLogs $label $proc $log $errlog
            throw "[$label] certutil rejected or could not fetch revocation (exit=$cuExit)"
        }
        Write-Host "[$label] OK - schannel/crypt32 accepted the leaf via loopback revocation"
    }
    finally {
        if ($thumb) { Remove-Item -Path ("Cert:\LocalMachine\Root\" + $thumb) -ErrorAction SilentlyContinue }
        if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    }
}

# Cargo end-to-end through the relay to *real* crates.io. Best-effort: this
# leg depends on the runner's outbound TCP to Fastly, IPv6/happy-eyeballs
# behaviour, and crates.io reachability, so a failure here is treated as a
# warning rather than a hard fail.
function Invoke-Cargo-Variant($variant) {
    $ca = Join-Path $work "ca-cargo-$variant.pem"
    $log = Join-Path $work "harness-cargo-$variant.log"
    $errlog = Join-Path $work "harness-cargo-$variant.err"
    $proc = $null
    $thumb = $null
    try {
        $proc = Start-Process -FilePath $bin `
            -ArgumentList @("--connect", "--leaf-revocation", $variant, "--ca-out", $ca) `
            -RedirectStandardOutput $log -RedirectStandardError $errlog -NoNewWindow -PassThru

        $addr = Wait-Ready $proc $log $errlog $variant
        $revoc = $null
        $rm = Select-String -Path $log -Pattern 'revoc=(\S+)' | Select-Object -First 1
        if ($rm) { $revoc = $rm.Matches[0].Groups[1].Value }
        Write-Host "[$variant] proxy=$addr revoc=$revoc -> real crates.io (best-effort)"

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
        $env:CARGO_HTTP_CHECK_REVOKE = "true"
        $env:CARGO_HTTP_TIMEOUT = "60"
        $env:CARGO_NET_RETRY = "3"
        cargo generate-lockfile --manifest-path (Join-Path $proj "Cargo.toml")
        if ($LASTEXITCODE -ne 0) {
            Dump-HarnessLogs $variant $proc $log $errlog
            throw "[$variant] cargo failed (network or revocation; treated as best-effort)"
        }
        if (-not (Select-String -Path (Join-Path $proj "Cargo.lock") -Pattern 'name = "itoa"' -Quiet)) {
            throw "[$variant] cargo did not resolve itoa through the MITM"
        }
        Write-Host "[$variant] OK - cargo (schannel + check-revoke) resolved revocation via our responder"
    }
    finally {
        if ($thumb) { Remove-Item -Path ("Cert:\LocalMachine\Root\" + $thumb) -ErrorAction SilentlyContinue }
        if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    }
}

try {
    # Hermetic legs — must pass.
    foreach ($variant in @("crl", "ocsp", "both")) { Invoke-Hermetic-Variant $variant }

    # Cargo legs — best-effort. Probe crates.io first; skip if unreachable.
    $networkOK = $false
    try {
        Invoke-WebRequest -Uri "https://index.crates.io/config.json" -TimeoutSec 15 -UseBasicParsing | Out-Null
        $networkOK = $true
    }
    catch {
        Write-Host "Cargo legs SKIPPED: network probe to crates.io failed: $($_.Exception.Message)"
    }
    if ($networkOK) {
        foreach ($variant in @("crl", "ocsp", "both")) {
            try { Invoke-Cargo-Variant $variant }
            catch { Write-Host "WARN [$variant] cargo leg SOFT-FAIL (best-effort): $_" }
        }
    }

    Write-Host "MITM REVOCATION GATE (WINDOWS) PASSED"
}
finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
