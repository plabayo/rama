# Transparent Proxy (MacOS) Example

This example shows how to link a Rust staticlib that implements the
Rama NetworkExtension C ABI into a macOS Transparent Proxy extension.

The sysext generates and stores the demo MITM root CA in the macOS System
Keychain (`/Library/Keychains/System.keychain`) using Rama's built-in boring TLS
support. The CA is created on first startup and reused on subsequent starts.

The container app can delete the stored CA material via the `Clear CA` menu
command (while the proxy is running) or the `--clean-secrets` launch flag; the
sysext then creates a fresh CA the next time it initialises. The container app
does not create or read the CA.

## Build

```sh
cd ffi/apple/examples/transparent_proxy
just build-tproxy-dev
```

This builds the Rust staticlib and the developer-signed macOS container app + system extension.
The Rust staticlib is produced at:

```
ffi/apple/examples/transparent_proxy/tproxy_rs/target/universal/librama_tproxy_example.a
```

## Xcode

`/RamaTransparentProxyExample.xcodeproj` is generated using `xcodegen generate`.

This example supports two modes:

- Developer mode: system extension packaging with `Apple Development` signing. This is the default path and is intended for normal developers working locally.
- Distribution mode: system extension packaging with `Developer ID` signing. This is the direct-distribution path an admin or release process uses.

Default local developer commands:

```sh
cd ffi/apple/examples/transparent_proxy
just install-tproxy-dev-reset-profile
```

Developer ID distribution commands:

```sh
cd ffi/apple/examples/transparent_proxy
just install-tproxy-dist-reset-profile
```

That distribution command now performs the full shipping flow: build, sign, notarize, staple, install, then launch.
Before replacing the installed app, the install helper uninstalls both the developer and distribution system-extension bundle IDs first, so switching between Apple Development and Developer ID signing does not leave the old extension active.

Developer mode uses the default Xcode spec at [Project.yml](./tproxy_app/Project.yml).
Developer ID distribution mode uses [Project.dist.yml](./tproxy_app/Project.dist.yml).
The example now follows a Proton-style layout: one transparent proxy system-extension implementation is shared by both modes, and the entitlement difference is controlled by `NE_ENTITLEMENT_SUFFIX` in the Xcode spec. To avoid local code-signature collisions when switching between Apple Development and Developer ID on the same Mac, the developer and distribution modes use different bundle IDs.
The build helpers are:

- [build_tproxy_app_with_signing.sh](./scripts/build_tproxy_app_with_signing.sh) for developer mode
- [build_tproxy_app_with_developer_id_signing.sh](./scripts/build_tproxy_app_with_developer_id_signing.sh) for the raw Developer ID signed build
- [notarize_tproxy_app_with_developer_id_signing.sh](./scripts/notarize_tproxy_app_with_developer_id_signing.sh) for the full Developer ID distribution flow

Both modes use the real system-extension product type. Developer mode uses the plain `app-proxy-provider` entitlement payload, while distribution mode switches the same entitlement template to `app-proxy-provider-systemextension`.

At runtime, the container app menu includes `Rotate CA` — which mints a fresh
CA and swaps it in live over XPC without restarting the proxy (falling back to
wiping the stored blobs, so the next start regenerates, when the proxy is
inactive) — and `Clear CA`, which uninstalls trust and wipes the stored CA
material so the sysext regenerates a fresh CA on its next startup.

## Signing Setup

Apple docs relevant to this demo:

- System extensions overview: https://developer.apple.com/system-extensions/
- Enable app capabilities: https://developer.apple.com/help/account/identifiers/enable-app-capabilities/
- Supported macOS capabilities: https://developer.apple.com/help/account/reference/supported-capabilities-macos/
- Create a development provisioning profile: https://developer.apple.com/help/account/provisioning-profiles/create-a-development-provisioning-profile/
- Apple Developer account roles: https://developer.apple.com/help/account/access/roles/
- Developer ID certificates: https://developer.apple.com/help/account/certificates/create-developer-id-certificates

### Capability Model

This demo uses two different Apple capability/signing models.

Developer mode:

- packaging: system extension (`.systemextension`)
- signing: `Apple Development` with Xcode automatic signing
- Network Extension entitlement payload: `app-proxy-provider`
- intended for local developer builds without requiring Developer ID distribution access

Distribution mode:

- packaging: system extension (`.systemextension`)
- signing: `Developer ID`
- Network Extension sysext entitlement payload: `app-proxy-provider-systemextension`
- container app also carries `com.apple.developer.system-extension.install`
- intended for direct distribution outside the Mac App Store

For the App IDs, the practical setup is:

- developer container App ID: enable `Network Extensions` and `System Extension`
- developer sysext App ID: enable `Network Extensions`
- distribution container App ID: enable `Network Extensions` and `System Extension`
- distribution sysext App ID: enable `Network Extensions`

The container app and sysext now share one entitlement template each, with the Network Extension sysext payload switched by `NE_ENTITLEMENT_SUFFIX`:

- developer mode uses `NE_ENTITLEMENT_SUFFIX = ""`
- distribution mode uses `NE_ENTITLEMENT_SUFFIX = "-systemextension"`

### What an admin needs to create

A team `Account Holder` or `Admin` needs to do the one-time Apple Developer portal setup.

1. Create or verify the four App IDs:
   - `org.ramaproxy.example.tproxy.dev`
   - `org.ramaproxy.example.tproxy.dev.provider`
   - `org.ramaproxy.example.tproxy.dist`
   - `org.ramaproxy.example.tproxy.dist.provider`
2. Enable `Network Extensions` on the container app' and sysext App IDs for both developer and distribution modes.
3. Enable `System Extension` on the container app's App ID used for direct distribution.
4. Register the shared app-group identifiers. The entitlement value is
   `$(APP_GROUP_ID)` = `$(AppIdentifierPrefix)` + the bundle base, i.e. prefixed
   with your `<TEAMID>`:
   - `<TEAMID>.org.ramaproxy.example.tproxy.dev`
   - `<TEAMID>.org.ramaproxy.example.tproxy.dist`

   The group is reused as the `NEMachServiceName` prefix; it is not an app-group
   keychain — the CA material lives in the file-based System Keychain.
5. Enable the App Groups capability for the container app and sysext App IDs.
6. Create the Developer ID distribution profiles for the direct-distribution container app and sysext.

### What a normal developer needs locally

A normal developer should use developer mode.

1. Sign in to Xcode with the team account.
2. Let Xcode manage the developer's own `Apple Development` certificate and automatic signing state.
3. Use the developer-mode command:

```sh
just install-tproxy-dev-reset-profile
```

This mode is designed to work for developers who do not have admin-level access to create or distribute `Developer ID` identities. No explicit provisioning-profile selection is documented for this mode. It uses the developer-only bundle IDs `org.ramaproxy.example.tproxy.dev` and `org.ramaproxy.example.tproxy.dev.provider`.

### What an admin or release engineer uses

For the real direct-distribution system extension path, use Developer ID mode. This helper builds the Xcode project in `Release`, lets Xcode perform the final signing pass with hardened runtime and secure timestamps, notarizes the built app, staples the result, and only then installs it:

```sh
just install-tproxy-dist-reset-profile
```

After launch, the app may report that system extension approval is required. The most reliable place to find the approval UI is:

- `System Settings` -> `General` -> `Login Items & Extensions` -> `Network Extensions`

A useful diagnostic command is:

```sh
systemextensionsctl list
```

When approval is pending, macOS prints a hint like:

```text
Go to "System Settings > General > Login Items & Extensions > Network Extensions" to modify these system extension(s)
```

If you only want the signed `Release` app without notarization, use:

```sh
just build-tproxy-dist
```

For distribution mode, the example expects these Developer ID profile names for the distribution bundle IDs `org.ramaproxy.example.tproxy.dist` and `org.ramaproxy.example.tproxy.dist.provider`:

- `Rama Transparent Proxy Example (Host)` (the container app)
- `Rama Transparent Proxy Example (Extension)`

Only for distribution mode, if you intentionally renamed those profiles, should you override:

- `RAMA_TPROXY_CONTAINER_PROFILE_SPECIFIER`
- `RAMA_TPROXY_EXTENSION_PROFILE_SPECIFIER`

If Xcode still fails to find the freshly downloaded Developer ID profiles, you can point the helper at the exact files and let it install them into the standard provisioning-profile directory before building:

- `RAMA_TPROXY_CONTAINER_PROFILE_PATH=/absolute/path/to/Rama_Transparent_Proxy_Example_Container.provisionprofile`
- `RAMA_TPROXY_EXTENSION_PROFILE_PATH=/absolute/path/to/Rama_Transparent_Proxy_Example_Extension.provisionprofile`

Distribution mode also requires a locally available `Developer ID Application` certificate with private key for team `ADPG6C355H`, unless your company uses an equivalent managed-signing service.

It also requires notarization credentials for `notarytool`. Recommended setup:

```sh
xcrun notarytool store-credentials rama-tproxy-notary \
  --apple-id <apple-id> \
  --team-id ADPG6C355H \
  --password <app-specific-password>

export RAMA_TPROXY_NOTARY_KEYCHAIN_PROFILE=rama-tproxy-notary
```

The distribution helper also supports direct environment variables instead of a stored keychain profile:

- `RAMA_TPROXY_NOTARY_APPLE_ID`
- `RAMA_TPROXY_NOTARY_PASSWORD`

### How an admin creates the Developer ID certificate

An Apple Developer `Account Holder` or `Admin` can create the distribution signing certificate using Apple's official Developer ID flow:

- Apple doc: https://developer.apple.com/help/account/certificates/create-developer-id-certificates

The practical steps are:

1. On macOS, prefer generating the Certificate Signing Request (CSR) from `Keychain Access`, not OpenSSL.
   This is the recommended path for this example because the private key stays in the login keychain and the issued certificate can pair with it automatically.
2. In `Keychain Access`, use:
   `Keychain Access` -> `Certificate Assistant` -> `Request a Certificate From a Certificate Authority...`
3. Enter the Apple Developer account email address, choose `Saved to disk`, and generate the CSR on the machine that should hold the private key.
4. Open `Certificates, Identifiers & Profiles` in Apple Developer.
5. Go to `Certificates`.
6. Create a new `Developer ID Application` certificate using that CSR.
7. Download the issued certificate from Apple and open it on the same machine that generated the CSR. Keychain Access should pair it with the private key automatically.
8. If another machine needs to sign, export that identity as a `.p12` from Keychain Access and import it into the login keychain on the signing machine.

Important: Apple lets you download the certificate again later, but not the private key. A usable `.p12` can only be exported from a keychain that already contains both the certificate and its private key.

An OpenSSL-based CSR is possible, but it is easier to end up with a `.crt`/`.cer` file that is not attached to a keychain private key. For this macOS example, Keychain Access is the safer default.

To verify the certificate is available locally:

```sh
security find-identity -p codesigning -v | grep -E 'Developer ID Application|ADPG6C355H'
```

If that command shows no matching identity, Xcode will not be able to perform the Developer ID distribution build.

### Cloud Signing

Teams do not have to distribute the `Developer ID Application` private key to every developer machine. A common alternative is cloud signing or another managed-signing workflow. In that model:

- developers use the normal developer mode locally
- CI or a managed signing service performs the Developer ID signing
- the private key stays in restricted infrastructure rather than being copied to all laptops

This example does not implement a specific cloud-signing provider, but the distribution mode is compatible with that workflow: the important requirement is that the final distribution build is signed with the correct `Developer ID Application` identity and the matching distribution provisioning profiles.

### Why the split exists

A non-admin developer cannot usually rely on self-service `Developer ID` signing the way they can rely on `Apple Development` signing in Xcode.

So this example deliberately demonstrates both:

- the local-developer workflow companies need for day-to-day development
- the Developer ID system-extension workflow companies need for shipping a directly distributed macOS L4 proxy

## Logs

Check the extension is registered, then stream Rama and NetworkExtension
events. Use `--level debug` for `log stream`; `log show` has separate
`--info --debug` output flags and otherwise returns default-level events only.

```sh
systemextensionsctl list
log stream --level debug --style compact \
  --predicate 'subsystem BEGINSWITH "org.ramaproxy.example.tproxy" OR process == "neagent" OR process == "nesessionmanager" OR process == "sysextd" OR process == "launchd"'

log show --last 5m --style compact --info --debug \
  --predicate 'subsystem BEGINSWITH "org.ramaproxy.example.tproxy" OR process == "neagent" OR process == "nesessionmanager" OR process == "sysextd" OR process == "launchd"'
```

`--info` and `--debug` only select events that macOS retained; they do not
retroactively persist debug events. For a planned reproduction, keep
`log stream --level debug` running. To make a later replay self-contained,
temporarily enable debug persistence and reset it after the reproduction:
The subsystem below is the development provider bundle identifier; substitute
the installed provider identifier for another build flavor.

```sh
sudo log config --subsystem org.ramaproxy.example.tproxy.dev.provider \
  --mode level:debug,persist:debug
# reproduce, then export with `log show --info --debug` or `log collect`
sudo log config --subsystem org.ramaproxy.example.tproxy.dev.provider --reset
```

Private metadata remains `<private>` by design; `sudo` does not turn a
redacted field public. Lifecycle text, counters, and other support-critical
summaries are emitted separately as public fields. Rust `tracing` events
share the same subsystem — see
[Observability with dial9](#observability-with-dial9).

The example exports its own and the Apple bridge's debug events, while other
Rama targets default to info to avoid per-chunk protocol noise. WebSocket
payloads are never logged; process arguments are included only as private
demo metadata. Per-message WebSocket events are trace-level and therefore
omitted from this debug stream.

## Troubleshooting

`NEVPNConnectionErrorDomainPlugin code=6` is usually a follow-up to either
stale registration or a previous provider crash, not the root cause. A
"works after reinstall" outcome only proves the registration/profile
layer was reset — it does *not* prove the original runtime bug is fixed.

### Decision tree

1. `systemextensionsctl list | grep 'org\.ramaproxy\.example\.tproxy'`
   — if nothing is registered or the state is not `[activated enabled]`,
   run `just install-tproxy-dev` and approve in System Settings.
2. Replay logs (`log show --last 5m ...`, see commands below) and
   inspect for these patterns:
   - `code=7`, `Plugin failed`, `Plugin was disabled`: provider crashed
     — check `/Library/Logs/DiagnosticReports/` for a fresh `.ips`.
   - `failed activation: error = 1: Operation not permitted` on the XPC
     service: launchd rejected the Mach service registration. Run
     `just install-tproxy-dev-reset-profile` to force `sysextd` to
     regenerate the launchd job from `Info.plist`'s `NEMachServiceName`,
     then verify `MachServices` is present (commands below).
   - `Found 0 extension(s) with identifier ...`: registration missing,
     reinstall.
3. Only when registration is fine *and* the saved
   `NETransparentProxyManager` profile is stale (or you changed
   entitlements / Info.plist keys read at install time): run
   `just install-tproxy-dev-reset-profile`.

### Useful commands

```sh
# Logs for the extension + NE daemons
log show --last 5m --style compact --info --debug \
  --predicate 'subsystem BEGINSWITH "org.ramaproxy.example.tproxy" OR process == "neagent" OR process == "nesessionmanager" OR process == "sysextd"'

# Recent provider crash reports (system-level, NOT ~/Library/...)
ls -lt /Library/Logs/DiagnosticReports/ \
  | grep 'org\.ramaproxy\.example\.tproxy\.dev\.provider' | head -5

# launchd job's MachServices block — should list the NEMachServiceName,
# i.e. <TEAM>.org.ramaproxy.example.tproxy.dev.provider.<version> => 0
sudo launchctl print system/org.ramaproxy.example.tproxy.dev.provider \
  | grep -A 5 -i machservices

# Installed-binary entitlements + Info.plist (rules out signing / plist drift)
codesign -d --entitlements - \
  /Library/SystemExtensions/*/org.ramaproxy.example.tproxy.dev.provider \
  2>&1 | grep -A2 -E 'mach-register|NEMach|networkextension'
plutil -p /Library/SystemExtensions/*/\
org.ramaproxy.example.tproxy.dev.provider.systemextension/Contents/Info.plist \
  | grep -E 'NEMach|TProxy|XpcService|BundleVersion'
```

### Wire capture (for diagnosing TLS / handshake issues)

`tcpdump` on `en0` captures the **egress** side (provider →
upstream). The **ingress** side (browser → provider) lives in
the kernel's NECP pipe — no interface, not visible to
`tcpdump`. Egress is usually enough to spot a malformed
ClientHello, missing SNI, wrong ALPN, or an upstream alert.

```sh
sudo tcpdump -i en0 -s 0 -C 100 -W 5 -w /tmp/rama-tproxy.pcap
```

To decrypt the egress TLS in Wireshark, enable the `Log TLS Session Keys`
menu toggle (a runtime XPC command). The sysext then writes NSS-format key-log
lines to `<storage_dir>/keylog/sslkeylog*`; point Wireshark's TLS dissector at
that file and the egress handshake becomes plaintext.

### Reinstall recipes

- `just install-tproxy-dev` — rebuilds + reinstalls everything, leaves
  the saved `NETransparentProxyManager` profile in place. Fixes stale
  registration.
- `just install-tproxy-dev-reset-profile` — same, plus launches with
  `--reset-profile-on-launch` so the saved profile is recreated and
  `sysextd` re-reads `Info.plist`. Required when changing
  `NEMachServiceName`, entitlements, or other install-time keys.

### Diagnosing sleep/wake connectivity loss

Symptom: after the machine sleeps and wakes, internet stops — apps hang,
nothing loads — and it stays broken until the proxy is restarted. The
provider is still alive (same PID) and still *intercepts* flows; the
egress side just carries no data.

Reproduce deterministically (locks the screen for ~100s — detach the
Xcode debugger first, an attached debugger keeps the machine awake):

```sh
for i in $(seq 1 20); do
  echo "===== cycle $i — $(date) ====="
  sudo pmset schedule wakeorpoweron "$(date -v+60S '+%m/%d/%y %H:%M:%S')"
  sudo pmset sleepnow
  # script resumes on wake; fire fresh flows to two destinations
  sleep 1
  curl -sS -o /dev/null --max-time 5 -w 'curl1 %{http_code} t=%{time_total}\n' https://example.com/ &
  curl -sS -o /dev/null --max-time 5 -w 'curl2 %{http_code} t=%{time_total}\n' https://cloudflare.com/ &
  wait
  sleep 5
done
```

Capture **while still broken** (within minutes — `log show` only keeps
`.info`/`.debug` for a short rolling window). Note the predicate adds
`com.apple.network`, which carries the egress `NWConnection` / NECP path
detail the standard bundle predicate omits:

```sh
DEST=$(mktemp -d /tmp/rama-tproxy-wake.XXXXXX)
log show --last 8m --style ndjson --info --debug \
  --predicate 'subsystem BEGINSWITH "org.ramaproxy.example.tproxy"
            OR subsystem == "com.apple.networkextension"
            OR subsystem == "com.apple.network"' \
  > "$DEST/system.ndjson"
echo "$DEST"
```

Failure signature of intercept-but-no-forward:

1. `transparent proxy tcp flow closed` with `bytes_sent=0` (client request
   received, nothing returned), and many closes with `age_ms < 50` (flows
   torn down almost immediately).
2. Apple `... Closing reads ... closed by plugin` immediate-EOFs.

The lifecycle lines are just `system sleep` / `system wake`: sleep is a
brief pause-and-return (no engine drain, no flow teardown), and flows
that don't survive the suspend are reaped post-wake by the per-flow
`.failed` path. The historical root cause here was a blocking on-sleep
engine drain that wedged on a non-yielding task and left the proxy
intercepting traffic it could no longer forward — do not reintroduce a
blocking drain on the sleep path.

Triage one-liners over the captured bundle:

```sh
B="$DEST/system.ndjson"
# egress health: client requests that got a reply (bytes_sent>0) vs total
grep 'tcp flow closed ' "$B" | grep direction=ingress \
  | grep -oE 'bytes_sent=[0-9]+' | awk -F= '{t++; if($2>0)o++} END{printf "%d/%d replied\n",o,t}'
# immediate-EOF count (sub-50ms closes)
grep 'tcp flow closed ' "$B" | grep -oE 'age_ms=[0-9]+' | awk -F= '$2<50{n++} END{print n" closes <50ms"}'
```

Confirm it's the proxy, not the link: while broken, restarting **only**
the proxy (`just install-tproxy-dev`, or toggling the profile) restores
connectivity without a reboot. (For the consuming product, replace the
`org.ramaproxy.example.tproxy` ids with that product's subsystem /
provider ids.)

## Stress + resource-usage testing

### One-click traffic stress

Run live traffic against public HTTP/HTTPS endpoints while the
sysext is active. Small/large GETs, large POST bodies, plain HTTP,
parallel connections, HTTP/1.1 ↔ HTTP/2 mix, quick connection churn:

```sh
just stress-traffic
```

Tunables (env vars):

```sh
STRESS_DURATION=120 STRESS_CONCURRENCY=32 just stress-traffic
STRESS_LARGE_BYTES=$((64 * 1024 * 1024)) just stress-traffic   # 64 MiB GET
```

To couple the run with periodic resource sampling of the extension
process — and to enable pre/post-run `vmmap`+`heap` snapshots so
the diff sits in the same log dir — hand the script the sysext PID
via `STRESS_MONITOR_PID`:

```sh
STRESS_MONITOR_PID=$(pgrep -f org.ramaproxy.example.tproxy.dev.provider) \
  just stress-traffic
```

For a more diagnostic run, capture the system log alongside the
stress run and pass it via `STRESS_NDJSON` so the summary prints a
close-reason histogram:

```sh
# Cache a sudo timestamp first so the script can capture
# vmmap/heap snapshots non-interactively without hanging on a
# password prompt (the sysext is root-owned).
sudo -v

START="$(date -u '+%Y-%m-%d %H:%M:%S')"
STRESS_MONITOR_PID=$(pgrep -f org.ramaproxy.example.tproxy.dev.provider) \
  STRESS_DURATION=180 just stress-traffic

# After the run, capture the system log for the same window:
sudo log show \
  --predicate 'subsystem BEGINSWITH "org.ramaproxy.example.tproxy" OR subsystem == "com.apple.networkextension" OR subsystem == "com.apple.network"' \
  --info --debug \
  --start "$START" --style ndjson > /tmp/system.ndjson

# Re-run the script in analysis-only mode:
STRESS_NDJSON=/tmp/system.ndjson STRESS_DURATION=0 just stress-traffic
sudo leaks $(pgrep -f org.ramaproxy.example.tproxy.dev.provider) | head -50
```

The script writes per-worker logs to a tmp directory and prints,
on exit:

- per-worker `iters / ok / fail` summary
- top-5 errors per worker (4xx/5xx, `000` transport failures, curl errors)
- truncation scan: `curl: ... N out of M bytes received` lines
- pre/post `vmmap`+`heap` snapshot if `STRESS_MONITOR_PID` was set
- close-reason histogram if `STRESS_NDJSON` points at a captured
  system log

Pair with [Bundle everything for offline triage](#bundle-everything-for-offline-triage)
below to also collect dial9 traces from the same window.

### Apple-native resource and leak inspection

The sysext runs as root, so most of the inspection commands need
`sudo`. Resolve the PID once and reuse:

```sh
PID=$(pgrep -f org.ramaproxy.example.tproxy.dev.provider)
echo "$PID"
```

| Tool | Command | Use for |
|---|---|---|
| `ps` | `ps -o pid,rss,vsz,%cpu,state -p $PID` | Snapshot RSS / VM size / CPU. |
| `top` | `top -pid $PID -stats pid,rsize,vsize,csw,faults` | Live RSS, context switches, page-faults. |
| `vmmap` | `sudo vmmap --summary $PID` | VM region totals (look for unbounded MALLOC_TINY / MALLOC_LARGE growth). |
| `heap` | `sudo heap $PID` | Heap snapshot — counts and total bytes per allocation class. Diff two snapshots after stress to find unbounded growth. |
| `leaks` | `sudo leaks $PID` | Walks the heap, reports cycles. The textbook signal for retain-cycle leaks (Swift dispatcher, ObjC cycle through `NWConnection.stateUpdateHandler`). |
| `sample` | `sudo sample $PID 10 -file /tmp/sample.txt` | 10-second sampling stack profile — find tight loops or wedged threads. |
| `lsof` | `sudo lsof -p $PID \| grep -E "TCP\|UDP"` | Open kernel socket count — should not climb monotonically across long runs. |

A typical leak-hunt loop while stress is running:

```sh
PID=$(pgrep -f org.ramaproxy.example.tproxy.dev.provider)
sudo heap $PID > /tmp/heap.before.txt
STRESS_DURATION=180 just stress-traffic
sudo heap $PID > /tmp/heap.after.txt
diff /tmp/heap.before.txt /tmp/heap.after.txt | head -60
sudo leaks $PID
```

For richer analysis use **Instruments.app**:

- `Leaks` template — graphs retain cycles. Open Instruments, choose
  the `Leaks` template, attach to the sysext PID, run `just
  stress-traffic` in another terminal. Cycle-detected allocations
  appear in the Leaks track with their full retain graph.
- `Allocations` template — show allocation counts over time per
  type. Useful for finding "this kind of object grows linearly with
  flow count and never deallocates".
- `Time Profiler` template — sample-based CPU profile while stress
  runs. Catches busy-waits / runaway loops.

Instruments needs the `com.apple.security.get-task-allow`
entitlement on the target binary or admin attach permission. The
demo's Apple-Development-signed dev sysext has it during developer
mode; the Distribution build does not (the entitlement is stripped
at notarisation).

### Cross-checking with the structured event stream

Per-flow byte counts and close reasons land in the unified system
log (`subsystem BEGINSWITH "org.ramaproxy.example.tproxy"`). For a single
flow id, ingress and egress events are emitted separately —
`bytes_received` / `bytes_sent` on each event are RELATIVE to the
side the bridge is on (use the `direction` field to interpret).

```sh
log show --last 5m --predicate 'subsystem BEGINSWITH "org.ramaproxy.example.tproxy"' \
  --info --debug | grep -E 'flow_id|tproxy.+flow closed'
```

If the dial9 runtime is wired (it is in this demo), each intercept
also produces a `TproxyFlowOpened` / `TproxyFlowClosed` pair in the
trace. `dial9-viewer` plots the per-flow lifecycle alongside Tokio
runtime events.

## Observability with dial9

This example always builds with [dial9](https://github.com/dial9-rs/dial9-tokio-telemetry)
runtime telemetry on. Wiring + tuning knobs live in
[`tproxy_rs/src/dial9.rs`](./tproxy_rs/src/dial9.rs); a misconfigured
build falls back to a plain runtime rather than failing the engine
build. Traces land at `<storage_dir>/dial9-traces/` — for this demo
that resolves to `/var/root/Library/Application Support/rama/tproxy/dial9-traces/`.
The test harness wires no storage directory through, so it stays plain.

### Reading traces

The trace is a self-describing binary stream from
[`dial9-tokio-telemetry`](https://github.com/dial9-rs/dial9-tokio-telemetry).
Triage with `dial9-viewer` (GUI timeline), `dial9` /  `dial9-cli` (grep
+ JSON; pipe into an LLM for triage), or deserialise programmatically
with [`dial9-trace-format`](https://docs.rs/dial9-trace-format). Follow
the upstream docs for current install + command surface.

The extension emits structured `tracing` events on the
`org.ramaproxy.example.tproxy` subsystem with field names that match
the dial9 events. Typical workflow: spot a problem in the system log,
lift `flow_id` or similar, then filter the dial9 trace by it.

```sh
log stream --level debug --style compact \
  --predicate 'subsystem BEGINSWITH "org.ramaproxy.example.tproxy"'
log show --last 1h --style compact --info --debug \
  --predicate 'subsystem BEGINSWITH "org.ramaproxy.example.tproxy"'
```

Widen to Apple's subsystems for NetworkExtension-side issues:

```sh
log show --predicate '(subsystem BEGINSWITH "org.ramaproxy.example.tproxy") || \
                      (subsystem == "com.apple.networkextension") || \
                      (subsystem == "com.apple.network")' \
  --info --debug --last 30m
```

### Bundle everything for offline triage

Hand a single tmp dir to a teammate, an LLM, or `dial9-viewer` —
pulls the dial9 traces from the sysext storage (sudo), the last hour
of relevant `log show` output, and any recent provider crash reports:

```sh
DEST=$(mktemp -d /tmp/rama-tproxy-bundle.XXXXXX) && \
sudo cp -R "/var/root/Library/Application Support/rama/tproxy/dial9-traces" "$DEST/" 2>/dev/null || true

log show --last 15m --style ndjson --info --debug \
  --predicate 'subsystem BEGINSWITH "org.ramaproxy.example.tproxy" OR subsystem == "com.apple.networkextension"' \
  > "$DEST/system.ndjson"

sudo log collect --last 15m --output "$DEST/system.logarchive" \
  --predicate 'subsystem BEGINSWITH "org.ramaproxy.example.tproxy" OR subsystem == "com.apple.networkextension"'

setopt NULL_GLOB
sudo cp /Library/Logs/DiagnosticReports/org.ramaproxy.example.tproxy.dev.provider*.ips "$DEST/" 2>/dev/null || true
unsetopt NULL_GLOB

sudo chown -R "$(id -u):$(id -g)" "$DEST"
echo "$DEST"
```

Open the directory with `dial9-viewer "$DEST/dial9-traces"`, point an
agent at it, or grep the NDJSON log alongside the binary trace.

### Caveats

- ~1 MiB buffer per OS thread. Fine for this demo; reconsider for
  high-thread workloads.
- macOS only captures runtime-level + application events; Linux gets
  kernel scheduling delays and CPU profiling samples too.
- The two ingress/egress bridge tasks are spawned from a Swift dispatch
  queue, so dial9's thread-local handle is inert there — per-future
  wake graphs are missing for those two tasks. Runtime-level events
  still fire on every poll.

### See also

[dial9 book chapter](https://ramaproxy.org/book/dial9.html),
[netstack.fm ep. 37](https://netstack.fm/#episode-37), and
[`production_use.rs`](https://github.com/dial9-rs/dial9/blob/HEAD/dial9/examples/production_use.rs)
for operator knobs (CPU profiling, S3 upload, schedule-event capture)
the demo deliberately keeps off by default.
