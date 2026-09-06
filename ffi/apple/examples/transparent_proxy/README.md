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
Clean signed builds compile both Rust architectures from a pinned source archive
and export the host's `dial9_evidence` helper for the live validation scripts.
For a standalone universal Rust library, run `just build-tproxy-rs`. It produces:

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

### Sanitizer coverage

`just test-e2e-sanitizers` runs two complementary passes. Rust AddressSanitizer
exercises the FFI stress cases for memory errors such as use-after-free; ASan
does not detect data races. Swift ThreadSanitizer covers instrumented Swift-side
code, but it does not instrument the linked Rust static library. The combined
recipe therefore does not claim complete Rust race coverage.

### Why the split exists

A non-admin developer cannot usually rely on self-service `Developer ID` signing the way they can rely on `Apple Development` signing in Xcode.

So this example deliberately demonstrates both:

- the local-developer workflow companies need for day-to-day development
- the Developer ID system-extension workflow companies need for shipping a directly distributed macOS L4 proxy

## Logs

### Signed modern UDP callback E2E (macOS 15+)

The signed example includes a real-socket test for
`NEAppProxyUDPFlowHandling`. It installs the current development build,
passes test-only policy overrides as non-persisted start options, and
drives public protocol endpoints through the active system extension:

- Cloudflare DNS (`1.1.1.1:53`) declined by Rama (`false`, direct pass-through)
- Cloudflare NTP (`162.159.200.1:123`) accepted by Rama (`true`, UDP forwarding)
- Google Public DNS (`8.8.8.8:53`) accepted then closed by Rama (`true`, blocked)
- Cloudflare HTTP/3 declined by Rama (`false`, direct UDP/443 pass-through)
- One bound Cloudflare HTTP/3 request forwarded by Rama (`true`, UDP interception)

Run it on a macOS 15+ signing host where the development system extension has
been approved:

```sh
just test-modern-udp-signed
```

The test first runs DNS/NTP controls and H3 pass-through with an unblocked
profile, then enables the exact blocked-DNS override and UDP/443 interception.
It captures the provider's structured
Rust log, verifies the exact remote address/port and Rama decision, verifies
pass-through flows never enter provider handling, and checks that the accepted
NTP endpoint reaches Rama's UDP forwarding service. It also snapshots the
root-owned Dial9 trace directory before the run, restores the default profile
afterward, waits for a new sealed segment, and decodes an exact
`TproxyFlowOpened`/`TproxyFlowClosed` pair for that NTP flow ID and UDP protocol.
Stale or still-active trace segments cannot satisfy the gate. The terminal
`udp-evidence-status.tsv` artifact distinguishes a complete product failure
from an infrastructure/cleanup failure and records probe, log-join, profile
restore, provider-process identity, Dial9 close reason/age/byte counts, Rust
UDP-ingress pressure, and Swift pre-queue staging counts. The provider PID and
start identity must remain stable through evidence collection; profile
restoration is verified separately and restarts the engine generation. Malformed/redacted
pressure lines make the evidence incomplete. The test deliberately stalls one
E2E UDP service and bursts 512 datagrams. The hold uses the same ten-minute
expiry as the temporary policy and applies only when the Python bundle, flow
metadata endpoint, actual datagram peer, and versioned payload endpoint marker
all agree. It leaves the production channel capacity unchanged, so interrupted
cleanup cannot permanently degrade unrelated UDP. The gate requires a Rust
ingress drop transition and its recovery for that exact decision `flow_id`
inside the pressure phase, rejects foreign-flow or outside-phase drops, and
rejects any Swift pre-queue staging loss. On macOS 15+, an exact
initial endpoint reaching Rust also proves that the modern typed callback
delivered the flow; the generic fallback has no public remote endpoint to
forward. The UDP/443 request uses Apple's
`nscurl --http3-prior-knowledge` and requires the response to report
`http=http/3`; the matching provider record must also be a fresh UDP/443 flow
attributed to the launched `nscurl` PID, at one of the URL's resolved endpoints.
The UUID in the URL is only a cache buster; it is not observable in the UDP
decision record and is not claimed as a flow-binding token. Instead, the gate
closes the decision window after a bounded quiescence interval following the
launched PID's record and
requires exactly one matching PID/endpoint decision, so a TCP fallback or an
unrelated background QUIC flow cannot satisfy it. The NTP Dial9 pair must close
with numeric reason `1` and readable reason `shutdown`, fall inside the actual
monotonic gate window, and contain at least one complete 48-byte request and
response.

The H3 pass-through canary may receive no usable local endpoint from the
pre-open flow metadata. It records `local_endpoint=unavailable` only for
`nscurl` pass-through decisions to UDP/443. Its correspondence still requires
one distinct provider flow per owned process, the exact remote endpoint,
run UUID, provider generation, and phase. This is not a complete socket-tuple
proof or evidence of H3 interception. Python probes explicitly bind before
traffic; every echo socket still requires a concrete local endpoint and an
exact endpoint-to-flow bijection.

After the blocked-DNS canary, the controlled echo population and deliberate
pressure burst run together in the second profile, followed by the NTP recovery
canary. Their decisions and Dial9 requirements must all use that profile's
intercepting generation. The initial NTP control remains bound to the first
generation. Raw receipt clocks and provider-log boundaries enforce this order.

The existing Python probe then loads an installed HTTP/3-capable libcurl and makes one
IPv4 request with a fresh handle bound to a nonzero local port. It requires
HTTP/3 and status 200, limits the transfer to 15 seconds and the response body
to 1 MiB, and retains normal TLS verification. The raw body, its digest, child
exit, clock window, and exact local/remote endpoints must agree with one Python
intercept decision in that profile. The finalizer restores the normal profile
before collecting Dial9 once, sealing both workload generations. The H3 flow
must close with reason `shutdown` and positive encrypted UDP byte counts no
larger than 16 MiB per direction; HTTP body size is not a transport byte count.

The client uses `/opt/homebrew/opt/curl/lib/libcurl.4.dylib` or
`/usr/local/opt/curl/lib/libcurl.4.dylib` when available. Set
`RAMA_TPROXY_E2E_HTTP3_LIBCURL` to an absolute path for another installation.
The harness does not install a library. Its receipt records the resolved main
library path, SHA-256, and version as toolchain provenance; this does not attest
the library's dependencies or the capture host. Offline evidence replay neither
loads that library nor makes network requests. The automated suite exercises
the client with mocks, so CI does not need libcurl or signing for those tests.

The signed workload defaults to 128 controlled UDP sockets, each sending 64
requests with two-second pacing. It permits 128–450 sockets within the same
180-second workload deadline:

```sh
RAMA_TPROXY_E2E_ECHO_SOCKETS=128 \
  just test-modern-udp-signed
```

The client exchanges one packet across every socket before beginning the next
round. Its 32 workers limit outstanding exchanges; all sockets remain open
throughout the rounds. Each packet records its flow/sequence and monotonic
send/receive timestamps. Release verification requires all initial responses
before the next round, at least 90 seconds shared by the entire population,
and gaps below the engine's 60-second UDP idle timeout. It also checks exact
timing cardinality, per-flow pacing, the workload deadline, and agreement with
the run's wall-clock window. Smaller configurations remain available through
the standalone `echo-load` command for developer testing.

Exact endpoint and source-application fields remain private during normal
operation. The example Rust policy owns the E2E mode, probe allowlist, public
test diagnostics, and ten-minute expiry for temporary UDP overrides. The
reusable `RamaAppleNetworkExtension` provider remains final and contains no
test policy or probe knowledge. Rust receives the normalized source-app bundle
identifier, so both bare and team-prefixed `python3` signing identifiers resolve
to `com.apple.python3`. Unrelated background flows remain private, and the mode
is passed through `startOptions` without ever being written to the saved
`NETransparentProxyManager` profile. Downstream users configure and decide UDP
flows in Rust; they do not need a custom Swift provider.

The temporary mode emits `udp_e2e_diagnostic_active` once when configured and
`udp_e2e_diagnostic_rejected` at most once per rejection reason per engine
generation. These records expose only the run/provider identity, counts, and
fixed reasons such as `missing_local_endpoint` or `missing_source_pid`.
They explain absent decision records without publishing rejected flow metadata;
they cannot satisfy the gate's exact traffic-attribution requirements.

The default targets are maintained public services and therefore require
Internet access. They can be replaced for a restricted runner with
`RAMA_TPROXY_E2E_PASSTHROUGH_DNS`, `RAMA_TPROXY_E2E_INTERCEPT_NTP`,
`RAMA_TPROXY_E2E_BLOCKED_DNS`, and `RAMA_TPROXY_E2E_HTTP3_URL`. The first three
values must be IP literals so callback-log assertions remain deterministic.
Cached `sudo` credentials are required to read and copy the extension's
root-owned Dial9 segments. Prime them with `sudo -v` immediately before the
recipe; the script itself uses non-interactive `sudo -n` and fails incomplete
instead of prompting mid-run.

The legacy callback remains compile- and unit-tested on current CI. On the
oldest supported pre-macOS-15 signing host, run the same real-socket probe with
the explicit legacy opt-in:

```sh
RAMA_TPROXY_ALLOW_LEGACY_UDP_E2E=1 just test-modern-udp-signed
```

That run retains the same Rust pass-through, intercept, block, endpoint, and
UDP/443 assertions. An older signed runner is not currently available in hosted
CI.

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

### Controlled remote UDP workload

The existing probe can exercise a controlled echo server on UDP/443. Use the
same checkout and a fresh lowercase UUID on both machines. On your test server,
choose its listening address and retain the ready/result files:

```sh
python3 scripts/modern_udp_e2e_probe.py echo-server \
  --bind "$ECHO_BIND_ADDRESS" --port 443 --run-uuid "$RUN_UUID" \
  --expected-count 8192 --max-seconds 600 \
  --ready-file echo-ready.json --result-file echo-server.json
```

On the client, use the server's reachable IP address. This profile sends 64
1200-byte requests from each of 128 persistent sockets, with each socket's
requests spaced by at least two seconds. Every socket participates in each
round even when the population exceeds the worker count:

```sh
python3 scripts/modern_udp_e2e_probe.py echo-load \
  --server "$ECHO_SERVER_ADDRESS" --port 443 --run-uuid "$RUN_UUID" \
  --socket-count 128 --concurrency 32 --datagrams-per-socket 64 \
  --payload-bytes 1200 --interval-ms 2000 --timeout 8 \
  --result-file echo-client.json
```

The server needs permission to bind UDP/443 and a firewall rule allowing the
test client. Start the client after the ready file appears. Preserve both
machines' results to compare counts and payload hashes. Successful replies
prove the echo workload; transparent-proxy interception additionally requires
an intercepting UDP/443 policy and matching provider/Dial9 flow identities.
Schema2 receipts also record `socket_endpoints` on the client and `socket_peers`
on the receiver, indexed by the payload's socket ID. Each map must cover every
socket exactly once. Proxy egress and NAT can change addresses: compare these
maps by socket ID, without requiring their address values to match. This fixed
flow fixture rejects a peer change or tuple reuse within one socket ID; a new
flow after intentional idle expiry needs a new identity. The receiver bounds
indices to512 sockets and64 packets each, and retained payload to256MiB.
Current replay requires schema2; old receipts lack these address records.
The signed modern harness currently supplies its own loopback echo server and
tests H3 pass-through plus one intercepted request. These commands do not extend its release
seal or replace the required idle, mixed TCP, recovery and performance phases.

### Automated evidence regressions

Run `just test-evidence` for the modern UDP, soak, stress, and signed-run
evidence suites. `just qa` and the macOS CI Apple QA job run the same suites;
`just test-soak-log-parser` remains an alias. They cover raw-data validation,
failed or incomplete runs, build-wrapper composition, and local socket,
subprocess, and terminal cleanup. Read any reported skips: restricted process
visibility or loopback access can prevent those local fixtures from running.

These suites do not install a provider or certify live signed traffic. The
signed modern UDP gate, on-device soak, and paired performance runs below
require separate execution. Developer ID signing and notarization also remain
separate from CI's unsigned build checks.

### On-device soak

From this example directory, with the signed development provider installed
and enabled:

```sh
./scripts/soak_test.sh
# Build and install first on a development machine:
DO_INSTALL=1 ./scripts/soak_test.sh
```

The script discovers its checkout from its own location; `REPO` can override
that path. It requires macOS, Python 3, the system curl, network access, and
interactive sudo authentication. Installation also requires development
signing and system-extension approval. Keep the terminal available for the
sleep/wake phase and wake the machine when prompted.

Defaults exercise 180 seconds of traffic at concurrency 24, active and idle
TCP holders, downloads, recovery, and idle CPU sampling. The default holder
limit is 300 flows. Evidence is written beneath `~/rama-tproxy-soak/`; `OUT`
can select a fresh empty directory. The script header documents other
controls. Skipping phases is useful for diagnosis but cannot satisfy the
canonical release profile. Exit codes are 0 for a complete passing run, 1
for a complete run with failed checks, and 2 for incomplete evidence.
This TCP soak does not replace the mass UDP/443 and long-lived UDP gates.

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

For a provider-monitored run, the script also owns a bounded NDJSON log stream,
joins it, seals it into the bundle, and verifies that the monitored provider PID
has a record inside the run window:

```sh
# Cache a sudo timestamp first so the script can capture
# vmmap/heap snapshots non-interactively without hanging on a
# password prompt (the sysext is root-owned).
sudo -v

STRESS_MONITOR_PID=$(pgrep -f org.ramaproxy.example.tproxy.dev.provider) \
  STRESS_DURATION=180 just stress-traffic

# Re-run the same artifact directory in analysis-only mode:
STRESS_LOG_DIR=/tmp/rama-stress.<run> \
  STRESS_DURATION=0 just stress-traffic
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

A terminal traffic run enforces configurable absolute p95 latency, throughput,
provider RSS-growth, and provider CPU limits. It writes `stress-manifest.tsv`
with the run UUID/window and SHA-256 identities for worker output, metrics,
harness sources, git state, and (in monitored mode) process, signing,
pre/post/monitor, and NDJSON artifacts. Analysis-only mode verifies the sealed
source bundle and writes `stress-analysis-status.tsv`; it never overwrites the
immutable `stress-status.tsv`. These are self-attested local-integrity records,
not proof against a party able to fabricate an entire bundle.

The absolute defaults are safety ceilings, not a performance claim. For a
regression gate, run the identical workload twice, adjacent in time: first with
the transparent proxy disabled, then with it enabled and monitored. Label the
runs explicitly and compare their already-sealed bundles:

```sh
BASE=$(mktemp -d /tmp/rama-stress-direct.XXXXXX)
CAND=$(mktemp -d /tmp/rama-stress-proxy.XXXXXX)
PAIR=$(mktemp -d /tmp/rama-stress-pair.XXXXXX)

# With the transparent proxy disabled:
STRESS_DURATION=60 STRESS_CONCURRENCY=16 \
  STRESS_TRAFFIC_ROLE=direct-baseline STRESS_LOG_DIR="$BASE" \
  just stress-traffic

# Enable the proxy; monitored mode owns its NDJSON capture:
STRESS_DURATION=60 STRESS_CONCURRENCY=16 \
  STRESS_TRAFFIC_ROLE=proxy-candidate STRESS_LOG_DIR="$CAND" \
  STRESS_MONITOR_PID=$(pgrep -f org.ramaproxy.example.tproxy.dev.provider) \
  STRESS_BUILT_PROVIDER="$BUILT_PROVIDER" \
  STRESS_INSTALLED_PROVIDER="$INSTALLED_PROVIDER" \
  just stress-traffic

scripts/stress_compare.py create "$BASE" "$CAND" \
  "$PAIR/stress-comparison.tsv"
scripts/stress_compare.py verify "$BASE" "$CAND" \
  "$PAIR/stress-comparison.tsv"
```

Set `BUILT_PROVIDER` and `INSTALLED_PROVIDER` to the exact built and installed
system-extension bundles verified for the running development provider. Keep
comparison outputs outside both sealed run directories; adding files to a run
invalidates its artifact manifest.

Use a controlled HTTP test server with sufficient capacity for release
measurements. Set `STRESS_TARGET_HOST` to its lowercase DNS hostname for all six
stress runs and the soak. The default is `http-test.ramaproxy.org`. This selects
the same host for HTTP and HTTPS `/method`, the 16 MiB `/bytes` download and the
8 MiB `/octet-stream` echo; release roles still reject changed routes, sizes or
thresholds. Soak also uses it for probes, active downloads and silent TCP
holders. Its legacy `DL_HOST` setting is an alias; conflicting values fail.

The server must provide trusted TLS, HTTP/1.1 and HTTP/2, exact echo/download
behavior, paced `/bytes` responses and sufficiently long silent TCP connections
on port 443. Check these capabilities and server rate limits before the native
campaign. Hostname validation does not prove the server implementation, its
resolved address or its performance isolation. Existing soak downloads may
follow redirects, so this names the initial target, not every eventual peer.

The workload records its host and exact route hashes. Pair/series verification
requires the same complete workload across all six runs. Final release
verification additionally requires a caller-selected expected host, independent
of the artifact and environment:

```sh
just verify-gate20-evidence "$MODERN" "$SOAK" "$SERIES" "$TEST_HOST"
# Equivalent explicit CLI policy:
python3 scripts/signed_run_evidence.py verify-release-set \
  --expected-http-host "$TEST_HOST" \
  --require-kind modern_udp --require-kind soak --require-kind stress-series \
  "$MODERN" "$SOAK" "$SERIES"
```

Omitting the expected host requires the default public hostname; a custom-host
artifact cannot silently change that policy. The verifier reads this field from
the manifest-retained workloads and soak metadata. Stress schema 5 adds this
host binding; older schema 4 artifacts retain their original source/verifier
boundary and are not current release evidence.

The paired gate requires an explicit traffic-only `direct-baseline`, a
provider-monitored `proxy-candidate`, identical workload and harness identities,
baseline-before-candidate ordering, and at most a ten-minute gap. Release-gate
defaults allow candidate p95 up to 1.5× baseline and require at least two-thirds of baseline
throughput, while the candidate still has to pass the absolute RSS/CPU and
latency/throughput ceilings. `stress_compare.py create` accepts optional
`MAX_P95_RATIO_MILLI MIN_THROUGHPUT_RATIO_MILLI MAX_GAP_MS` overrides.
It also writes an adjacent `stress-comparison.tsv.source-stress_compare.py` and
seals that exact source's SHA-256 into the verdict. Verification fails if either
the sealed copy or the currently executing comparator differs, so an old verdict
cannot silently acquire new comparison semantics.
The `direct-baseline` harness samples development-provider absence throughout
the run. This does not establish the absence of unrelated Network Extensions.
Record other active providers and retain the profile-disable/enable audit
record alongside both bundles.

A final device/release claim requires at least three interleaved adjacent pairs,
ordered `direct-1, proxy-1, direct-2, proxy-2, direct-3, proxy-3`, against the
same stable workload and controlled test server. Create and verify
each strict pair as above, then seal the aggregate:

```sh
SERIES_PARENT=$(mktemp -d /tmp/rama-stress-series.XXXXXX)
SERIES="$SERIES_PARENT/release-set"
scripts/stress_compare.py create-series "$SERIES" \
  "$BASE1" "$CAND1" "$PAIR1/stress-comparison.tsv" \
  "$BASE2" "$CAND2" "$PAIR2/stress-comparison.tsv" \
  "$BASE3" "$CAND3" "$PAIR3/stress-comparison.tsv"
scripts/stress_compare.py verify-series "$SERIES"
```

`create-series` requires a new directory outside all member runs and copies
the verified inputs into a self-contained sealed release set.

The series gate rejects fewer than three pairs, weakened per-pair thresholds,
workload drift, reordered/overlapping pairs, or gaps over ten minutes. Its sealed
verdict reports median and worst p95/throughput ratios plus worst candidate
p95, throughput, RSS growth, and CPU. Preserve the enable/disable audit record
for every transition; the bundle cannot independently prove that operator step.

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

This example always builds with [dial9](https://github.com/dial9-rs/dial9)
runtime telemetry on. Wiring + tuning knobs live in
[`tproxy_rs/src/dial9.rs`](./tproxy_rs/src/dial9.rs); a misconfigured
build falls back to a plain runtime rather than failing the engine
build. Traces land at `<storage_dir>/dial9-traces/` — for this demo
that resolves to `/var/root/Library/Application Support/rama/tproxy/dial9-traces/`.
The test harness wires no storage directory through, so it stays plain.

### Reading traces

The trace is a self-describing binary stream from
[`dial9`](https://github.com/dial9-rs/dial9).
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
