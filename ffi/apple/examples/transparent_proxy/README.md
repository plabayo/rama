# Transparent Proxy (MacOS) Example

This example shows how to link a Rust staticlib that implements the
Rama NetworkExtension C ABI into a macOS Transparent Proxy extension.

The sysext generates and stores the demo MITM root CA in the macOS System
Keychain (`/Library/Keychains/System.keychain`) using Rama's built-in boring TLS
support. The CA is created on first startup and reused on subsequent starts.

The container app can delete the stored CA material via the `Rotate CA`
menu command or the `--clean-secrets` launch flag; the sysext will create a
fresh CA the next time it initialises. The container app does not create or
read the CA.

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

At runtime, the container app menu includes `Rotate CA`, which deletes the
CA material from the System Keychain and restarts the proxy. The sysext
generates a fresh CA on the next startup.

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
4. Register the shared app-group identifiers used as protected-storage access groups:
   - `group.org.ramaproxy.example.tproxy.dev.group`
   - `group.org.ramaproxy.example.tproxy.dist.group`
5. Enable the app-group / shared-keychain capability needed for the container app and sysext App IDs.
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

- `Rama Transparent Proxy Example (Container)`
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

Check that the system extension is currently registered:

```sh
systemextensionsctl list
```

When approval is pending, macOS prints the exact Settings location for Network Extension system extensions.

Stream live logs from the extension process and NE daemons:

```sh
log stream --info --debug \
  --predicate 'process == "org.ramaproxy.example.tproxy.dev.provider" OR process == "neagent" OR process == "nesessionmanager" OR process == "sysextd" OR process == "launchd"'
```

For historical logs (e.g. after the fact), replace `log stream` with `log show`:

```sh
log show --last 5m --style compact --info --debug \
  --predicate 'process == "org.ramaproxy.example.tproxy.dev.provider" OR process == "neagent" OR process == "nesessionmanager" OR process == "sysextd" OR process == "launchd"'
```

> **Note:** The Rust extension writes tracing logs to stderr, which launchd captures under
> the process name `org.ramaproxy.example.tproxy.dev.provider`. For the distribution
> extension replace `dev` with `provider` in the predicate above.

## Troubleshooting

The most confusing startup failure is:

```text
NEVPNConnectionErrorDomainPlugin code=6
The VPN app used by the VPN configuration is not installed
```

In this demo, code `6` is often not the first failure. It is frequently the
follow-up symptom after either:

- the installed app/system extension registration went stale
- the provider crashed and macOS disabled the plugin for the next launch

Use the checks below to separate those cases.

### 1. Reinstall the app without recreating the saved profile

This is the fastest recovery path when app-extension registration is stale:

```sh
cd ffi/apple/examples/transparent_proxy
just install-tproxy-dev
```

That target:

- rebuilds the Rust staticlib
- rebuilds the container app and system extension
- replaces `/Applications/RamaTransparentProxyExampleContainer.app`
- refreshes LaunchServices registration for the container app
- launches the installed app so it can request system extension activation without recreating the saved proxy manager

If the next launch connects, the problem was registration state.

### 2. Reinstall the app and explicitly recreate the saved profile

Only do this when the saved `NETransparentProxyManager` profile itself is stale,
or when you have changed `NEMachServiceName`, entitlements, or any Info.plist
key that `sysextd` reads only at install time:

```sh
cd ffi/apple/examples/transparent_proxy
just install-tproxy-dev-reset-profile
```

That uses the same reinstall flow, but launches once with
`--reset-profile-on-launch`, which removes and recreates the saved proxy
manager. Because macOS treats that as a new network configuration, it may ask
for profile approval again. It also forces `sysextd` to deactivate and
reactivate the extension, causing it to re-read `Info.plist` and regenerate the
launchd job (including `NEMachServiceName` and `MachServices` entries).

### 3. Check whether macOS currently sees the system extension

```sh
systemextensionsctl list | grep 'org\.ramaproxy\.example\.tproxy'
```

Expected output should include something like:

```text
[activated enabled] org.ramaproxy.example.tproxy.dev.provider (0.1/20260426200600)
```

If nothing is returned, or the state is not `[activated enabled]`, macOS does not
currently have the system extension active. Run the reinstall command above and
approve the system extension in System Settings if prompted.

### 4. Inspect container and sysext logs around the failure

```sh
log show --last 5m --style compact --info --debug \
  --predicate 'process == "org.ramaproxy.example.tproxy.dev.provider" OR process == "neagent" OR process == "nesessionmanager" OR process == "sysextd"'
```

Useful interpretations:

- `NEVPNConnectionErrorDomainPlugin code=6`
  Usually means "system extension unavailable now", not necessarily the original cause.
- `NEVPNConnectionErrorDomainPlugin code=7`
  The provider failed after launch; inspect extension logs and crash reports.
- `last stop reason Plugin failed`
  Provider runtime failure.
- `last stop reason Plugin was disabled`
  Provider crashed earlier and macOS disabled it for the next start.
- `Found 0 extension(s) with identifier org.ramaproxy.example.tproxy.dev.provider`
  Registration is missing; reinstall the app.

### 5. Check for XPC Mach service registration failure

If the sysext starts but immediately crashes or the XPC channel between container
and extension does not work, look for this pattern in the logs:

```text
launchd: failed activation: name = <TPROXY_XPC_SERVICE_NAME>
requestor = org.ramaproxy.example.tproxy.dev.provider
error = 1: Operation not permitted
```

This means launchd is rejecting the extension's attempt to register its named
Mach service. The correct fix is `NEMachServiceName` in the extension's
`Info.plist` (already present in this example), combined with a full
force-reinstall so that `sysextd` regenerates the launchd job with a
`MachServices` entry for that name.

After reinstalling with `reset-profile`, verify the launchd job has the entry:

```sh
sudo launchctl print system/org.ramaproxy.example.tproxy.dev.provider \
  | grep -A 5 -i machservices
```

Expected:

```text
MachServices = {
    ADPG6C355H.org.ramaproxy.example.tproxy.dev.group.xpc => 0
}
```

If the `MachServices` block is absent, `sysextd` did not pick up `NEMachServiceName`.
Try a reboot followed by another `reset-profile` install.

### 6. Check for provider crash reports

Sysext crash reports are written to the system-level diagnostic directory
(not the user-level `~/Library/...`):

```sh
ls -lt /Library/Logs/DiagnosticReports/ \
  | grep 'org\.ramaproxy\.example\.tproxy\.dev\.provider' \
  | head -5
```

If you see a fresh `.ips` file near the failure time, the provider crashed and the
later code `6` error is only fallout.

Also inspect what entitlements and `Info.plist` values ended up in the
installed binary to rule out signing or plist issues:

```sh
# Entitlements baked into the running binary
codesign -d --entitlements - \
  /Library/SystemExtensions/*/org.ramaproxy.example.tproxy.dev.provider \
  2>&1 | grep -A2 -E 'mach-register|NEMach|networkextension'

# Info.plist of the installed extension
plutil -p /Library/SystemExtensions/*/\
org.ramaproxy.example.tproxy.dev.provider.systemextension/Contents/Info.plist \
  | grep -E 'NEMach|TProxy|XpcService|BundleVersion'
```

### 7. Quick decision tree

1. Start fails with code `6`.
2. Run `systemextensionsctl list | grep 'org\.ramaproxy\.example\.tproxy'`.
3. If nothing is registered or state is not `[activated enabled]`: run `just install-tproxy-dev`.
4. If the system extension is registered: inspect logs with `log show --last 5m ...`.
5. If logs show `failed activation: error = 1: Operation not permitted` for the XPC service name: run `just install-tproxy-dev-reset-profile`, then verify `MachServices` via `sudo launchctl print ...`.
6. If logs show code `7`, `Plugin failed`, or `Plugin was disabled`: inspect the extension crash report in `/Library/Logs/DiagnosticReports/`.
7. Only if registration is fine but the manager/profile is stale: run `just install-tproxy-dev-reset-profile`.

### 8. Common pattern in this demo

The failure sequence often looks like this:

1. Provider launches and starts handling flows.
2. Provider crashes because of a real runtime bug.
3. The next start reports code `6` or "plugin disabled".

So, if the proxy "randomly" starts working again after reinstall, that does not
guarantee the original runtime issue is fixed. It only means the registration /
profile layer was reset successfully.

## Observability with dial9 (optional)

[dial9](https://github.com/dial9-rs/dial9-tokio-telemetry) is a low-overhead
runtime telemetry crate for Tokio that records poll timing, wake events, and
custom application events into a self-describing binary trace. It is
particularly useful for diagnosing the long-tail / wedge bugs that hit
transparent proxies in real-world use — the same failure modes that
motivated the per-flow shutdown / idle-timeout / handler-deadline / watchdog
hardening in `rama-net-apple-networkextension`.

This example exposes a `dial9` cargo feature that pulls in the dial9 crates
and defines a small set of custom events that mirror rama's structured
flow lifecycle logs (`TproxyFlowOpened`, `TproxyFlowClosed`,
`TproxyHandlerDeadline`). Cross-correlating dial9 traces with rama's
`flow_id=…` close events is the recommended workflow for post-mortem
analysis.

### Why bother

- Wake-up latency and Tokio scheduling delay show up as concrete numbers
  in the trace, not as P99 aggregations.
- The `flow_id` shared between rama's structured logs and dial9 custom
  events lets you go from a slow flow in production logs to its full poll
  history in `dial9-viewer`.
- On Linux, dial9 also captures kernel scheduling delays and CPU profiling
  samples. On macOS the kernel-side capture is more limited but the
  runtime-level events are still the bulk of what's useful here.

### Caveats

- **Requires `tokio_unstable`.** Add to `.cargo/config.toml` under
  `[build]`:

  ```toml
  rustflags = ["--cfg", "tokio_unstable"]
  ```

- **~1 MiB buffer per OS thread.** Fine for this example's bounded thread
  counts; document if copying the integration pattern into a high-thread
  workload.
- **Runtime wiring is not enabled by default.** The example defines the
  custom event types and gates the dependency, but does not swap the
  default `tokio::runtime::Runtime` for a `TracedRuntime`. To get full
  dial9 instrumentation, provide a custom
  [`TransparentProxyAsyncRuntimeFactory`](https://docs.rs/rama-net-apple-networkextension/latest/rama_net_apple_networkextension/tproxy/trait.TransparentProxyAsyncRuntimeFactory.html)
  that returns a runtime constructed via
  `dial9_tokio_telemetry::TracedRuntime::try_new`.

### Building with the feature on

```sh
RUSTFLAGS="--cfg tokio_unstable" cargo build --features dial9
```

### Viewing traces

```sh
cargo install dial9-viewer
dial9-viewer /path/to/trace.bin
```

### See also

- The book chapter
  [dial9 runtime telemetry](https://ramaproxy.org/book/proxies/operate/transparent/dial9.html)
  for the broader story on why dial9 fits this use case.
- [netstack.fm episode 37](https://netstack.fm/) — interview with the
  dial9 authors covering motivation and design.
