# Transparent Proxy (MacOS) Example

This example shows how to link a Rust staticlib that implements the
Rama NetworkExtension C ABI into a macOS Transparent Proxy extension.

## Build

```sh
cd ffi/apple/examples/transparent_proxy
just build-tproxy-dev
```

This builds the Rust staticlib and the developer-signed macOS host + system extension. The Rust staticlib is produced at:

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
just install-tproxy-with-signing-reset-profile
```

Developer ID distribution commands:

```sh
cd ffi/apple/examples/transparent_proxy
just install-tproxy-with-developer-id-signing-reset-profile
```

That distribution command now performs the full shipping flow: build, sign, notarize, staple, install, then launch.
Before replacing the installed app, the install helper uninstalls both the developer and distribution system-extension bundle IDs first, so switching between Apple Development and Developer ID signing does not leave the old extension active.

Developer mode uses the default Xcode spec at [Project.yml](/Users/glendc/code/github.com/plabayo/rama/ffi/apple/examples/transparent_proxy/tproxy_app/Project.yml).
Developer ID distribution mode uses [Project.dist.yml](/Users/glendc/code/github.com/plabayo/rama/ffi/apple/examples/transparent_proxy/tproxy_app/Project.dist.yml).
The example now follows a Proton-style layout: one transparent proxy system-extension implementation is shared by both modes, and the entitlement difference is controlled by `NE_ENTITLEMENT_SUFFIX` in the Xcode spec. To avoid local code-signature collisions when switching between Apple Development and Developer ID on the same Mac, the developer and distribution modes use different bundle IDs.
The build helpers are:

- [build_tproxy_app_with_signing.sh](/Users/glendc/code/github.com/plabayo/rama/ffi/apple/examples/transparent_proxy/scripts/build_tproxy_app_with_signing.sh) for developer mode
- [build_tproxy_app_with_developer_id_signing.sh](/Users/glendc/code/github.com/plabayo/rama/ffi/apple/examples/transparent_proxy/scripts/build_tproxy_app_with_developer_id_signing.sh) for the raw Developer ID signed build
- [notarize_tproxy_app_with_developer_id_signing.sh](/Users/glendc/code/github.com/plabayo/rama/ffi/apple/examples/transparent_proxy/scripts/notarize_tproxy_app_with_developer_id_signing.sh) for the full Developer ID distribution flow

Both modes use the real system-extension product type. Developer mode uses the plain `app-proxy-provider` entitlement payload, while distribution mode switches the same entitlement template to `app-proxy-provider-systemextension`.

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
- Network Extension entitlement payload: `app-proxy-provider-systemextension`
- host app also carries `com.apple.developer.system-extension.install`
- intended for direct distribution outside the Mac App Store

For the App IDs, the practical setup is:

- developer host App ID: enable `Network Extensions` and `System Extension`
- developer extension App ID: enable `Network Extensions`
- distribution host App ID: enable `Network Extensions` and `System Extension`
- distribution extension App ID: enable `Network Extensions`

The host and extension now share one entitlement template each, with the Network Extension payload switched by `NE_ENTITLEMENT_SUFFIX`:

- developer mode uses `NE_ENTITLEMENT_SUFFIX = ""`
- distribution mode uses `NE_ENTITLEMENT_SUFFIX = "-systemextension"`

### What an admin needs to create

A team `Account Holder` or `Admin` needs to do the one-time Apple Developer portal setup.

1. Create or verify the four App IDs:
   - `org.ramaproxy.example.tproxy.dev`
   - `org.ramaproxy.example.tproxy.dev.provider`
   - `org.ramaproxy.example.tproxy.dist`
   - `org.ramaproxy.example.tproxy.dist.provider`
2. Enable `Network Extensions` on both App IDs.
3. Enable `System Extension` on the host App ID used for direct distribution.
4. Create the Developer ID distribution profiles for the direct-distribution system extension path.

### What a normal developer needs locally

A normal developer should use developer mode.

1. Sign in to Xcode with the team account.
2. Let Xcode manage the developer's own `Apple Development` certificate and automatic signing state.
3. Use the developer-mode command:

```sh
just install-tproxy-with-signing-reset-profile
```

This mode is designed to work for developers who do not have admin-level access to create or distribute `Developer ID` identities. No explicit provisioning-profile selection is documented for this mode. It uses the developer-only bundle IDs `org.ramaproxy.example.tproxy.dev` and `org.ramaproxy.example.tproxy.dev.provider`.

### What an admin or release engineer uses

For the real direct-distribution system extension path, use Developer ID mode. This helper builds the Xcode project in `Release`, lets Xcode perform the final signing pass with hardened runtime and secure timestamps, notarizes the built app, staples the result, and only then installs it:

```sh
just install-tproxy-with-developer-id-signing-reset-profile
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

- `Rama Transparent Proxy Example (Host)`
- `Rama Transparent Proxy Example (Extension)`

Only for distribution mode, if you intentionally renamed those profiles, should you override:

- `RAMA_TPROXY_HOST_PROFILE_SPECIFIER`
- `RAMA_TPROXY_EXTENSION_PROFILE_SPECIFIER`

If Xcode still fails to find the freshly downloaded Developer ID profiles, you can point the helper at the exact files and let it install them into the standard provisioning-profile directory before building:

- `RAMA_TPROXY_HOST_PROFILE_PATH=/absolute/path/to/Rama_Transparent_Proxy_Example_Host.provisionprofile`
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
security find-identity -p codesigning -v | rg 'Developer ID Application|ADPG6C355H'
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

Stream all logs (host, extension, and Rust (incl. rama)):

```sh
systemextensionsctl list
```

This is especially useful when the app reports that approval is required, because macOS will print the exact Settings location for Network Extension system extensions.

```sh
log stream --info --debug \
    --predicate 'subsystem == "org.ramaproxy.example.tproxy"'
```


Or if you want historical logs:

```sh
log show --last 1h --style compact --info --debug \
    --predicate 'subsystem == "org.ramaproxy.example.tproxy"'
```

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
just install-tproxy-with-signing
```

That target:

- rebuilds the Rust staticlib
- rebuilds the host app and system extension
- replaces `/Applications/RamaTransparentProxyExampleHost.app`
- refreshes LaunchServices registration for the host app
- launches the installed app so it can request system extension activation without recreating the saved proxy manager

If the next launch connects, the problem was registration state.

### 2. Reinstall the app and explicitly recreate the saved profile

Only do this when the saved `NETransparentProxyManager` profile itself is stale:

```sh
cd ffi/apple/examples/transparent_proxy
just install-tproxy-with-signing-reset-profile
```

That uses the same reinstall flow, but launches once with
`--reset-profile-on-launch`, which removes and recreates the saved proxy
manager. Because macOS treats that as a new network configuration, it may ask
for profile approval again.

### 3. Check whether macOS currently sees the system extension

```sh
systemextensionsctl list | rg 'org\.ramaproxy\.example\.tproxy|RamaTransparentProxyExample'
```

Expected output should include something like:

```text
org.ramaproxy.example.tproxy.dist.provider(0.1)
Path = /Applications/RamaTransparentProxyExampleHost.app/Contents/Library/SystemExtensions/RamaTransparentProxyExampleExtension.systemextension
SDK = com.apple.networkextension.app-proxy
```

If nothing is returned, macOS does not currently have the system extension activated. Run the reinstall command above and approve the system extension in System Settings if prompted.

### 4. Inspect host and Network Extension logs around the failure

Recent logs:

```sh
log show --last 5m --style compact \
  --predicate 'subsystem == "org.ramaproxy.example.tproxy" OR process == "neagent" OR process == "nesessionmanager" OR process == "RamaTransparentProxyExampleExtension"'
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
- `Found 0 extension(s) with identifier org.ramaproxy.example.tproxy.dist.provider`
  Registration is missing; reinstall the app.

### 5. Check for provider crash reports

```sh
find ~/Library/Logs/DiagnosticReports -maxdepth 1 \
  \( -name 'RamaTransparentProxyExampleExtension*.ips' -o -name 'RamaTransparentProxyExampleExtension*.crash' \) \
  -print | tail -n 10
```

If you see a fresh `.ips` file near the failure time, the provider crashed and the
later code `6` error is only fallout.

To inspect the latest report:

```sh
sed -n '1,240p' ~/Library/Logs/DiagnosticReports/RamaTransparentProxyExampleExtension-YYYY-MM-DD-HHMMSS.ips
```

### 6. Quick decision tree

1. Start fails with code `6`.
2. Run `systemextensionsctl list | rg 'org\.ramaproxy\.example\.tproxy|RamaTransparentProxyExample'`.
3. If nothing is registered: run `just install-tproxy-with-signing`.
4. If the system extension is registered: inspect logs with `log show --last 5m ...`.
5. If logs show code `7`, `Plugin failed`, or `Plugin was disabled`: inspect the extension crash report.
6. Only if registration is fine but the manager/profile is stale: run `just install-tproxy-with-signing-reset-profile`.

### 7. Common pattern in this demo

The failure sequence often looks like this:

1. Provider launches and starts handling flows.
2. Provider crashes because of a real runtime bug.
3. The next start reports code `6` or "plugin disabled".

So, if the proxy "randomly" starts working again after reinstall, that does not
guarantee the original runtime issue is fixed. It only means the registration /
profile layer was reset successfully.
