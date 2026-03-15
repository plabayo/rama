# Transparent Proxy (MacOS) Example

This example shows how to link a Rust staticlib that implements the
Rama NetworkExtension C ABI into a macOS Transparent Proxy extension.

## Build

```sh
cd ffi/apple/examples/transparent_proxy
just build-tproxy
```

This builds a universal staticlib at:

```
ffi/apple/examples/transparent_proxy/tproxy_rs/target/universal/librama_tproxy_example.a
```

## Xcode

`/RamaTransparentProxyExample.xcodeproj` is generated using `xcodegen generate`.

## Logs

Stream all logs (host, extension, and Rust (incl. rama)):

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

- the installed app/appex registration went stale
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
- rebuilds the host app and appex
- replaces `/Applications/RamaTransparentProxyExampleHost.app`
- forces LaunchServices / PlugInKit registration
- launches the installed app without recreating the saved proxy manager

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

### 3. Check whether macOS currently sees the app extension

```sh
pluginkit -mAvv | rg 'org\.ramaproxy\.example\.tproxy|RamaTransparentProxyExample|app-proxy'
```

Expected output should include something like:

```text
org.ramaproxy.example.tproxy.provider(0.1)
Path = /Applications/RamaTransparentProxyExampleHost.app/Contents/PlugIns/RamaTransparentProxyExampleExtension.appex
SDK = com.apple.networkextension.app-proxy
```

If nothing is returned, macOS does not currently have the appex registered.
Run the reinstall command above.

### 4. Inspect host and Network Extension logs around the failure

Recent logs:

```sh
log show --last 5m --style compact \
  --predicate 'subsystem == "org.ramaproxy.example.tproxy" OR process == "neagent" OR process == "nesessionmanager" OR process == "RamaTransparentProxyExampleExtension"'
```

Useful interpretations:

- `NEVPNConnectionErrorDomainPlugin code=6`
  Usually means "appex unavailable now", not necessarily the original cause.
- `NEVPNConnectionErrorDomainPlugin code=7`
  The provider failed after launch; inspect extension logs and crash reports.
- `last stop reason Plugin failed`
  Provider runtime failure.
- `last stop reason Plugin was disabled`
  Provider crashed earlier and macOS disabled it for the next start.
- `Found 0 extension(s) with identifier org.ramaproxy.example.tproxy.provider`
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
2. Run `pluginkit -mAvv | rg 'org\.ramaproxy\.example\.tproxy|RamaTransparentProxyExample|app-proxy'`.
3. If nothing is registered: run `just install-tproxy-with-signing`.
4. If the appex is registered: inspect logs with `log show --last 5m ...`.
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
