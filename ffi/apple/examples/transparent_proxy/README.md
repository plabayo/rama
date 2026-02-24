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
