# StarlingMonkey engine proof

This directory builds the private JavaScript engine component used by the
`starling-spike` feature. Normal Cargo builds consume the checked-in
`rama-js-engine.wasm`; they do not require Node.js or rebuild the component.

Rebuild it with:

```sh
npm install --ignore-scripts
npm run build
```

The build is pinned by `package-lock.json`. It uses ComponentizeJS 0.22.0
without Weval AOT and disables every ambient WASI feature. The guest can only
call interfaces explicitly linked by its Rust host.

ComponentizeJS snapshots the initialized engine with Wizer. Consecutive builds
are not byte-identical, so verify a rebuilt artifact through its WIT interface,
metadata, size, and the Rust integration tests rather than its checksum.

The component exports persistent evaluation and registration operations. A
single generic host import carries encoded values between JavaScript and Rust;
the WIT interface does not need to change when a new function, value,
namespace, or host-object member is registered.

## Scope of the proof

The `starling_spike` integration test verifies persistent evaluation, values,
host functions, namespaces, mutable host objects, getters, setters, methods,
and receiver validation. It also verifies three containment properties:

- Wasmtime fuel interrupts a non-terminating script.
- a Wasmtime store memory limit rejects excessive guest memory growth;
- parsing 100,000-level parenthesis, binary, unary, and member chains cannot
  overflow the host process's native stack.

This feature is an architecture proof, not a second production backend. It is
not selected by the public runtime API. A production migration still needs to
move the boundary and host state into `src`, apply fuel, epoch deadlines, and
memory limits to every store, and run the existing runtime behavior suite
against the new backend.
