# StarlingMonkey engine component

This directory builds the private JavaScript engine component used by
`rama-js`. Normal Cargo builds consume the checked-in
`rama-js-engine.wasm`; they do not require Node.js or rebuild the component.

Rebuild it with:

```sh
npm install --ignore-scripts
npm run build
```

The build is pinned by `package-lock.json` and exact ComponentizeJS and
StarlingMonkey revisions in `build.mjs`. The build script downloads those
sources and their toolchain dependencies into the ignored `.build` directory,
then injects `script-evaluator.cpp` as a custom StarlingMonkey builtin. It uses
ComponentizeJS 0.22.0 without Weval AOT and disables every ambient WASI
feature. The guest can only call interfaces explicitly linked by its Rust
host.

The native builtin compiles each dynamically supplied source as a classic
SpiderMonkey Script in the runtime's persistent content realm. `runtime.js`
captures its two entry points during component initialization and removes
their temporary global properties before application code can run. This gives
separate loads the same global lexical environment and declaration semantics
as browser scripts without exposing the privileged evaluator to loaded code.

ComponentizeJS snapshots the initialized engine with Wizer. Consecutive builds
are not byte-identical, so verify a rebuilt artifact through its WIT interface,
metadata, size, and the Rust integration tests rather than its checksum.

The resulting component exports persistent evaluation and registration operations. A
single generic host import carries encoded values between JavaScript and Rust;
the WIT interface does not need to change when a new function, value,
namespace, or host-object member is registered.

## Runtime contract

The Rust integration tests verify persistent evaluation, values, host
functions, namespaces, mutable host objects, getters, setters, methods, and
receiver validation. They also verify three containment properties:

- Wasmtime fuel interrupts a non-terminating script;
- the Wasmtime store memory limit rejects excessive guest memory growth;
- parsing 100,000-level parenthesis, binary, unary, and member chains cannot
  overflow the host process's native stack.

The component imports only the generic Rama host-call interface declared in
`engine.wit`. Rust applies fuel, epoch deadlines, a Wasm stack limit, and a
store memory limit around the component; no engine type crosses the private
`rama-js::engine` boundary.

Desktop, server, and Android targets use Wasmtime's Winch compiler. iOS uses
the Pulley interpreter so the crate does not depend on runtime executable-memory
permission there; this is slower but keeps the same component and Rust API.
