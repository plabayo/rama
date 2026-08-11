# Embedded engine notices

`rama-js-engine.wasm` is produced with
[@bytecodealliance/componentize-js 0.22.0](https://github.com/bytecodealliance/ComponentizeJS),
including its StarlingMonkey/SpiderMonkey embedding. ComponentizeJS is licensed
under Apache-2.0 with the LLVM exception. Its corresponding source and license
are available from the linked release and the pinned package in
`package-lock.json`.

Rama's boundary and build-integration code in `runtime.js`,
`script-evaluator.cpp`, `rama-engine.cmake`, and `build.mjs` is licensed under
Rama's `MIT OR Apache-2.0` terms.
