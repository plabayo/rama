# Embedded engine notices

`rama-js-engine.wasm` contains these third-party works:

- [ComponentizeJS](https://github.com/bytecodealliance/ComponentizeJS/tree/4b8d6eb465b5cded6b97c67aaf6fdaa8b62001e2)
  revision `4b8d6eb465b5cded6b97c67aaf6fdaa8b62001e2`, Apache-2.0 with
  the LLVM exception;
- [StarlingMonkey](https://github.com/bytecodealliance/StarlingMonkey/tree/9dda8ba7fcda2e17c6795d402f0478cf4c1f7f37)
  revision `9dda8ba7fcda2e17c6795d402f0478cf4c1f7f37`, Apache-2.0 with
  the LLVM exception;
- [Mozilla SpiderMonkey](https://github.com/bytecodealliance/firefox/tree/9dab3d6f643e926a340c391ea30968e940390dec)
  revision `9dab3d6f643e926a340c391ea30968e940390dec` (release tag
  `FIREFOX_147_0_4_RELEASE_STARLING`), Mozilla Public License 2.0.

The links above identify the exact corresponding sources. License texts are
available as `LICENSE` files at those revisions; the MPL 2.0 text is also at
<https://www.mozilla.org/MPL/2.0/>. Downloaded release archives are verified
against their publishers' SHA-256 digests by `build.mjs` before use.

Rama's boundary and build-integration code in `runtime.js`,
`script-evaluator.cpp`, `rama-engine.cmake`, and `build.mjs` is licensed under
Rama's `MIT OR Apache-2.0` terms.
