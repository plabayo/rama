# Fork Information

Rama forks code from several repositories. All these are meant as permanent forks.
Some however are meant to be kept in sync with the originals to make sure we receive
improvements and bugfixes from "upstream". Others are not meant to be kept in sync and serve more
as a distant relative.

## Sync Forks

### hyperium

- h2: <https://github.com/hyperium/h2/tree/d361b75762868f51fb85e39e0a6c3c79958b42ea>
  - License:
    - Original: <https://github.com/hyperium/h2/blob/d361b75762868f51fb85e39e0a6c3c79958b42ea/LICENSE>
    - Type: MIT
    - Copy: [./licenses/h2](./licenses/h2)
- hyper: <https://github.com/hyperium/hyper/tree/54e8511d5fb25e7db3fd766a403826d4946af5b6>
  - License:
    - Original: <https://github.com/hyperium/hyper/blob/54e8511d5fb25e7db3fd766a403826d4946af5b6/LICENSE>
    - Type: MIT
    - Copy: [./licenses/hyper](./licenses/hyper)
- hyper-util: <https://github.com/hyperium/hyper-util/tree/66afc93debef02548c86e8454e6bc01cf4fca280>
  - License:
    - Original: <https://github.com/hyperium/hyper-util/blob/66afc93debef02548c86e8454e6bc01cf4fca280/LICENSE>
    - Type: MIT
    - Copy: [./licenses/hyper-util](./licenses/hyper-util)
- headers: <https://github.com/hyperium/headers/tree/e900f04aa329d3211c226dc2333fe37ec143d680>
  - License:
    - Original: <https://github.com/hyperium/headers/blob/e900f04aa329d3211c226dc2333fe37ec143d680/LICENSE>
    - Type: MIT
    - Copy: [./licenses/headers](./licenses/headers)
- tonic: <https://github.com/hyperium/tonic/tree/a88b919bd872f20e29d40aa05a88b19574037358>
  - License:
    - Original: <https://github.com/hyperium/tonic/blob/a88b919bd872f20e29d40aa05a88b19574037358/LICENSE>
    - Type: MIT
    - Copy: [./licenses/tonic](./licenses/tonic)

### tower-rs

- <https://github.com/tower-rs/tower/tree/251296dc54a044383dffd16d2179b443e2615672>
  - Service / Layer traits
  - Some layers such as timeout, filter, most of util ones
  - License:
    - Original: <https://github.com/tower-rs/tower/blob/251296dc54a044383dffd16d2179b443e2615672/LICENSE>
    - Type: MIT
    - Copy: [./licenses/tower](./licenses/tower)
- <https://github.com/tower-rs/tower-http/tree/b5366318c0661693e15de6d75e15a2f7924b5036>
  - pretty much everything
  - now kept directly in sync "conceptual logic wise",
    but originally forked as an actual `tower-async` package as found in
    <https://github.com/plabayo/tower-async/tree/57798b7baea8e212197a226a2481fa282591dda4>
  - License:
    - Original: <https://github.com/tower-rs/tower-http/blob/b5366318c0661693e15de6d75e15a2f7924b5036/tower-http/LICENSE>
    - Type: MIT
    - Copy: [./licenses/tower-http](./licenses/tower-http)

## External Forks

These are forks made within other code repositories,
but still directly in function of Rama.

- <https://github.com/cloudflare/boring/tree/e71b24328f1cd787f64036d8208a4470ae58e200>
  - boring:
    - Fork: <https://github.com/plabayo/rama-boring/tree/master/boring>
    - License:
      - Original: <https://github.com/cloudflare/boring/blob/e71b24328f1cd787f64036d8208a4470ae58e200/boring/LICENSE>
      - Type: Apache 2.0
      - Copy: [./licenses/boring](./licenses/boring)
  - boring-sys:
    - Fork: <https://github.com/plabayo/rama-boring/tree/master/boring-sys>
    - License:
      - Original: <https://github.com/cloudflare/boring/blob/e71b24328f1cd787f64036d8208a4470ae58e200/boring-sys/LICENSE-MIT>
      - Type: MIT
      - Copy: [./licenses/boring-sys](./licenses/boring-sys)
  - tokio-boring:
    - Fork: <https://github.com/plabayo/rama-boring/tree/master/tokio-boring>
    - License:
      - Original: <https://github.com/cloudflare/boring/blob/e71b24328f1cd787f64036d8208a4470ae58e200/tokio-boring/LICENSE-MIT>
      - Type: MIT
      - Copy: [./licenses/tokio-boring](./licenses/tokio-boring)

## Permanent Forks

These are permanent forks that we have taken into the rama ecosystem so we
can shape them to fit naturally into the rest of the codebase. They will
not be kept in sync with upstream — they are now part of `rama`.

- <https://github.com/JonahLund/vy/tree/1280174f54774c24fa478475af17fd7f5814c91a>
  - Forked into [`rama-http-macros`](https://github.com/plabayo/rama/tree/main/rama-http-macros)
    (the proc-macros) and into private modules under
    [`rama-http/src/protocols/html`](https://github.com/plabayo/rama/tree/main/rama-http/src/protocols/html)
    (the `IntoHtml` trait, escaping, scalar / numeric / tuple impls).
  - Reasons for forking:
    - Better integration with the rest of the rama ecosystem — in
      particular dropping vy's bespoke `Either*` types in favour of the
      already-existing [`rama_core::combinators::Either`] family.
    - Adding a `custom!` macro for runtime tag names (web components).
    - Letting the macro output (`HtmlBuf`) implement `IntoResponse`
      directly so handler code can return HTML without any extra wrapper.
    - Dropping `no_std` support and `itoap` / `ryu` deps in favour of the
      standard library — this crate is `std`-only anyway via `rama-http`.
  - License:
    - Original: <https://github.com/JonahLund/vy/blob/1280174f54774c24fa478475af17fd7f5814c91a/LICENSE>
    - Type: MIT
    - Copy: [./licenses/vy](./licenses/vy)
- <https://github.com/cloudflare/lol-html/tree/02f139c4437b2da666a50d32e11d9158cbe0a393>
  - Forked into private modules under
    [`rama-http/src/protocols/html`](https://github.com/plabayo/rama/tree/main/rama-http/src/protocols/html)
    as the foundation for rama's native streaming HTML parsing and
    rewriting (the CSS selector engine, the HTML tokenizer, and the
    selector-driven rewriter).
  - Reasons for forking:
    - A redesigned, ergonomic API: a visitor trait (your struct *is* the
      shared state) plus a state-threaded closure escape hatch, replacing
      lol-html's boxed-closure handlers that force `Rc<RefCell>` /
      `Arc<Mutex>` for shared state and a duplicated `send::` module.
    - Integration with the rest of the rama ecosystem — `IntoHtml` for
      building replacement content, a native `Body` / `Layer` / `Service`
      for streaming responses, and rama's error and string utilities.
    - Fewer dependencies: the CSS selector parser is hand-rolled for the
      streaming-safe subset, dropping `cssparser` and Servo's `selectors`.
  - License:
    - Original: <https://github.com/cloudflare/lol-html/blob/02f139c4437b2da666a50d32e11d9158cbe0a393/LICENSE>
    - Type: BSD-3-Clause
    - Copy: [./licenses/lol-html](./licenses/lol-html)

[`rama_core::combinators::Either`]: https://docs.rs/rama-core/latest/rama_core/combinators/enum.Either.html

## Relative Forks

- <https://github.com/tokio-rs/axum/tree/061666a1116d853f9ca838fb2d0c668614a9f535>
  - IntoResponse Code
  - (Optional)FromRequest/ (Optional)FromRequestParts code
  - Error/BoxError
  - web::extract inspiration + Path (param) deserializion code
  - License:
    - Original: <https://github.com/tokio-rs/axum/blob/061666a1116d853f9ca838fb2d0c668614a9f535/LICENSE>
    - Type: MIT
    - Copy: [./licenses/axum](./licenses/axum)
- <https://github.com/dtolnay/paste/tree/6a302522990cbfd9de4e0c61d91854622f7b2999>
  - it was no longer maintained, so we're taking it over for ourselves
  - License:
    - Original: <https://github.com/dtolnay/paste/blob/6a302522990cbfd9de4e0c61d91854622f7b2999/LICENSE-MIT>
    - Type: MIT
    - Copy: [./licenses/paste](./licenses/paste)
- <https://github.com/SimonSapin/rust-utf8/tree/218fea2b57b0e4c3de9fa17a376fcc4a4c0d08f3>
  - it was no longer maintained, so we're taking it over for ourselves
  - License:
    - Original: <https://github.com/SimonSapin/rust-utf8/blob/218fea2b57b0e4c3de9fa17a376fcc4a4c0d08f3/LICENSE-MIT>
    - Type: MIT
    - Copy: [./licenses/rust-utf8](./licenses/rust-utf8)
- <https://github.com/snapview/tungstenite-rs/tree/16ca0fc87e0a39f66548e24a08ab0961e592324f>
  - minor improvements, and adapted+scoped for rama use
  - License:
    - Original: <https://github.com/snapview/tungstenite-rs/blob/16ca0fc87e0a39f66548e24a08ab0961e592324f/LICENSE-MIT>
    - Type: MIT
    - Copy: [./licenses/tungstenite-rs](./licenses/tungstenite-rs)
- <https://github.com/snapview/tokio-tungstenite/tree/753ca72690919485a1aa1f0f69a336b1152fb0ae>
  - minor improvements, and adapted+scoped for rama use
  - License:
    - Original: <https://github.com/snapview/tokio-tungstenite/blob/753ca72690919485a1aa1f0f69a336b1152fb0ae/LICENSE>
    - Type: MIT
    - Copy: [./licenses/tokio-tungstenite](./licenses/tokio-tungstenite)
- <https://github.com/Michael-F-Bryan/include_dir/tree/d742c6fffce99ee89da91b934e7ce6fb2a82680c>
  - it was more or less unmaintained and missing features due to being behind in rust versions
  - License:
    - Original: <https://github.com/Michael-F-Bryan/include_dir/blob/d742c6fffce99ee89da91b934e7ce6fb2a82680c/LICENSE>
    - Type: MIT
    - Copy: [./licenses/include_dir](./licenses/include_dir)

## Small Lib Forks

These are forks initially because the libraries are too simple or small
to really warrant a permanent entry in our dep tree, yet are useful enough
to give a foundation for similar functionality that we want.

Over time they might diverge from the original as it grows with the rest
of the rama ecosystem.

- <https://github.com/cloudhead/nonempty/tree/95d5cb131262b12bbe55366cbbd48096f9a05493>
  - Integrated in `rama::utils::collections`
  - License:
    - Original: <https://github.com/cloudhead/nonempty/blob/95d5cb131262b12bbe55366cbbd48096f9a05493/LICENSE>
    - Type: MIT
    - Copy: [./licenses/nonempty](./licenses/nonempty)
- <https://github.com/thomcc/arcstr/tree/faa7692b0d6662bb177b3aefa80a6a13f897554d>
  - Integrated in `rama::utils::str::arcstr`
  - License:
    - Original: <https://github.com/thomcc/arcstr/blob/faa7692b0d6662bb177b3aefa80a6a13f897554d/LICENSE-MIT>
    - Type: MIT
    - Copy: [./licenses/arcstr](./licenses/arcstr)
- <https://github.com/rustls/rustls-native-certs/tree/9d1f11e5da42f061c9a5aebbcde48a1b843afff2>
  - Forked into [`rama-crypto::native_certs`](https://github.com/plabayo/rama/tree/main/rama-crypto/src/native_certs)
    as rama's tls-implementation agnostic native trust store loader, used by
    both the rustls and boring client connectors.
  - Reasons for forking:
    - Reshape the public surface around rama's `pki_types` re-export, error and
      tracing conventions, and add a cached `shared_native_trust_anchors()` with
      a bundled webpki root fallback.
    - Fold in the pending upstream permission-skip fix
      (<https://github.com/rustls/rustls-native-certs/pull/228>).
    - Broaden the Windows reader to both the current-user and local-machine
      ROOT + CA stores (carried over from rama's previous boring-only logic).
  - License:
    - Original: <https://github.com/rustls/rustls-native-certs/blob/9d1f11e5da42f061c9a5aebbcde48a1b843afff2/LICENSE-MIT>
    - Type: MIT (offered as Apache-2.0 OR ISC OR MIT)
    - Copy: [./licenses/rustls-native-certs](./licenses/rustls-native-certs)

## Vendored Test Corpora

Third-party test data vendored verbatim and used only by the test suite
(not shipped in any published crate).

- <https://github.com/html5lib/html5lib-tests/tree/9fb614afaa42ce8787840f057b32084308e76549>
  - The `tokenizer/*.test` data, vendored under
    [`rama-http/tests/html5lib-tokenizer`](https://github.com/plabayo/rama/tree/main/rama-http/tests/html5lib-tokenizer)
    and used to exercise the HTML tokenizer's identity property over a large
    real-world corpus.
  - License:
    - Original: <https://github.com/html5lib/html5lib-tests/blob/9fb614afaa42ce8787840f057b32084308e76549/LICENSE>
    - Type: MIT
    - Copy: [./licenses/html5lib-tests](./licenses/html5lib-tests)
