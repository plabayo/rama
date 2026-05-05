# Fork Information

Rama forks code from several repositories. All these are meant as permanent forks.
Some however are meant to be kept in sync with the originals to make sure we receive
improvements and bugfixes from "upstream". Others are not meant to be kept in sync and serve more
as a distant relative.

## Sync Forks

### hyperium

- h2: <https://github.com/hyperium/h2/tree/dbc204e57e0f96ea25d023c82d8a16340675b271>
  - License:
    - Original: <https://github.com/hyperium/h2/blob/dbc204e57e0f96ea25d023c82d8a16340675b271/LICENSE>
    - Type: MIT
    - Copy: [./licenses/h2](./licenses/h2)
- hyper: <https://github.com/hyperium/hyper/tree/0d6c7d5469baa09e2fb127ee3758a79b3271a4f0>
  - License:
    - Original: <https://github.com/hyperium/hyper/blob/0d6c7d5469baa09e2fb127ee3758a79b3271a4f0/LICENSE>
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
- <https://github.com/tower-rs/tower-http/tree/0d608fdbb0e62fcaa9d3e7b5205207337f223831>
  - pretty much everything
  - now kept directly in sync "conceptual logic wise",
    but originally forked as an actual `tower-async` package as found in
    <https://github.com/plabayo/tower-async/tree/57798b7baea8e212197a226a2481fa282591dda4>
  - License:
    - Original: <https://github.com/tower-rs/tower-http/blob/0d608fdbb0e62fcaa9d3e7b5205207337f223831/tower-http/LICENSE>
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
    [`rama-http/src/html`](https://github.com/plabayo/rama/tree/main/rama-http/src/html)
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
- <https://github.com/snapview/tungstenite-rs/tree/59bee6404f3c126af71e33b3cf02627df0cae50a>
  - minor improvements, and adapted+scoped for rama use
  - License:
    - Original: <https://github.com/snapview/tungstenite-rs/blob/59bee6404f3c126af71e33b3cf02627df0cae50a/LICENSE-MIT>
    - Type: MIT
    - Copy: [./licenses/tungstenite-rs](./licenses/tungstenite-rs)
- <https://github.com/snapview/tokio-tungstenite/tree/38d04656fe28be0000920201d6a49bf5ec3d537b>
  - minor improvements, and adapted+scoped for rama use
  - License:
    - Original: <https://github.com/snapview/tokio-tungstenite/blob/38d04656fe28be0000920201d6a49bf5ec3d537b/LICENSE>
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
