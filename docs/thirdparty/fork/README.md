# Fork Information

Rama forks code from several repositories. All these are meant as permanent forks.
Some however are meant to be kept in sync with the originals to make sure we receive
improvements and bugfixes from "upstream". Others are not meant to be kept in sync and serve more
as a distant relative.

## Sync Forks

### hyperium

- h2: <https://github.com/hyperium/h2/tree/b9d5397bd751633f676b3164ebe03cb3c4534a75>
  - License:
    - Original: <https://github.com/hyperium/h2/blob/b9d5397bd751633f676b3164ebe03cb3c4534a75/LICENSE>
    - Type: MIT
    - Copy: [./licenses/h2](./licenses/h2)
- hyper: <https://github.com/hyperium/hyper/tree/f9f8f44058745d23fa52abf51b96b61ee7665642>
  - License:
    - Original: <https://github.com/hyperium/hyper/blob/f9f8f44058745d23fa52abf51b96b61ee7665642/LICENSE>
    - Type: MIT
    - Copy: [./licenses/hyper](./licenses/hyper)
- hyper-util: <https://github.com/hyperium/hyper-util/tree/66afc93debef02548c86e8454e6bc01cf4fca280>
  - License:
    - Original: <https://github.com/hyperium/hyper-util/blob/66afc93debef02548c86e8454e6bc01cf4fca280/LICENSE>
    - Type: MIT
    - Copy: [./licenses/hyper-util](./licenses/hyper-util)
- headers: <https://github.com/hyperium/headers/tree/c91416787b689b6ad838d4579556e10fac474d14>
  - License:
    - Original: <https://github.com/hyperium/headers/blob/c91416787b689b6ad838d4579556e10fac474d14/LICENSE>
    - Type: MIT
    - Copy: [./licenses/headers](./licenses/headers)

### tower-rs

- <https://github.com/tower-rs/tower/tree/21e01e977e97a7025ff4beb00b2acd79eadf7285>
  - Service / Layer traits
  - Some layers such as timeout, filter, most of util ones
  - License:
    - Original: <https://github.com/tower-rs/tower/blob/21e01e977e97a7025ff4beb00b2acd79eadf7285/LICENSE>
    - Type: MIT
    - Copy: [./licenses/tower](./licenses/tower)
- <https://github.com/tower-rs/tower-http/tree/7cfdf76723415faf12e3dfdfdf1d1c93a2e31cab>
  - pretty much everything
  - now kept directly in sync "conceptual logic wise",
    but originally forked as an actual `tower-async` package as found in
    <https://github.com/plabayo/tower-async/tree/57798b7baea8e212197a226a2481fa282591dda4>
  - License:
    - Original: <https://github.com/tower-rs/tower-http/blob/7cfdf76723415faf12e3dfdfdf1d1c93a2e31cab/tower-http/LICENSE>
    - Type: MIT
    - Copy: [./licenses/tower-http](./licenses/tower-http)

## External Forks

These are forks made within other code repositories,
but still directly in function of Rama.

- <https://github.com/cloudflare/boring/tree/47c33f64284a905bd1c26dc59c5eec6f5f38bf8b>
  - boring:
    - Fork: <https://github.com/plabayo/rama-boring/tree/7b3fb171483c6250dc607520cd7cc71c85843ee1/boring>
    - License:
      - Original: <https://github.com/cloudflare/boring/blob/47c33f64284a905bd1c26dc59c5eec6f5f38bf8b/boring/LICENSE>
      - Type: Apache 2.0
      - Copy: [./licenses/boring](./licenses/boring)
  - boring-sys:
    - Fork: <https://github.com/plabayo/rama-boring/tree/7b3fb171483c6250dc607520cd7cc71c85843ee1/boring-sys>
    - License:
      - Original: <https://github.com/cloudflare/boring/blob/47c33f64284a905bd1c26dc59c5eec6f5f38bf8b/boring-sys/LICENSE-MIT>
      - Type: MIT
      - Copy: [./licenses/boring-sys](./licenses/boring-sys)
  - tokio-boring:
    - Fork: <https://github.com/plabayo/rama-boring/tree/7b3fb171483c6250dc607520cd7cc71c85843ee1/tokio-boring>
    - License:
      - Original: <https://github.com/cloudflare/boring/blob/47c33f64284a905bd1c26dc59c5eec6f5f38bf8b/tokio-boring/LICENSE-MIT>
      - Type: MIT
      - Copy: [./licenses/tokio-boring](./licenses/tokio-boring)

## Relative Forks

- <https://github.com/tokio-rs/axum/tree/ff031867df7126abe288f13a62c51849c9e544af>
  - IntoResponse Code
  - (Optional)FromRequest/ (Optional)FromRequestParts code
  - Error/BoxError
  - web::extract inspiration + Path (param) deserializion code
  - License:
    - Originals:
      - <https://github.com/tokio-rs/axum/blob/ff031867df7126abe288f13a62c51849c9e544af/axum-core/LICENSE>
      - <https://github.com/tokio-rs/axum/blob/ff031867df7126abe288f13a62c51849c9e544af/axum-extra/LICENSE>
      - <https://github.com/tokio-rs/axum/blob/ff031867df7126abe288f13a62c51849c9e544af/axum/LICENSE>
    - Type: MIT
    - Copies:
      - [./licenses/axum-core](./licenses/axum-core)
      - [./licenses/axum-extra](./licenses/axum-extra)
      - [./licenses/axum](./licenses/axum)
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
- <https://github.com/snapview/tungstenite-rs/tree/3ffeb33e29824deae10d86f7edff2ed4de22e91b>
  - minor improvements, and adapted+scoped for rama use
  - License:
    - Original: <https://github.com/snapview/tungstenite-rs/blob/3ffeb33e29824deae10d86f7edff2ed4de22e91b/LICENSE-MIT>
    - Type: MIT
    - Copy: [./licenses/tungstenite-rs](./licenses/tungstenite-rs)
- <https://github.com/snapview/tokio-tungstenite/tree/25b544e43fe979bca951f085ee1b66e9c1cc3113>
  - minor improvements, and adapted+scoped for rama use
  - License:
    - Original: <https://github.com/snapview/tokio-tungstenite/blob/25b544e43fe979bca951f085ee1b66e9c1cc3113/LICENSE>
    - Type: MIT
    - Copy: [./licenses/tokio-tungstenite](./licenses/tokio-tungstenite)
- <https://github.com/Michael-F-Bryan/include_dir/tree/d742c6fffce99ee89da91b934e7ce6fb2a82680c>
  - it was more or less unmaintained and missing features due to being behind in rust versions
  - License:
    - Original: <https://github.com/Michael-F-Bryan/include_dir/blob/d742c6fffce99ee89da91b934e7ce6fb2a82680c/LICENSE>
    - Type: MIT
    - Copy: [./licenses/include_dir](./licenses/include_dir)
