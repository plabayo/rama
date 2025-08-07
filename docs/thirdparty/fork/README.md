# Fork Information

Rama forks code from several repositories. All these are meant as permanent forks.
Some however are meant to be kept in sync with the originals to make sure we receive
improvements and bugfixes from "upstream". Others are not meant to be kept in sync and serve more
as a distant relative.

## Sync Forks

### hyperium

- h2: <https://github.com/hyperium/h2/tree/41a0f805c833666a68a293641b0979362e411b5f>
  - License:
    - Original: <https://github.com/hyperium/h2/blob/41a0f805c833666a68a293641b0979362e411b5f/LICENSE>
    - Type: MIT
    - Copy: [./licenses/h2](./licenses/h2)
- hyper: <https://github.com/hyperium/hyper/tree/b8affd8a2ee5d77dec0c32050a7234e4f2f3751b>
  - License:
    - Original: <https://github.com/hyperium/hyper/blob/b8affd8a2ee5d77dec0c32050a7234e4f2f3751b/LICENSE>
    - Type: MIT
    - Copy: [./licenses/hyper](./licenses/hyper)
- hyper-util: <https://github.com/hyperium/hyper-util/tree/00911ecd3d57c7ab130d19e6ec4f5dceb54b81b9>
  - License:
    - Original: <https://github.com/hyperium/hyper-util/blob/00911ecd3d57c7ab130d19e6ec4f5dceb54b81b9/LICENSE>
    - Type: MIT
    - Copy: [./licenses/hyper-util](./licenses/hyper-util)
- headers: <https://github.com/hyperium/headers/tree/8db1b786d414cc43e4d77e73b0f7afdcf061be59>
  - License:
    - Original: <https://github.com/hyperium/headers/blob/8db1b786d414cc43e4d77e73b0f7afdcf061be59/LICENSE>
    - Type: MIT
    - Copy: [./licenses/headers](./licenses/headers)

### tower-rs

- <https://github.com/tower-rs/tower/tree/a1c277bc90839820bd8b4c0d8b47d14217977a79>
  - Service / Layer traits
  - Some layers such as timeout, filter, most of util ones
  - License:
    - Original: <https://github.com/tower-rs/tower/blob/a1c277bc90839820bd8b4c0d8b47d14217977a79/LICENSE>
    - Type: MIT
    - Copy: [./licenses/tower](./licenses/tower)
- <https://github.com/tower-rs/tower-http/tree/35a6cb83242b2004352a8a45f97c0c2cb5475254>
  - pretty much everything
  - now kept directly in sync "conceptual logic wise",
    but originally forked as an actual `tower-async` package as found in
    <https://github.com/plabayo/tower-async/tree/57798b7baea8e212197a226a2481fa282591dda4>
  - License:
    - Original: <https://github.com/tower-rs/tower-http/blob/35a6cb83242b2004352a8a45f97c0c2cb5475254/tower-http/LICENSE>
    - Type: MIT
    - Copy: [./licenses/tower-http](./licenses/tower-http)

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
