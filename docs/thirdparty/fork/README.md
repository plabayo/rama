# Fork Information

Rama forks code from several repositories. All these are meant as permanent forks.
Some however are meant to be kept in sync with the originals to make sure we receive
improvements and bugfixes from "upstream". Others are not meant to be kept in sync and serve more
as a distant relative.

## Sync Forks

### hyperium

- <https://github.com/hyperium/h2/tree/e4ed3502f111302ba601799bf70b4aecd37466fd>
  - License:
    - Original: <https://github.com/hyperium/h2/blob/e4ed3502f111302ba601799bf70b4aecd37466fd/LICENSE>
    - Type: MIT
    - Copy: [./licenses/h2](./licenses/h2)
- <https://github.com/hyperium/hyper/tree/436cadd1ac08a9508a46f550e03281db9f2fee97>
  - License:
    - Original: <https://github.com/hyperium/hyper/blob/436cadd1ac08a9508a46f550e03281db9f2fee97/LICENSE>
    - Type: MIT
    - Copy: [./licenses/hyper](./licenses/hyper)
- <https://github.com/hyperium/hyper-util/tree/e74ab7888638e768de17c47ed5f20c8b623a308f>
  - License:
    - Original: <https://github.com/hyperium/hyper-util/blob/e74ab7888638e768de17c47ed5f20c8b623a308f/LICENSE>
    - Type: MIT
    - Copy: [./licenses/hyper-util](./licenses/hyper-util)
- <https://github.com/hyperium/headers/tree/d425d3ca90261683150eda8292c3f14f0d3db3ee>
  - License:
    - Original: <https://github.com/hyperium/headers/blob/d425d3ca90261683150eda8292c3f14f0d3db3ee/LICENSE>
    - Type: MIT
    - Copy: [./licenses/headers](./licenses/headers)

### tower-rs

- <https://github.com/tower-rs/tower/tree/81658e65ad6dbddaf4fa7d0f19361e4c56d85c80>
  - Service / Layer traits
  - Some layers such as timeout, filter, most of util ones
  - License:
    - Original: <https://github.com/tower-rs/tower/blob/81658e65ad6dbddaf4fa7d0f19361e4c56d85c80/LICENSE>
    - Type: MIT
    - Copy: [./licenses/tower](./licenses/tower)
- <https://github.com/tower-rs/tower-http/tree/cf3046f2266230227d268616792ca170fa9d73d3>
  - pretty much everything
  - now kept directly in sync "conceptual logic wise",
    but originally forked as an actual `tower-async` package as found in
    <https://github.com/plabayo/tower-async/tree/57798b7baea8e212197a226a2481fa282591dda4>
  - License:
    - Original: <https://github.com/tower-rs/tower-http/blob/cf3046f2266230227d268616792ca170fa9d73d3/tower-http/LICENSE>
    - Type: MIT
    - Copy: [./licenses/tower-http](./licenses/tower-http)

## Relative Forks

- <https://github.com/tokio-rs/axum/tree/7d1dbeb3af6c709b20708cbfcf0a29bcbcc40692>
  - IntoResponse Code
  - (Optional)FromRequest/ (Optional)FromRequestParts code
  - Error/BoxError
  - web::extract inspiration + Path (param) deserializion code
  - License:
    - Originals:
      - <https://github.com/tokio-rs/axum/blob/7d1dbeb3af6c709b20708cbfcf0a29bcbcc40692/axum-core/LICENSE>
      - <https://github.com/tokio-rs/axum/blob/7d1dbeb3af6c709b20708cbfcf0a29bcbcc40692/axum-extra/LICENSE>
      - <https://github.com/tokio-rs/axum/blob/7d1dbeb3af6c709b20708cbfcf0a29bcbcc40692/axum/LICENSE>
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
