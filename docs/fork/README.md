# Fork Information

Rama forks code from several repositories. All these are meant as permanent forks.
Some however are meant to be kept in sync with the originals to make sure we receive
improvements and bugfixes from "upstream". Others are not meant to be kept in sync and serve more
as a distant relative.

## Sync Forks

### hyperium

- <https://github.com/hyperium/h2/tree/adab70fd9f9e5ce3099d274a4b548a27bfdee4dc>
  - License:
    - Original: <https://github.com/hyperium/h2/blob/adab70fd9f9e5ce3099d274a4b548a27bfdee4dc/LICENSE>
    - Type: MIT
    - Copy: [./licenses/h2](./licenses/h2)
- <https://github.com/hyperium/hyper/tree/v1.6.0>
  - License:
    - Original: <https://github.com/hyperium/hyper/blob/v1.6.0/LICENSE>
    - Type: MIT
    - Copy: [./licenses/hyper](./licenses/hyper)
- <https://github.com/hyperium/hyper-util/tree/e74ab7888638e768de17c47ed5f20c8b623a308f>
  - License:
    - Original: <https://github.com/hyperium/hyper-util/blob/e74ab7888638e768de17c47ed5f20c8b623a308f/LICENSE>
    - Type: MIT
    - Copy: [./licenses/hyper-util](./licenses/hyper-util)

### tower-rs

- <https://github.com/tower-rs/tower/tree/abb375d08cf0ba34c1fe76f66f1aba3dc4341013>
  - Service / Layer traits
  - Some layers such as timeout, filter, most of util ones
  - License:
    - Original: <https://github.com/tower-rs/tower/blob/abb375d08cf0ba34c1fe76f66f1aba3dc4341013/LICENSE>
    - Type: MIT
    - Copy: [./licenses/tower](./licenses/tower)
- <https://github.com/tower-rs/tower-http/tree/6c20928e50a7462cd4abfe7ad404dc03c8445de9>
  - pretty much everything
  - now kept directly in sync "conceptual logic wise",
    but originally forked as an actual `tower-async` package as found in
    <https://github.com/plabayo/tower-async/tree/57798b7baea8e212197a226a2481fa282591dda4>
  - License:
    - Original: <https://github.com/tower-rs/tower-http/blob/6c20928e50a7462cd4abfe7ad404dc03c8445de9/tower-http/LICENSE>
    - Type: MIT
    - Copy: [./licenses/tower-http](./licenses/tower-http)

## Relative Forks

- <https://github.com/tokio-rs/axum/tree/9c9cbb5c5f72452825388d63db4f1e36c0d9b3aa>
  - IntoResponse Code
  - (Optional)FromRequest/ (Optional)FromRequestParts code
  - Error/BoxError
  - web::extract inspiration + Path (param) deserializion code
  - License:
    - Originals:
      - <https://github.com/tokio-rs/axum/blob/9c9cbb5c5f72452825388d63db4f1e36c0d9b3aa/axum-core/LICENSE>
      - <https://github.com/tokio-rs/axum/blob/9c9cbb5c5f72452825388d63db4f1e36c0d9b3aa/axum-extra/LICENSE>
      - <https://github.com/tokio-rs/axum/blob/9c9cbb5c5f72452825388d63db4f1e36c0d9b3aa/axum/LICENSE>
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
