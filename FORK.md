# Fork Information

Rama forks code from several repositories. All these are meant as permanent forks.
Some however are meant to be kept in sync with the originals to make sure we receive
improvements and bugfixes from "upstream". Others are not meant to be kept in sync and serve more
as a distant relative.

## Sync Forks

### hyperium

- <https://github.com/hyperium/h2/tree/adab70fd9f9e5ce3099d274a4b548a27bfdee4dc>
- <https://github.com/hyperium/hyper/tree/v1.6.0>
- <https://github.com/hyperium/hyper-util/tree/v0.1.10>

### tower-rs

- <https://github.com/tower-rs/tower/tree/954e4c7e8d889b3b77e68886b2c78d5bb45b74fb>
  - Service / Layer traits
  - Some layers such as timeout, filter, most of util ones
- <https://github.com/tower-rs/tower-http/tree/6c20928e50a7462cd4abfe7ad404dc03c8445de9>
  - pretty much everything
  - now kept directly in sync "conceptual logic wise",
    but originally forked as an actual `tower-async` package as found in
    <https://github.com/plabayo/tower-async/tree/57798b7baea8e212197a226a2481fa282591dda4>

## Relative Forks
- <https://github.com/tokio-rs/axum/tree/9c9cbb5c5f72452825388d63db4f1e36c0d9b3aa>
  - IntoResponse Code
  - (Optional)FromRequest/ (Optional)FromRequestParts code
  - Error/BoxError
  - web::extract inspiration + Path (param) deserializion code
- <https://github.com/dtolnay/paste/tree/6a302522990cbfd9de4e0c61d91854622f7b2999>
  - it was no longer maintained, so we're taking it over for ourselves
