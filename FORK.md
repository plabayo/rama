# Fork Information

Rama forks code from several repositories. All these are meant as permanent forks.
Some however are meant to be kept in sync with the originals to make sure we receive
improvements and bugfixes from "upstream". Others are not meant to be kept in sync and serve more
as a distant relative.

## Sync Forks

### hyperium

- <https://github.com/hyperium/h2/tree/v0.4.7>
- <https://github.com/hyperium/hyper/tree/v1.5.2>
- <https://github.com/hyperium/hyper-util/tree/v0.1.10>

### tower-r

- <https://github.com/tower-rs/tower/tree/71551010acff922c5b51c280e49a15ad2d33df61>
  - Service / Layer traits
  - Some layers such as timeout, filter, most of util ones
- <https://github.com/tower-rs/tower-http/tree/aeca2626d4b5836d2fe66877ba1b857db9851815>
  - pretty much everything
  - now kept directly in sync "conceptual logic wise",
    but originally forked as an actual `tower-async` package as found in
    <https://github.com/plabayo/tower-async/tree/57798b7baea8e212197a226a2481fa282591dda4>

## Relative Forks

- <https://github.com/tokio-rs/axum/tree/3fda093806d43d64dd70cda0274cd3d73d29b6c7>
  - FromRef (proc macro), we use it in a different form using `std::convert::AsRef` (to avoid clones);
  - IntoResponse Code
  - FromRequest/ FromRequestParts code
  - Error/BoxError
  - web::extract inspiration + Path (param) deserializion code
