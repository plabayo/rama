# Fork Information

Rama forks code from several repositories. All these are meant as permanent forks.
Some however are meant to be kept in sync with the originals to make sure we receive
improvements and bugfixes from "upstream". Others are not meant to be kept in sync and serve more
as a distant relative.

## Sync Forks

- <https://github.com/tower-rs/tower/tree/39adf5c509a1b2141f679654d8317524ca96b58b>
  - Service / Layer traits
  - ServiceBuilder (note that we keep ours more minimal on purpose)
  - Some layers such as timeout, filter, most of util ones
- <https://github.com/tower-rs/tower-http/tree/bb0d1b2b2a8f75d283d9c94f327d8e4aa214381e>
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