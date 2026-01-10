# Fork Information

Rama forks code from several repositories. All these are meant as permanent forks.
Some however are meant to be kept in sync with the originals to make sure we receive
improvements and bugfixes from "upstream". Others are not meant to be kept in sync and serve more
as a distant relative.

## Sync Forks

### hyperium

- h2: <https://github.com/hyperium/h2/tree/e38678b1e2c465965f3ce5ec8d3040458415b376>
  - License:
    - Original: <https://github.com/hyperium/h2/blob/e38678b1e2c465965f3ce5ec8d3040458415b376/LICENSE>
    - Type: MIT
    - Copy: [./licenses/h2](./licenses/h2)
- hyper: <https://github.com/hyperium/hyper/tree/32b76f4742df62f4419b9f87ef464bc0b1c21e72>
  - License:
    - Original: <https://github.com/hyperium/hyper/blob/32b76f4742df62f4419b9f87ef464bc0b1c21e72/LICENSE>
    - Type: MIT
    - Copy: [./licenses/hyper](./licenses/hyper)
- hyper-util: <https://github.com/hyperium/hyper-util/tree/66afc93debef02548c86e8454e6bc01cf4fca280>
  - License:
    - Original: <https://github.com/hyperium/hyper-util/blob/66afc93debef02548c86e8454e6bc01cf4fca280/LICENSE>
    - Type: MIT
    - Copy: [./licenses/hyper-util](./licenses/hyper-util)
- headers: <https://github.com/hyperium/headers/tree/de0b1a1e97d20f3667a346c4d5b5973d92ab58f9>
  - License:
    - Original: <https://github.com/hyperium/headers/blob/de0b1a1e97d20f3667a346c4d5b5973d92ab58f9/LICENSE>
    - Type: MIT
    - Copy: [./licenses/headers](./licenses/headers)
- tonic: <https://github.com/hyperium/tonic/tree/88a448a2fdedf06340deac645a061120a2612537>
  - License:
    - Original: <https://github.com/hyperium/tonic/blob/88a448a2fdedf06340deac645a061120a2612537/LICENSE>
    - Type: MIT
    - Copy: [./licenses/tonic](./licenses/tonic)

### tower-rs

- <https://github.com/tower-rs/tower/tree/1992ebd196467deffe193d5a073db655492ce168>
  - Service / Layer traits
  - Some layers such as timeout, filter, most of util ones
  - License:
    - Original: <https://github.com/tower-rs/tower/blob/1992ebd196467deffe193d5a073db655492ce168/LICENSE>
    - Type: MIT
    - Copy: [./licenses/tower](./licenses/tower)
- <https://github.com/tower-rs/tower-http/tree/1a55dd83ab9e2268453018877a74ce2171f4701a>
  - pretty much everything
  - now kept directly in sync "conceptual logic wise",
    but originally forked as an actual `tower-async` package as found in
    <https://github.com/plabayo/tower-async/tree/57798b7baea8e212197a226a2481fa282591dda4>
  - License:
    - Original: <https://github.com/tower-rs/tower-http/blob/1a55dd83ab9e2268453018877a74ce2171f4701a/tower-http/LICENSE>
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
- <https://github.com/snapview/tungstenite-rs/tree/2d4abe8dba23b283c1a3d2f4f4937c2f9a8d91e7>
  - minor improvements, and adapted+scoped for rama use
  - License:
    - Original: <https://github.com/snapview/tungstenite-rs/blob/2d4abe8dba23b283c1a3d2f4f4937c2f9a8d91e7/LICENSE-MIT>
    - Type: MIT
    - Copy: [./licenses/tungstenite-rs](./licenses/tungstenite-rs)
- <https://github.com/snapview/tokio-tungstenite/tree/35d110c24c9d030d1608ec964d70c789dfb27452>
  - minor improvements, and adapted+scoped for rama use
  - License:
    - Original: <https://github.com/snapview/tokio-tungstenite/blob/35d110c24c9d030d1608ec964d70c789dfb27452/LICENSE>
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
