![rama banner](docs/img/banner.png)

[![Crates.io][crates-badge]][crates-url]
[![Docs.rs][docs-badge]][docs-url]
[![Business Source License][license-badge]][license-url]
[![Build Status][actions-badge]][actions-url]

[crates-badge]: https://img.shields.io/crates/v/rama.svg
[crates-url]: https://crates.io/crates/rama
[docs-badge]: https://img.shields.io/docsrs/rama/latest
[docs-url]: https://docs.rs/rama/latest/rama/index.html
[license-badge]: https://img.shields.io/badge/license-BSL-blue.svg
[license-url]: https://github.com/plabayo/rama/blob/master/LICENSE
[actions-badge]: https://github.com/plabayo/rama/workflows/CI/badge.svg
[actions-url]: https://github.com/plabayo/rama/actions?query=workflow%3ACI+branch%main

> rama is early work in progress, use at your own risk.
>
> Not everything that exists is documented and not everything that is documented is implemented.

## Nightly

`rama` is currently only available on nightly rust,
this is because it uses the `async_trait` feature,
which is currently only available on nightly rust.

We expect to be able to switch back to stable rust once `async_trait` is available on stable rust,
which should be by the end of 2023.

See <https://blog.rust-lang.org/inside-rust/2023/05/03/stabilizing-async-fn-in-trait.html> for more information.

## Contributing

:balloon: Thanks for your help improving the project! We are so happy to have
you! We have a [contributing guide][contributing] to help you get involved in the
`rama` project.

Should you want to contribure this project but you do not yet know how to program in Rust, you could start learning Rust with as goal to contribute as soon as possible to `rama` by using "[the Rust 101 Learning Guide](https://rust-lang.guide/)" as your study companion. Glen can also be hired as a mentor or teacher to give you paid 1-on-1 lessons and other similar consultancy services. You can find his contact details at <https://www.glendc.com/>.

## License

This project is licensed under the [BSL license][license].

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in `rama` by you, shall be licensed as BSL, without any
additional terms or conditions.

[contributing]: https://github.com/plabayo/rama/blob/main/CONTRIBUTING.md
[license]: https://github.com/plabayo/rama/blob/main/rama/LICENSE

## Sponsors

Support this project by becoming a [sponsor](https://github.com/sponsors/plabayo).

Sponsors help us continue to maintain and improve `rama`, as well as other
Free and Open Source (FOSS) technology. It also helps us to create
educational content such as <https://github.com/plabayo/learn-rust-101>.

Sponsors receive perks and depending on your regular contribution it also
allows you to rely on us for support and consulting.

### Contribute to Open Source

Part of the money we receive from sponsors is used to contribute to other projects
that we depend upon. Plabayo sponsors the following organisations and individuals
building and maintaining open source software that `rama` depends upon:

| | name | projects |
| - | - | - |
| 💌 | [Tokio](https://github.com/tokio-rs) | (Tokio Project and Ecosystem)
| 💌 | [Sean McArthur](https://github.com/seanmonstar) | (Hyper and Tokio)
| 💌 | [Ulixee](https://github.com/ulixee) | (Browser Profile Data)

### Platinum Sponsors

[![OTA Insight Ltd. Logo](./docs/img/sponsor_ota_insight.png)][OTA Insight Ltd.]

[OTA Insight Ltd.][OTA Insight Ltd.] is always [on the look for great talent](https://careers.otainsight.com/).
They have many positions open, including a position for Senior Crawler Engineer which is not openly advertised.

If you would be interested in the latter position, and you have a hacker mindset,
as well as a passion to work on network technologies such as `rama`,
automated browser technology for browser web scraping purposes or have amazing proven skills for reverse engineering APIs
and (mobile) applications.

Please [send an email to Glen at glen.decauwsemaecker@otainsight.com](mailto:glen.decauwsemaecker@otainsight.com),
who is also the maintainer of `rama`, and apply now for this or other jobs at [OTA Insight Ltd.][OTA Insight Ltd.]

We thank [OTA Insight Ltd.][OTA Insight Ltd.] for their support of this project.

[OTA Insight Ltd.]: https://www.otainsight.com/

## FAQ

### Why the name rama?

The name _rama_ is Japanese for llama and written as "ラマ".
This animal is used as a our mascot and spiritual inspiration of this proxy framework.
It was chosen to honor our connection with Peru, the homeland of this magnificent animal,
and translated into Japanese because we gratefully have built _rama_
upon the broad shoulders of [Tokio and its community](https://tokio.rs/).
