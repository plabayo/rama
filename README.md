![rama banner](https://raw.githubusercontent.com/plabayo/rama/main/docs/img/banner.svg)

[![Crates.io][crates-badge]][crates-url]
[![Docs.rs][docs-badge]][docs-url]
[![MIT License][license-mit-badge]][license-mit-url]
[![Apache 2.0 License][license-apache-badge]][license-apache-url]
[![Build Status][actions-badge]][actions-url]

[![Discord][discord-badge]][discord-url]
[![Buy Me A Coffee][bmac-badge]][bmac-url]
[![GitHub Sponsors][ghs-badge]][ghs-url]

[crates-badge]: https://img.shields.io/crates/v/rama.svg
[crates-url]: https://crates.io/crates/rama
[docs-badge]: https://img.shields.io/docsrs/rama/latest
[docs-url]: https://docs.rs/rama/latest/rama/index.html
[license-mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[license-mit-url]: https://github.com/plabayo/rama/blob/main/LICENSE-MIT
[license-apache-badge]: https://img.shields.io/badge/license-APACHE-blue.svg
[license-apache-url]: https://github.com/plabayo/rama/blob/main/LICENSE-APACHE
[actions-badge]: https://github.com/plabayo/rama/workflows/CI/badge.svg
[actions-url]: https://github.com/plabayo/rama/actions?query=workflow%3ACI+branch%main

[discord-badge]: https://img.shields.io/badge/Discord-%235865F2.svg?style=for-the-badge&logo=discord&logoColor=white
[discord-url]: https://discord.gg/29EetaSYCD
[bmac-badge]: https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black
[bmac-url]: https://www.buymeacoffee.com/plabayo
[ghs-badge]: https://img.shields.io/badge/sponsor-30363D?style=for-the-badge&logo=GitHub-Sponsors&logoColor=#EA4AAA
[ghs-url]: https://github.com/sponsors/plabayo

Rama is first and foremost a framework for the Rust language to build distortion proxy software. Meaning to build proxies that sit in between in your spiders (software used for data extraction, also known as scraping) and your upstream (IP) proxies.

Please refer to [the examples found in the `./examples` dir](./examples) to learn how rama is to be used. There is no [crates.io](https://crates.io) release of rama yet. If you already want to start using rama already your can do so by referring to it in your `Cargo.toml` as follows:

```
rama = { git = "https://github.com/plabayo/rama" }
```

Come join us at [Discord][discord-url] on the `#rama` public channel. To ask questions, discuss ideas and ask how rama may be useful for you.

> rama is early work in progress, use at your own risk.
>
> Not everything that exists is documented and not everything that is documented is implemented.


## Roadmap

Please refer to <https://github.com/plabayo/rama/milestones> to know what's on the roadmap. Is there something not on the roadmap for the next version that you would really like? Please [create a feature request](https://github.com/plabayo/rama/issues) to request it and [become a sponsor](#sponsors) if you can.

### Visual Overview (out of date)

This was an early attempt to visualise the overview of what the project offers. It is badly out of date however and will be replaced by a purely markdown documentation in the form of sections, summaries and example code. For now this at least should give you an idea of what v0.2 wil llook like.

![rama roadmap v0.2.0](./docs/img/roadmap.svg)

## Nightly

`rama` is currently only available on nightly rust,
this is because it uses the `async_trait` feature,
which is currently only available on nightly rust.

We expect to be able to switch back to stable rust once `async_trait` is available on stable rust,
which should be by the end of 2023.

See <https://blog.rust-lang.org/inside-rust/2023/05/03/stabilizing-async-fn-in-trait.html> for more information.

> NOTE: the above information was about design #3 of Rama,
> in the new design we might switch to `impl Future` which would stabalize this year...

## Contributing

:balloon: Thanks for your help improving the project! We are so happy to have
you! We have a [contributing guide][contributing] to help you get involved in the
`rama` project.

Should you want to contribure this project but you do not yet know how to program in Rust, you could start learning Rust with as goal to contribute as soon as possible to `rama` by using "[the Rust 101 Learning Guide](https://rust-lang.guide/)" as your study companion. Glen can also be hired as a mentor or teacher to give you paid 1-on-1 lessons and other similar consultancy services. You can find his contact details at <https://www.glendc.com/>.

## License

This project is dual-licensed under both the [MIT license][mit-license] and [Apache 2.0 License][apache-license].

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in `rama` by you, shall be licensed as both [MIT][mit-license] and [Apache 2.0][apache-license],
without any additional terms or conditions.

[contributing]: https://github.com/plabayo/rama/blob/main/CONTRIBUTING.md
[mit-license]: https://github.com/plabayo/rama/blob/main/LICENSE-MIT
[apache-license]: https://github.com/plabayo/rama/blob/main/LICENSE-APACHE

## Sponsors

Rama is **completely free, open-source software** which needs lots of effort and time to develop and maintain.

Support this project by becoming a [sponsor][ghs-url]. One time payments are accepted [at GitHub][ghs-url] as well as at ["Buy me a Coffee"][bmac-url]

Sponsors help us continue to maintain and improve `rama`, as well as other
Free and Open Source (FOSS) technology. It also helps us to create
educational content such as <https://github.com/plabayo/learn-rust-101>,
and other open source libraries such as <https://github.com/plabayo/tower-async>.

Sponsors receive perks and depending on your regular contribution it also
allows you to rely on us for support and consulting.

If you plan to use Rama for your commercial resell or package activities you
need to be a sponsor for a high enough tier to allow you to use it
for these purposes despite it having a Business License (BSL).

### Contribute to Open Source

Part of the money we receive from sponsors is used to contribute to other projects
that we depend upon. Plabayo sponsors the following organisations and individuals
building and maintaining open source software that `rama` depends upon:

| | name | projects |
| - | - | - |
| 💌 | [Tokio (*)](https://github.com/tokio-rs) | (Tokio Project and Ecosystem)
| 💌 | [Sean McArthur](https://github.com/seanmonstar) | (Hyper and Tokio)
| 💌 | [Ulixee](https://github.com/ulixee) | (Browser Profile Data)

> (*) we no longer depend upon `tower` directly, and instead
> have made a permanent fork of it, available at: <https://github.com/plabayo/tower-async>
>
> We do still contribure to `tower` as well and the goal is to move back to tower
> once it becomes more suitable for our use cases.

## FAQ

### Why the name rama?

The name _rama_ is Japanese for llama and written as "ラマ".
This animal is used as a our mascot and spiritual inspiration of this proxy framework.
It was chosen to honor our connection with Peru, the homeland of this magnificent animal,
and translated into Japanese because we gratefully have built _rama_
upon the broad shoulders of [Tokio and its community](https://tokio.rs/).

Note that the Tokio runtime and its ecosystems sparked initial experimental versions of Rama,
but that we since then, after plenty of non-published iterations, have broken free from that ecosystem,
and are now supporting other ecosystems as well. In fact, by default we link not into any async runtime,
and rely only on the `std` library for for any future/async primitives.

### What Async Runtime is used?

We try to write the Rama codebase in an async runtime agnostic manner. Everything that is
runtime specific (e.g. low level primitives) lives within `rama-rt`. For now Tokio is the only platform
tested on and that is ready to use. In fact it is for now the only one implemented in the `rama-rt` crate.

Please refer to <https://github.com/plabayo/rama/issues/6> if you have a use case / need for `rama` outside
of the tokio async runtime setting. E.g. in case you want to be able to support async-std, smol, something else
or any DIY custom async runtime. Please add sufficient reasons and motivation to explain why support for it would
be required for your use case. Also describe your use case well enough and if possible link to the code in case
it is source-open.

### Help! My Async Trait's Future is not `Send`

Due to a bug in Rust, most likely its trait resolver,
you can currently run into this not very meanigful error.

Cfr: <https://github.com/rust-lang/rust/issues/114142>

By using the 'turbo fish' syntax you can resolve it.
See that issue for more details on this solution.
