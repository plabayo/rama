# 📦 Rama Crate

Rama is a modular service framework distributed as a Rust crate at <https://crates.io/crates/rama>. You can add it to your project as follows:

```
cargo add rama
```

## Quick Links

* Crates Page: <https://crates.io/crates/rama>
* Official Docs Page (for releases): <https://docs.rs/rama>
    * Edge (main branch): <https://ramaproxy.org/docs/rama/index.html>
* Github repo: <https://github.com/plabayo/rama>

## All Rama Crates

The `rama` crate can be used as the one and only dependency.
However, as you can also read in the "DIY" chapter of the book
at <https://ramaproxy.org/book/diy.html#empowering>, you are able
to pick and choose not only what specific parts of `rama` you wish to use,
but also in fact what specific (sub) crates.

Here is a list of all `rama` crates:

- [`rama`](https://crates.io/crates/rama): one crate to rule them all
- [`rama-error`](https://crates.io/crates/rama-error): error utilities for rama and its users
- [`rama-macros`](https://crates.io/crates/rama-macros): contains the procedural macros used by `rama`
- [`rama-utils`](https://crates.io/crates/rama-utils): utilities crate for rama
- [`rama-core`](https://crates.io/crates/rama-core): core crate containing the service, layer and
  context used by all other `rama` code, as well as some other _core_ utilities
- [`rama-net`](https://crates.io/crates/rama-net): rama network types and utilities
- [`rama-dns`](https://crates.io/crates/rama-dns): DNS support for rama
- [`rama-tcp`](https://crates.io/crates/rama-tcp): TCP support for rama
- [`rama-udp`](https://crates.io/crates/rama-udp): UDP support for rama
- [`rama-tls`](https://crates.io/crates/rama-tls): TLS support for rama (types, `rustls` and `boring`)
- [`rama-proxy`](https://crates.io/crates/rama-proxy): proxy types and utilities for rama
- [`rama-socks5`](https://crates.io/crates/rama-socks5): SOCKS5 support for rama
- [`rama-haproxy`](https://crates.io/crates/rama-haproxy): rama HaProxy support
- [`rama-ua`](https://crates.io/crates/rama-ua): User-Agent (UA) support for `rama`
- [`rama-http-types`](https://crates.io/crates/rama-http-types): http types and utilities
- [`rama-http`](https://crates.io/crates/rama-http): rama http services, layers and utilities
- [`rama-http-backend`](https://crates.io/crates/rama-http-backend): default http backend for `rama`
- [`rama-http-core`](https://crates.io/crates/rama-http-core): http protocol implementation driving `rama-http-backend`

## Examples

Examples to help you get started can be found in
[the examples found in the `/examples` dir](https://github.com/plabayo/rama/tree/main/examples)
to know how to use rama for your purposes.

## 💪 | Performance

`rama`'s default http implementation is forked from [`hyper`] and adds very little
overhead. So `rama`'s performance is comparable to [`hyper`] and frameworks that built on top of that.

[`hyper`]: https://github.com/hyperium/hyper

Here's a list of external benchmarks:

- http server benchmark @ <https://web-frameworks-benchmark.netlify.app/result>

Please [open an issue](https://github.com/plabayo/rama/issues) or Pull Request (PR) in case
you are aware of any other benchmarks of interest in regards to http(s) servers,
http(s) clients or proxies such as Man-In-The-Middle (MITM) proxies.

## ⛨ | Safety

The rama crates avoid `unsafe_code`, but do make use of it for some low level primitives (e.g. http core)
or indirectly because of bindgens to C (e.g. boring).

We also make use of [`cargo vet`](https://github.com/mozilla/cargo-vet) to
[audit our supply chain](https://github.com/plabayo/rama/tree/main/supply-chain/).

## 🦀 | Compatibility

Rama (ラマ) is developed mostly on MacOS M-Series machines and run in production
on a variety of Linux systems. There is no windows support, and neither do we test on that platform.

| platform | tested | test platform |
|----------|--------|---------------|
| MacOS    | ✅     | MacOS Apple Silicon (developer laptop) and macos-12 Intel ([GitHub Action](https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners/about-github-hosted-runners)) |
| Linux    | ✅     | Ubuntu 22.04 ([GitHub Action](https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners/about-github-hosted-runners)) |

Please [open a ticket](https://github.com/plabayo/rama/issues) in case you have compatibility issues for your setup/platform.
Our goal is not to support all possible platformns in the world, but we do want to
support as many as we reasonably can.

### Minimum supported Rust version

Rama's MSRV is `1.85`.

[Using GitHub Actions we also test](https://github.com/plabayo/rama/blob/main/.github/workflows/CI.yml) if `rama` on that version still works on
the stable and beta versions of _rust_ as well.

## 🧭 | Roadmap

Please refer to <https://github.com/plabayo/rama/milestones> to know what's on the roadmap. Is there something not on the roadmap for the next version that you would really like? Please [create a feature request](https://github.com/plabayo/rama/issues) to request it and [become a sponsor](#sponsors) if you can.

## 📰 | Media Appearances

Rama (`0.2`) was featured in a 📻 Rustacean episode on the 19th of May 2024, and available to listen at <https://rustacean-station.org/episode/glen-de-cauwsemaecker/>. In this episode [Glen](https://www.glendc.com/) explains the history of Rama, why it exists, how it can be used and more.

## 💼 | License

This project is dual-licensed under both the [MIT license][mit-license] and [Apache 2.0 License][apache-license].

## 👋 | Contributing

🎈 Thanks for your help improving the project! We are so happy to have
you! We have a [contributing guide][contributing] to help you get involved in the
`rama` project.

Contributions often come from people who already know what they want, be it a fix for a bug they encountered,
or a feature that they are missing. Please do always make a ticket if one doesn't exist already.

It's possible however that you do not yet know what specifically to contribute, and yet want to help out.
For that we thank you. You can take a look at the open issues, and in particular:

- [`good first issue`](https://github.com/plabayo/rama/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22): issues that are good for those new to the `rama` codebase;
- [`easy`](https://github.com/plabayo/rama/issues?q=is%3Aissue+is%3Aopen+label%3Aeasy): issues that are seen as easy;
- [`mentor available`](https://github.com/plabayo/rama/issues?q=is%3Aissue+is%3Aopen+label%3A%22mentor+available%22): issues for which we offer mentorship;
- [`low prio`](https://github.com/plabayo/rama/issues?q=is%3Aissue+is%3Aopen+label%3A%22low+prio%22): low prio issues that have no immediate pressure to be finished quick, great in case you want to help out but can only do with limited time to spare;

In general, any issue not assigned already is free to be picked up by anyone else. Please do communicate in the ticket
if you are planning to pick it up, as to avoid multiple people trying to solve the same one.

> 💡 Some issues have a [`needs input`](https://github.com/plabayo/rama/issues?q=is%3Aissue+is%3Aopen+label%3A%22needs+input%22+) label.
> These mean that the issue is not yet ready for development. First of all prior to starting working on an issue you should always look for
> alignment with the rama maintainers. However these
> [`needs input`](https://github.com/plabayo/rama/issues?q=is%3Aissue+is%3Aopen+label%3A%22needs+input%22+) issues require also prior R&D work:
>
> - add and discuss missing knowledge or other things not clear;
> - figure out pros and cons of the solutions (as well as what if we choose to not not resolve the issue);
> - discuss and brainstorm on possible implementations, desire features, consequences, benefits, ...
>
> Only once this R&D is complete and alignment is confirmed, shall the feature be started to be implemented.

Should you want to contribure this project but you do not yet know how to program in Rust, you could start learning Rust with as goal to contribute as soon as possible to `rama` by using "[the Rust 101 Learning Guide](https://rust-lang.guide/)" as your study companion. Glen can also be hired as a mentor or teacher to give you paid 1-on-1 lessons and other similar consultancy services. You can find his contact details at <https://www.glendc.com/>.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in `rama` by you, shall be licensed as both [MIT][mit-license] and [Apache 2.0][apache-license],
without any additional terms or conditions.

[contributing]: https://github.com/plabayo/rama/blob/main/CONTRIBUTING.md
[mit-license]: https://github.com/plabayo/rama/blob/main/LICENSE-MIT
[apache-license]: https://github.com/plabayo/rama/blob/main/LICENSE-APACHE
