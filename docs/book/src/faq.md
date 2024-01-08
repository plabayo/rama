# ❓FAQ

## Why the name "rama"?

The name _rama_ is Japanese for llama and written as "ラマ".
This animal is used as a our mascot and spiritual inspiration of this proxy framework.
It was chosen to honor our connection with Peru, the homeland of this magnificent animal,
and translated into Japanese because we gratefully have built _rama_
upon the broad shoulders of [Tokio and its community](https://tokio.rs/).

Note that the Tokio runtime and its ecosystems sparked initial experimental versions of Rama,
but that we since then, after plenty of non-published iterations, have broken free from that ecosystem,
and are now supporting other ecosystems as well. In fact, by default we link not into any async runtime,
and rely only on the `std` library for for any future/async primitives.

## On which platform can I run rama?

In theory you should be able to run on any platform which is supported by [our MSVR](https://github.com/plabayo/rama/tree/main?tab=readme-ov-file#--minimum-supported-rust-version) and which is supported by [Tokio](https://tokio.rs).

That said, you might need to disable certain feature flags such as the support for `boringssl`,
something used in the underlying clients. It also must be noted that we only develop from MacOS (Apple Silicon),
and use the default Ubuntu VM's for our CI at GitHub Actions. Any other platform is therefore
to be considered untested, even though the most common ones probably should work.

Please [open an issue](https://github.com/plabayo/rama/issues) in case you have troubles using rama on your platform.

## Can I use rama without using Async?

No.

## Can I use rama with an async runtime other than Tokio?

Some runtimes like [smol](https://github.com/smol-rs/smol) promise compatibility with Tokio.
It might therefore work while using that one...

That said, Rama is really designed with Tokio, and only Tokio in mind.
This because our resources are limited and the Async runtime story in Rust is still a bit
of a mess..

Feel free to open an issue in case you want Rama to work for a runtime
other than Tokio. Know however that it will not quickly be our priority or desire to change this.
The creation of the issue however would allow you to kick off progress towards a change
in attitude here and would allow you to start a conversation about it.

## Can Tower be used?

Initially Rama was designed fully around the idea of Tower. The initial design of Rama took many
iterations and was R&D'd over a timespan of about a year, in between other work and parenting.
We switched between [`tower`](https://crates.io/crates/tower), [`tower-async`](https://crates.io/crates/tower-async) (our own public fork of tower) and back to [`tower`](https://crates.io/crates/tower) again...

It became clear however that the version of [`tower`](https://crates.io/crates/tower) at the time was incompatible with the ideas
which we wanted it to have:

- We are not interested in the `poll_ready` code of tower,
  and in fact it would be harmful if something is used which makes use of it
  (Axum warns for it, but strictly it is possible...);
  - This idea is also further elaborated in the FAQ of our tower-async fork:
    <https://github.com/plabayo/tower-async?tab=readme-ov-file#faq>
- We want to start to prepare for an `async`-ready future as soon as we can...

All in all, it was clear after several iterations that usage of tower did more
harm then it did good. What was supposed to be a stack to help us implement our vision,
became a hurdle instead.

This is not the fault of tower, but more a sign that it did not age well,
or perhaps... it is actually a very different beast altogether.

## Can I build Web Services with Rama?

Yes...

But this is however not the intention on itself.
Please consult [./web_servers.md](./web_servers.md) for more information.
