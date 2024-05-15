# Do It Yourself (DIY)

Rust has the following tagline:

> A language empowering everyone to build reliable and efficient software

There is a lot to unpack in that tagline, and you can read more about [why we built rama](./why_rama.md) or [why we have chosen for Rust](./rust.md) in other chapters. Here we would like to focus on the keyword "empowering".

## Empowering

> Empowering: give (someone) the authority or power to do something.

Rama is a framework with 🔋 batteries included, as can be seen in [the preface of this book](./preface.md). We do this for two reasons:

1. it helps us validate the overall architecture and design of "rama";
2. it helps in avoiding needless repetitive coding of the same kind of logic over and over again, to instead be able to focus for the most part on our actual business logic.

That said, the tagline of "Rama" is:

> modular service framework to move and transform network packets

Where modularity is something we do take seriously. Rama's design is build around the [Tower](https://github.com/tower-rs/tower)-like concept in which we allow services to be stacked and branched (see [the service intro chapters](./intro/services_all_the_way_down.md) to learn this in more depth). This allows middlewares (called `Layer`s) and other kinds of `Service`s to be combined, stacked and reused for all kind of purposes.

What it also allows you to do is to build your own services:

- Do you want to use `curl` or `hyper` for your _Http_ server / client logic? No problem, use the relevant crates in your own `Service`s and off you go.
- Do you want to want to use `openssl`, `gnutls` or something else for your _Tls_ server / client logic. Once again, go nuts by defining your own `Service`s.

This and more is possible, without having to fork "Rama", meaning you can still easily get the benefits of being to update the logic that you do use of "Rama", while at the same time never getting blocked on a feature that "Rama" does not yet support or perhaps never will.

On top of that we try to make the built-in `Service`s (be it middleware or leaf services), as minimal as possible, such that you can easily modify the parts you wish without having to fork/create an entire big monolithic `Service` yourself.

Feel free to use the entire "Rama" codebase as your own source of inspiration, copying whatever code you wish and modifying it to your heart's content.
