# Do It Yourself (DIY)

In the context of Rama, "Do It Yourself" represents our commitment to flexibility and extensibility. While Rama provides a comprehensive set of tools and services out of the box, we understand that every project has unique requirements. This chapter explains how you can extend and customize Rama to fit your specific needs, whether that means creating custom services, implementing your own middleware, or integrating with different networking libraries.

Rust's tagline states:

> A language empowering everyone to build reliable and efficient software

There is much to unpack in this tagline. You can learn more about [why we built Rama](./why_rama.md) or [why we chose Rust](./rust.md) in other chapters. Here, we focus on the keyword "empowering."

## Empowering

> Empowering: giving someone the authority or power to do something.

Rama is a framework with 🔋 batteries included, as detailed in [the preface of this book](./preface.md). We made this choice for two reasons:

1. It helps us validate Rama's overall architecture and design
2. It prevents repetitive coding of similar logic, allowing us to focus primarily on business logic

Rama's tagline is:

> modular service framework to move and transform network packets

We take modularity seriously. Rama's design is built around the [Tower](https://github.com/tower-rs/tower)-like concept, allowing services to be stacked and branched (see [the service intro chapters](./intro/services_all_the_way_down.md) for more details). This enables middlewares (called `Layer`s) and other `Service`s to be combined, stacked, and reused for various purposes.

This design also empowers you to build your own services:

- Want to use `curl` for your HTTP server/client logic? No problem - use the relevant crates in your own `Service`s and you're good to go. For examples of custom HTTP services, see [the HTTP services chapter](./services/http.md).
- Prefer `openssl`, `gnutls`, or something else for your TLS server/client logic? Go ahead and define your own `Service`s. Learn more about TLS configuration in [the TLS chapter](./services/tls.md).

All of this is possible without forking Rama. You can easily update the Rama components you use while never being blocked by features that Rama doesn't support or may never implement. For more information about Rama's architecture and how to extend it, see [the architecture chapter](./architecture.md).

Additionally, we design our built-in `Service`s (both middleware and leaf services) to be as minimal as possible. This allows you to easily modify the parts you need without having to fork or create an entire monolithic `Service` yourself. For examples of custom middleware, check out [the middleware chapter](./middleware.md).

Feel free to use Rama's codebase as inspiration, copying and modifying any code to suit your needs. For more detailed information about contributing to Rama, see [the contributing guide](../CONTRIBUTING.md).
