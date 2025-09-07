# Why Rama

<div class="book-article-intro">
    <img src="./img/old_logo.png" alt="original (OG) rama logo">
    <div>
        <p>
            When developing specialized proxies in Rust (or other languages),
            developers typically face two main approaches:
        </p>
        <ol>
            <li>Use an "off-the-shelf" solution;</li>
            <li>Build it "from scratch".</li>
        </ol>
    </div>
</div>

The first approach typically involves using established solutions like Nginx, Caddy, or Envoy.
While these tools are powerful, they often limit you to their predefined features and configuration options.
Although most of these technologies allow for custom code integration, you're constrained by their
specific implementation details and architectural choices. Additionally, you're bound to their
underlying layers, which you cannot modify or remove.

The second approach offers complete freedom and flexibility, much like a blank canvas for an artist.
However, this freedom comes at a cost: repeatedly building similar proxy components becomes tedious
and time-consuming. Despite the unique requirements of your proxy, you'll find yourself implementing
many common patterns that are similar to other proxies, including your own previous implementations.

This is where Rama steps in. Rama enables you to develop network proxies tailored to your specific
use case while providing reusable components for the common patterns. It allows you to focus on
what makes your proxy unique while leveraging shared functionality.

## Alternatives

While there are several proxy implementations in Rust, only two other frameworks are specifically
designed for proxy development. Most other Rust-based proxy codebases are single-purpose
implementations, some created for educational purposes, or are general HTTP/web frameworks
that include proxy capabilities as an additional feature.

[Cloudflare] has been developing [`pingora`], a proxy service framework, for several years
and open-sourced it on February 28th, 2024.

While Rama may not be the perfect solution for everyone, we believe it offers significant value
for many use cases. If Rama doesn't meet your needs, we encourage you to explore [`pingora`],
which might be a better fit for your requirements.

Additionally, [ByteDance] has open-sourced [`g3proxy`], a Rust-based framework for developing
both forward and reverse proxies.

[Cloudflare]: https://www.cloudflare.com/
[`pingora`]: https://github.com/cloudflare/pingora
[ByteDance]: https://www.bytedance.com/en/
[`g3proxy`]: https://github.com/bytedance/g3

## More than proxies

During Rama's initial development, we discovered that its advantages extend beyond proxy development
to [web servers](./web_servers.md) and [http clients](./http_clients.md):

* Utilize Async Method Traits for efficient asynchronous operations;
* Leverage modular [Tower](https://github.com/tower-rs/tower)-like middleware with extensions;
* Maintain full control over your web stack from the Transport Layer (TCP, UDP) through TLS and HTTP;
* Ensure the integrity of your proxied data. E.g. for HTTP/1.1preserving header casing and order;

Continue reading this book to learn more about using Rama for these various purposes.

## Tower Compatible

Rama is designed to be tower-compatible. While we don't aim to use Tower for all service needs
in Rama, we want to enable the reuse of existing Tower layers and services where appropriate.

You can find an example of Tower integration at
<https://github.com/plabayo/rama/blob/main/examples/http_rama_tower.rs>.

<div class="book-article-image-center">
<img style="width: 50%" src="https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_tower.jpg" alt="rama tower visual representation">
</div>
