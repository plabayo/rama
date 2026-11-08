# Introduction to rama

<div class="book-article-intro">
    <img src="./img/rama_intro.jpeg" alt="llama teaching a class of crabs">
    <div>
        🦙 rama® (ラマ) is a modular service framework for the 🦀 Rust language
        that provides a cohesive foundation for building network clients,
        servers, proxies, and combinations thereof.
        The reasons behind the creation of rama can be read in <a href="https://ramaproxy.org/book/why_rama.html">the "Why Rama" chapter</a>.
        In this chapter we'll start to dive deeper into the architecture, design and philosophy behind rama.
        At the end of this chapter you should know enough in order to start diving into
        <a href="https://github.com/plabayo/rama/tree/main/examples">the examples found in the `/examples` dir</a>.
    </div>
</div>

In case you want to use Rama to build a proxy service but are new to proxy technology you might want to read the
[introduction to proxies chapter](./proxies/intro.md) first.

And of course as a reminder, if you want to use Rama but are still learning Rust you can use  "[the free Rust 101 Learning Guide](https://rust-lang.guide/)" as your study companion. Next to that, [Glen](mailto:glen@plabayo.tech) can also be hired as a mentor or teacher to give you paid 1-on-1 lessons and other similar consultancy services. You can find his contact details at <https://www.glendc.com/>.

## Index

- [🗼 Services all the way down 🐢](./intro/services_all_the_way_down.md)
- [Service Stack](./intro/service_stack.md)
- [🍔 Middlewares and ☘️ Leaf Services](./intro/terminology.md)
- [Network Layers](./intro/network_layers.md)
- [🚦 Limits: concurrency, rate & bandwidth](./intro/limits.md)
- [Graceful scopes](./intro/graceful.md)
- [⛌ Service Branches](./intro/service_branches.md)
- [☀️ State](./intro/state.md)
- [🧱 Modular](./intro/modular.md)
- [🚚 Dynamic Dispatch](./intro/dynamic_dispatch.md)
- [🚫 Errors](./intro/errors.md)
- [🧘 Zen of Services](./intro/service_zen.md)
- [🔭 Telemetry](./intro/telemetry.md)
- [👤 User Agent](./intro/user_agent.md)
    - [User Agent Emulation](./intro/user_agent_emulation.md)
    - [🎯 Capturing your own profiles](./intro/user_agent_capture.md)
- [🏗 Patterns used inside rama](./intro/patterns.md)

## Rama 101: Blog Series

A series of blog articles to introduce you to Rama. In case you are new to network programming, you might learn a thing or two about its nifty protocols and how they "work together" as well.

1. [Rama 101.1: HTTPS clients and layers of abstraction](https://plabayo.tech/blog/rama-101-1-https-clients-and-abstractions)
2. [Rama 101.2: Core Concepts](https://plabayo.tech/blog/rama-101-2-core-concepts)

## Talk: Rethinking network services: Freedom and modularity with Rama (FOSDEM 2026)

<div class="book-article-image-center">

<iframe width="560" height="315" src="https://www.youtube.com/embed/gCLjK2RS5xA?si=Mdo6kn-PuPg3Wzon" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

</div>

Recording of a talk we gave as an introduction to Rama at FOSDEM 2026:

The talk introduces Rama, a modular Rust framework for moving and transforming packets across the network stack.

It covers how Rama's layers, services and extensions fit together, and how its building blocks span transport, TLS and HTTP, with the option to plug in your own logic or replace existing components. One example is a network stack that runs socks5 over TLS.

Through practical examples, the talk shows how to build proxies, servers and custom network tools with Rama. It also covers programmable networking and Rust's async ecosystem.

More information about rama itself can be found at https://ramaproxy.org/, which is developed and maintained by https://plabayo.tech/, a FOSS, consulting and commercial technology (small family) company from Ghent.

https://github.com/plabayo/rama

> [!NOTE]
> Credits of recording and production go to the FOSDEM 2026 team.
>
> Original video found at <https://fosdem.org/2026/schedule/event/CKANPK-programmable_networking_with_rama/>.
> You can also report issues there and find the slide deck in PDF format.
