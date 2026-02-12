# Introduction to rama

<div class="book-article-intro">
    <img src="./img/rama_intro.jpeg" alt="llama teaching a class of crabs">
    <div>
        🦙 rama® (ラマ) is a modular service framework for the 🦀 Rust language to move and transform your network packets.
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
- [☀️ State](./intro/state.md)
- [🧱 Modular](./intro/modular.md)
- [🚚 Dynamic Dispatch](./intro/dynamic_dispatch.md)
- [🚫 Errors](./intro/errors.md)
- [🧘 Zen of Services](./intro/service_zen.md)
- [🔭 Telemetry](./intro/telemetry.md)
- [👤 User Agent](./intro/user_agent.md)

## Talk: Rethinking network services: Freedom and modularity with Rama (FOSDEM 2026)

<div class="book-article-image-center">

<iframe width="560" height="315" src="https://www.youtube.com/embed/gCLjK2RS5xA?si=Mdo6kn-PuPg3Wzon" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

</div>

Recording of a talk we gave as an introduction to Rama at FOSDEM 2026:

Modern networking software often forces developers to choose between rigid, off-the-shelf frameworks and the painstaking effort of building everything from scratch. Rama takes a different path. It’s a modular Rust framework that lets you move and transform packets across the network stack, without giving up control, safety, or composability.

In this talk, I’ll explore together with the audience how Rama’s philosophy of layers, services, and extensions turns network programming into a flexible and enjoyable experience. You’ll see how its building blocks span multiple layers of abstraction. From transport and TLS up to HTTP, and a lot more in between. All while you can still easily plug in your own logic or replace existing components. It also shows how you can build network stacks that aren't possible anywhere else, and all without a sweat. For example socks5 over TLS. Why not.

Through practical examples, we’ll look at how Rama empowers developers to build everything from proxies and servers to custom network tools, while still benefiting from Rust’s performance and safety guarantees. Whether you’re curious about programmable networking, Rust’s async ecosystem, or just want to build things your own way, this talk will show you how Rama helps you do it, all with elegance and confidence.

More information about rama itself can be found at https://ramaproxy.org/, which is developed and maintained by https://plabayo.tech/, a FOSS, consulting and commercial technology (small family) company from Ghent.

https://github.com/plabayo/rama

> [!NOTE]
> Credits of recording and production go to the FOSDEM 2026 team.
>
> Original video found at <https://fosdem.org/2026/schedule/event/CKANPK-programmable_networking_with_rama/>.
> You can also report issues there and find the slide deck in PDF format.
