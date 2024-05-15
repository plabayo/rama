# 🗼 Services all the way down 🐢

To understand Rama you need to understand the abstraction it uses, which is all about services.
It all boils down to the `Service` trait that can be found at
<https://github.com/plabayo/rama/blob/main/src/service/svc.rs>.

> 💡 Rama's `Service` trait and design is directly influenced by
> [tower-rs/tower](https://github.com/tower-rs/tower). The initial goal was to actually use
> `tower`. At some point of the R&D phase we even [developed a fork of it](https://github.com/plabayo/tower-async).
> In the end we decided to roll out or own design.
> You can [learn more about why in the FAQ](https://ramaproxy.org/book/faq.html#can-tower-be-used).
>
> Even so, `tower` has a great introduction tutorial that can help you to understand
> how a design around something like a `Service` operates, how it is to be used,
> and why it is such an excellent solution to this design space. You can find it
> at <https://github.com/tower-rs/tower/blob/master/guides/README.md> 📚. A must read if you haven't already.

[The trait](https://github.com/plabayo/rama/blob/main/src/service/svc.rs)
can be represented in reduced form as follows:

```rust,noplayground
/// A [`Service`] that produces rama services,
/// to serve requests with, be it transport layer requests or application layer requests.
pub trait Service<S, Request>: Send + Sync + 'static {
    /// The type of response returned by the service.
    type Response: Send + 'static;

    /// The type of error returned by the service.
    type Error: Send + Sync + 'static;

    /// Serve a response or error for the given request,
    /// using the given context.
    fn serve(
        &self,
        ctx: Context<S>,
        req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_;
}
```

This trait is an [async trait](https://blog.rust-lang.org/2023/12/21/async-fn-rpit-in-traits.html) only supported
[in Stable Rust since version 1.75](https://blog.rust-lang.org/2023/12/28/Rust-1.75.0.html) of the Rust Language.
Due to the unfinished async story in Rust and the fact that we want to support and mainly
target the multithreaded async setting supported by [Tokio](https://tokio.rs/), 

The design is all about allowing one to use a `Service` that can take a `Request`,
process it and return a `Result` which contains a `Response` at success and an `Error` when it failed for some reason.
As per the design of Rust's _std_ `Result` we do want to make clear that despite the associated type's name,
that it does not have to mean that the assigned type implements the `std::error::Error` trait. It is perfectly fine
for that to contain the same or similar type as is used for the `Response` associated type.

## Everything is a service

Within Rama pretty much anything is a service, except for the configurable parts of a service, those are most likely other types or even just primitives.

A notable difference from other (web) frameworks where you might ave worked with the concept of services is that within Rama you can have services on multiple layers of the network stack. The lowest layer that we offer support for is the transport layer, allowing you to operate as a leaf or middleware service directly on the input Tcp/Udp stream. The highest layer is the Http layer which you are most likely already familiar with. Layers such as Tls operate within the transport layer for what is Rama concerned. As tls is from a minimal POV simply a wrapper around the Tcp stream.

The story doesn't end here however. Where in most frameworks you would also have "thick" services such as an Http client. This is not the case in Rama. Here we really do it services all the way down. If you look at Rama's [HttpClient](https://ramaproxy.org/docs/rama/http/client/struct.HttpClient.html) you'll notice that it takes optionally a service to get connections. This allows you to build any kind of service stack you wish, where the input is the http request, and out the output is the input + a connection to be operated upon. Features such as a connection pool are implemented in the form of layers that you can easily add to your `HttpClient` in that manner. As we said... services all the way down.
