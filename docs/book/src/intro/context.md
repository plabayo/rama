# ☀️ Context

To recap, a `Service::serve` method has the following signature:

```rust,noplayground
fn serve(
    &self,
    ctx: Context,
    req: Request,
) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_;
```

- `&self` allows services to access shared `Send + Sync + 'static` state internal and specific to that `Service`;
- `Request` is the input used to produce a `Result`.

`Context` is what this chapter is about,
and its documemtation can be consumed at <https://ramaproxy.org/docs/rama/context/struct.Context.html>.

`Context` is used to:

- access `Extensions` that can be used to dynamically get and set extra (optional) data, to be passed for usage by inner service(s).
- spawn tasks for the given (async) executor, doing so gracefully if configured to do so.
- abrubt tasks early in a graceful manner in case of a shutdown using the gracuful `ShutdownGuard` if defined.

This is a clear distinction from a `Tower` service which only takes a `Request`.
If that `Request` is an `http Request` it does allow one to add extra optional data using
the `Extensions` type/data also available in an `http Request`. However it provides no means
of typesafe executors, spawning etc. On top of that it would make it more awkward to
also freely pass all this data between services, especially those operating
across different layers of the network.

## State

`rama` supports two kinds of states:

1. static state: this state can be a part of the service struct or captured by a closure
2. dynamic state: these can be injected as [`Extensions`]s using methods such as [`Context::insert`]

Any state that is optional, and especially optional state injected by middleware, can be inserted using extensions.
It is however important to try as much as possible to then also consume this state in an approach that deals
gracefully with its absence. Good examples of this are header-related inputs. Headers might be set or not,
and so absence of [`Extensions`]s that might be created as a result of these might reasonably not exist.
It might of course still mean the app returns an error response when it is absent, but it should not unwrap/panic.

TODO: once https://github.com/plabayo/rama/issues/462 is finished and `Context` is removed, write a separate page about `State` and explain all the different options in more detail.

[`Context`]: https://ramaproxy.org/docs/rama/context/struct.Context.html
[`Context::insert`]: https://ramaproxy.org/docs/rama/context/struct.Context.html#method.insert
[`Extensions`]: https://ramaproxy.org/docs/rama/context/struct.Extensions.html
