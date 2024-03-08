# ☀️ Context\<State\>

To recap, a `Service::serve` method has the following signature:

```rust,noplayground
fn serve(
    &self,
    ctx: Context<State>,
    req: Request,
) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_;
```

- `&self` allows services to access shared `Send + Sync + 'static` state internal and specific to that `Service`;
- `Request` is the input used to produce a `Result`.

`Context<State>` is what this chapter is about,
and its documemtation can be consumed at <https://ramaproxy.org/docs/rama/service/context/struct.Context.html>.

`Context<State>` is used to:

- access shared typesafe `State` defined by the code location instantiating the `Service` on its own or part of a _stack_.
- access `Extensions` that can be used to dynamically get and set extra (optional) data, to be passed for usage by inner service(s).
- spawn tasks for the given (async) executor, doing so gracefully if configured to do so.
- abrubt tasks early in a graceful manner in case of a shutdown using the gracuful `ShutdownGuard` if defined.

This is a clear distinction from a `Tower` service which only takes a `Request`.
If that `Request` is an `http Request` it does allow one to add extra optional data using
the `Extensions` type/data also available in an `http Request`. Hower it provides no means
of typesafe `State`, executors, spawning etc. On top of that it would make it more awkward to
also freely pass all this data between services, especially those operating
across different layers of the network.

## State

rama` supports two kinds of states:

1. type-safe state: this is the `S` generic parameter in [`Context`] and is to be used
   as much as possible, given its existence and type properties can be validated at compile time
2. dynamic state: these can be injected as [`Extensions`]s using methods such as [`Context::insert`]

As a rule of thumb one should use the type-safe state (1) in case:

- the state is always expected to exist at the point the middleware/service is called
- the state is specific to the app or middleware
- and the state can be constructed in a default/empty state

The latter is important given the state is often created (or at least reserved) prior to
it is actually being populated by the relevant middleware. This is not the case for app-specific state
such as Database pools which are created since the start and shared amongs many different tasks.

The rule could be be simplified to "if you need to `.unwrap()` you probably want type-safe state instead".
It's however just a guideline and not a hard rule. As maintainers of `rama` we'll do our best to respect it though,
and we recommend you to do the same.

Any state that is optional, and especially optional state injected by middleware, can be inserted using extensions.
It is however important to try as much as possible to then also consume this state in an approach that deals
gracefully with its absence. Good examples of this are header-related inputs. Headers might be set or not,
and so absence of [`Extensions`]s that might be created as a result of these might reasonably not exist.
It might of course still mean the app returns an error response when it is absent, but it should not unwrap/panic.

[`Context`]: https://ramaproxy.org/docs/rama/service/context/struct.Context.html
[`Context::insert`]: https://ramaproxy.org/docs/rama/service/context/struct.Context.html#method.insert
[`Extensions`]: https://ramaproxy.org/docs/rama/service/context/struct.Extensions.html

## Extensions

Rama makes no use of `http::Extensions`, and instead keeps it all within the extensions API provided by `Context<State>`.
Extensions are there for middleware to inject state into the context. Here is how you should think about extensions:

- Extensions are not for shared data, as it will be unique to this request path, with only the inner service having access to it.
  - Parent of sibling services will not have access to newly inserted data;
- Extensions can be be referenced (`get`) and inserted (`insert`). They cannot be exclusively referenced (`mut`),
  nor can they be removed or anything ese.

`State` in contrast is shared and is fully statically typed. This is a great solution for putting resource pools, databases, etc...
However such a statically typed static type does not lend itself well towards state that is provided by an extension and that is unique to
a specific request (path).

