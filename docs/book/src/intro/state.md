# ☀️ State

To recap, [`Service::serve`] takes `&self` and an `Input`, and returns a `Send` future
that resolves to a `Result<Self::Output, Self::Error>`:

- `&self` allows services to access shared `Send + Sync + 'static` state internal and specific to that `Service`;
- `Input` is used to produce a `Result`. Inputs such as http requests and transport streams also contain `Extensions`, which can be used to store dynamic state. Not every input type has them.

## Types of state

`rama` supports two kinds of states:

1. static state: this state can be a part of the service struct or captured by a closure
2. dynamic state: these can be injected as [`Extensions`]s using methods such as [`Extensions::insert`] or [`request.extensions().insert`]

Any state that is optional, and especially optional state injected by middleware, can be inserted using extensions.
It is however important to try as much as possible to then also consume this state in an approach that deals
gracefully with its absence. Good examples of this are header-related inputs. Headers might be set or not,
and so absence of [`Extensions`]s that might be created as a result of these might reasonably not exist.
It might of course still mean the app returns an error response when it is absent, but it should not unwrap/panic.

## Extensions

`Extensions` is what this chapter is about, and its documentation can be consumed at <https://ramaproxy.org/docs/rama/extensions/struct.Extensions.html>.

- access `Extensions` that can be used to dynamically get and set extra (optional) data, to be passed for usage by inner service(s).

[`Service::serve`]: https://ramaproxy.org/docs/rama/service/trait.Service.html#tymethod.serve
[`Extensions`]: https://ramaproxy.org/docs/rama/extensions/struct.Extensions.html
[`Extensions::insert`]: https://ramaproxy.org/docs/rama/extensions/struct.Extensions.html#method.insert
[`request.extensions().insert`]: https://ramaproxy.org/docs/rama/extensions/trait.ExtensionsRef.html#tymethod.extensions
