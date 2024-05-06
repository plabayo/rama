# 🚚 Dynamic Dispatch

> In computer science, _dynamic dispatch_ is the process of selecting
> which implementation of a polymorphic operation (method or function) to call at run time.
>
> — [Wikipedia](https://en.wikipedia.org/wiki/Dynamic_dispatch).

Generics are Rust's approach to provide static dispatch. it is called static because
at compile time disjoint code is generated prior to compilation and as such it is static in nature,
and in fact no dispatch at all is happening at runtime.

There are however scenarios where dynamic disaptch shines:

- allowing to inject / select logic based on external runtime input;
- managing collections of different kind of data structures (e.g. different kinds of end point services in a single router).

In Rust dynamic dispatch is supported through trait objects, using the `dyn` keyword.
Traditionally that's combined with a `Box` (e.g. `Box<dyn Service>`), but some prefer to use `Arc` instead of `Box` for reasons not mentioned here.
One can also support it through the `enum` sum type, and there is even a crate named [`enum_dispatch`](https://docs.rs/enum_dispatch/latest/enum_dispatch/),
to help you automate this process. The latter is faster then _true_ dynamic dispatch.

## 🤷 Either

```rust
pub enum Either<A, B> {
    A(A),
    B(B),
}
```

Rama provides [the `rama::service::util::combinator::Either`](https://ramaproxy.org/docs/rama/service/util/combinators/enum.Either.html) combinator,
for two variants, up to nine ([`Either9`](https://ramaproxy.org/docs/rama/service/util/combinators/enum.Either9.html)). These have as the sole purpose
to provide you with an easy way to dynamically dispatch a [`Layer`](https://ramaproxy.org/docs/rama/service/layer/trait.Layer.html)s, [`Service`](https://ramaproxy.org/docs/rama/service/trait.Service.html)s, [`retry::Policy`](https://ramaproxy.org/docs/rama/http/layer/retry/trait.Policy.html) and a [`limit::Policy`](https://ramaproxy.org/docs/rama/service/layer/limit/policy/trait.Policy.html).

You can also implement it for your own traits in case you have the need for it.

In [/examples/http_rate_limit.rs](https://github.com/plabayo/rama/blob/main/examples/http_rate_limit.rs) you can see it in action.

## 😵‍💫 Async Dynamic Dispatch

Only object safe traits can be the base trait of a trait object. You can learn more about this at <https://doc.rust-lang.org/reference/items/traits.html#object-safety>. At the moment traits with `impl Trait` return values are not yet object safe. Luckily however there is a workaround, so even though we do not encourage it, if desired you can box [`Service`](https://ramaproxy.org/docs/rama/service/trait.Service.html)s.

The approach taken to allow for this was widely published in the rust blog at <https://blog.rust-lang.org/inside-rust/2023/05/03/stabilizing-async-fn-in-trait.html>, which originally was mentioned at <https://rust-lang.github.io/async-fundamentals-initiative/evaluation/case-studies/builder-provider-api.html#dynamic-dispatch-behind-the-api>.

The result is that `rama` has a [`BoxService`](https://ramaproxy.org/docs/rama/service/struct.BoxService.html), which can easily be created using the [`Service::boxed`](https://ramaproxy.org/docs/rama/service/trait.Service.html#method.boxed) method, which is implemented automatically for all [`Service`](https://ramaproxy.org/docs/rama/service/trait.Service.html)s.
