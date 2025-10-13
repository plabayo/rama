# 🧘 Zen of Services

In case reading the ["🗼 Services all the way down 🐢"](./services_all_the_way_down.md) was your first introduction to [services][service],
and even if you have no extensive experience with it yet, working
with the concept of services as your architectural backbone might still
be hard to grasp or do.

In a way you could see services as an abstraction similar to how functions, also called routines, are abstractions for reusable code blocks. You could also see it as lego blocks that help you build a tower. But all these are in the end
poor analogies that only get you so far. This chapter hopefully can serve
together with other chapters of this book, code examples and more to
aid you in your journey of becoming a [service] master.

See also [the FAQ](../faq.md) in case you are stuck.
The answer might be there. If you do not find it you can
either search elsewhere or find it for the answer yourself, [send us an email][email],
[open a GitHub issue][gh-issue] or [join us on Discord][discord].

Please do contribute improvements to this chapter and book as a whole,
where you do find clarifications, answers and improvements yourself.

## Tips and Tricks

### 💥 Avoid recursive service stacking

In rama there are service implementations for [`Either`] (allowing you to
provide alternative implementations for two or more services),
and also blanket implementations for types such as `Option`, which work
more or less like [`Either`], either using your middleware service
or not.

These are nice and convenient but be careful with them as they blow up
your stack type.

Let's say you have a service stack such as `A > B > C > D > E`.
In case you want to make `B` optional, by wrapping it with `Option`,
you would get now the type: `A > [ B > C > D > E] | [ () > C > D > E]`.

As you can see your type became twice as long. Depending on your work machine
you only have to do this a couple of times and your rust analyzer, cargo check,
cargo build or any other Rust tool will suddenly become very slow.. Be careful of it.

So what is the solution? Make it possible to allow your middlewares to function
as identity layers (`()`). E.g. [a Limit layer] could be configured to also limit nothing at all. This way your type remains the same while still
allowing your layer to be optional depending on something like a `cli` flag.

### 🛞 Stacks of services, not a service of stacks.

In your attempt to make a (layer) service as useful as possible it can be
attractive to put a lot of configurations in your layer. Perhaps even
to allow generic components that can also be nested.

Avoid this if possible. It makes using your service a lot harder and
you are essentially reinventing the service concept that rama is build around.

Instead keep your service stack as flat as possible by allowing these configurations to instead be chained as you do with all your other layers,
and getting the optional configurations to be set and get via the [`Extension`]
that you can set via service inputs.

When doing so also try to keep these configurations as generic as possible.
Examples in rama are things like the [`ProxyAddress`] that can be set to configure
a proxy for a tcp/udp connector, and that can be defined in any way you wish.

It gives you the full flexibility of how you want to allow a developer to let
the [`ProxyAddress`] to be defined, without having to have any of that in your connect service and without having to do anything at all.

Speaking about `Connectors`, those are a nice example of a type of [`Service`][service] that you might not expect. Because in rama we practise the zen of [services][service]:

- Transport streams and dataframes are passed in [service] stacks
- Application layers such as http work in service stacks
- And even the underlying client transport connectors establish
  their connections using [services][service].

[Services][service], it's all [services][service].

[service]: https://ramaproxy.org/docs/rama/service/trait.Service.html
[`Either`]: https://ramaproxy.org/docs/rama/combinators/index.html

[a Limit layer]: https://ramaproxy.org/docs/rama/layer/limit/struct.Limit.html

[`Extension`]: https://ramaproxy.org/docs/rama/extensions/struct.Extensions.html

[`ProxyAddress`]: https://ramaproxy.org/docs/rama/net/address/struct.ProxyAddress.html

[email]: mailto:glen@plabayo.tech
[gh-issue]: https://github.com/plabayo/rama/issues/new
[discord]: https://discord.gg/29EetaSYCD
