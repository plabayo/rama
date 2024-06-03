# ❓FAQ

## Why the name "rama"?

The name _rama_ is Japanese for llama and written as "ラマ".
This animal is used as a our mascot and spiritual inspiration of this framework.
It was chosen to honor our connection with Peru, the homeland of this magnificent animal,
and translated into Japanese because we gratefully have built _rama_
upon the broad shoulders of [Tokio and its community](https://tokio.rs/).

## On which platform can I run rama?

In theory you should be able to run on any platform which is supported by [our MSVR](https://github.com/plabayo/rama/tree/main?tab=readme-ov-file#minimum-supported-rust-version) and which is supported by [Tokio](https://tokio.rs).

That said, you might need to disable certain feature flags such as the support for `boringssl`,
something used in the underlying clients. It also must be noted that we only develop from MacOS (Apple Silicon),
and use the default Ubuntu VM's for our CI at GitHub Actions. Any other platform is therefore
to be considered untested, even though the most common ones probably should work.

See [the Compatibility info in the README](https://github.com/plabayo/rama/tree/main?tab=readme-ov-file#--compatibility) for more information.

Please [open an issue](https://github.com/plabayo/rama/issues) in case you have troubles using rama on your platform.

## Can I use rama without using Async?

No.

## Can I use rama with an async runtime other than Tokio?

Some runtimes like [smol](https://github.com/smol-rs/smol) promise compatibility with Tokio.
It might therefore work while using that one...

That said, Rama is really designed with Tokio, and only Tokio in mind.
This because our resources are limited and the Async runtime story in Rust is still a bit
of a mess..

Feel free to open an issue in case you want Rama to work for a runtime
other than Tokio. Know however that it will not quickly be our priority or desire to change this.
The creation of the issue however would allow you to kick off progress towards a change
in attitude here and would allow you to start a conversation about it.

## Can Tower be used?

Initially Rama was designed fully around the idea of Tower. The initial design of Rama took many
iterations and was R&D'd over a timespan of about a year, in between other work and parenting.
We switched between [`tower`](https://crates.io/crates/tower), [`tower-async`](https://crates.io/crates/tower-async) (our own public fork of tower) and back to [`tower`](https://crates.io/crates/tower) again...

It became clear however that the version of [`tower`](https://crates.io/crates/tower) at the time was incompatible with the ideas
which we wanted it to have:

- We are not interested in the `poll_ready` code of tower,
  and in fact it would be harmful if something is used which makes use of it
  (Axum warns for it, but strictly it is possible...);
  - This idea is also further elaborated in the FAQ of our tower-async fork:
    <https://github.com/plabayo/tower-async?tab=readme-ov-file#faq>
- We want to start to prepare for an `async`-ready future as soon as we can...

All in all, it was clear after several iterations that usage of tower did more
harm then it did good. What was supposed to be a stack to help us implement our vision,
became a hurdle instead.

This is not the fault of tower, but more a sign that it did not age well,
or perhaps... it is actually a very different beast altogether.

## Can I build Web Services with Rama?

Yes you can, there are even some examples:

- [http_k8s_health.rs](https://github.com/plabayo/rama/tree/main/examples/http_k8s_health.rs):
  built-in web service that can be used as a k8s health service for proxies deploying as a k8s deployment;
- [http_key_value_store.rs](https://github.com/plabayo/rama/tree/main/examples/http_key_value_store.rs):
  a web service example showcasing how one might do a key value store web service using `Rama`;
- [http_web_service_dir_and_api.rs](https://github.com/plabayo/rama/tree/main/examples/http_web_service_dir_and_api.rs):
  a web service example showcasing how one can make a web service to serve a website which includes an XHR API;

Given Rama's prime focus is to aid in the development of proxy services it is
even more natural to write web services that run as part of a proxy service, e.g.:

- a k8s health service ([/examples/http_k8s_health.rs](https://github.com/plabayo/rama/tree/main/examples/http_k8s_health.rs));
- a metric exposure service;
- a minimal api service (e.g. to expose device profiles or certificates);
- a graphical interface / control panel;

Please consult [./web_servers.md](./web_servers.md) for more information.

## Help! I get trait-related compile errors that I do not understand!!

Rama's code is written in a very generic manner, which combined with the fact that it is written with a tokio
multithreaded work-stealing environment and at the same time with the goal to provide you with high level ergonomical features, results in a pretty complicated set of trait bounds and restrictions of all kinds.

As such it is very easy to write code — especially when you're new to `rama` — which will give a compiler error for which you have no clue how to resolve it. Sometimes the answer can be found in the compiler output if you know at what line to spot, but at times the answer might honestly not be there at all.

Axum had similar issues at the past and they solved it as far as we know by:

- Boxing services and other core types where possible to erase complicated type signatures;
- Provide debug macros for code stacks to more easily figure out what is missing;

For `rama` we try to box as little as possible, and we do not provide such `debug` macros.

> 💡 You can learn more about about [Dynamic- vs Static dispatch here](./intro/dynamic_dispatch.md).

Most commonly you might get this error, especially the difficult ones, for high level http service handlers. In which case the problem is usually on of these:

- add a service struct or function which does not derive `Clone` (a requirement);
- use something which is not `Send/Sync/'static`, while it is expected to be;
- return a Result as the output of an `Endpoint` service/fn (when using the `WebService` router), instead of only returning the happy path value;

There are other possibilities to get long wielded compiler errors as well. It is not feasible to list all possible reasons here, but know most likely it is among the lines of the examples above. If not, and you continue to be stuck, to feel free to join our discord at <https://discord.gg/29EetaSYCD> and reach out for help. We're here for you.

## my cargo check/build/... commands take forever

[Service stacks](./intro/service_stack.md) can become quiet complex in Rama. In case you notice that your current change
makes the `cargo check` command (or something similar) becomes very slow, it should hopefully be clear
why by checking `git diff` or a similar VCS action.

The most common reasons for this is if:

1. you have a very large function which also contains deeply nested generic types;
2. you have a lot of [`Either`] service/layer stuff within your [Service stacks](./intro/service_stack.md).

It's especially (2) that can slow you down if you overuse it. This usually comes op in case you use
plenty of `Option<Layer<L>>` code to optionally create a layer based on a certain input/config variable.
While this might seem like a good idea, and it can be if used sparsly, it can really slow you down once you
use a couple of these. This is because under the hood this results in `Either<L::Service, S>`, meaning your
`S` service (stack) will be twice in that signature. Do that a couple of times and you very quickly have a very long long type.

Therefore it is recommended for optional layers/services to instead provide an option to create the same kind of layer/service
type, but in a "nop" mode. Meaning the (middleware) service would essentially do nothing more then passing the request and response.

Middleware provided by `rama` should provide this for all types that are commonly used in a setting where they might be opt-in.
Please do [open an issue](https://github.com/plabayo/rama/issues) if you notice a case for which this is not yet possible.

Another option is to use [`Either`] on the internal policy/config items used by your layer.

[`Either`]: https://ramaproxy.org/docs/rama/service/util/combinators/enum.Either.html
