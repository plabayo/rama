# ❓FAQ

## Why the name "rama"?

The name _rama_ is Japanese for llama and written as "ラマ".
This animal is used as a our mascot and spiritual inspiration of this framework.
It was chosen to honor our connection with Peru, the homeland of this magnificent animal,
and translated into Japanese because we gratefully have built _rama_
upon the broad shoulders of [Tokio and its community](https://tokio.rs/).
The name reminds us to the city of Tokyo.

## On which platform can I run rama?

In theory you should be able to run on any platform which is supported by [our MSVR](https://github.com/plabayo/rama/tree/main?tab=readme-ov-file#minimum-supported-rust-version) and which is supported by [Tokio](https://tokio.rs).

See [the Compatibility info in the book](https://ramaproxy.org/book/crate.html#--compatibility) for more information.

Please [open an issue](https://github.com/plabayo/rama/issues) in case you have troubles using rama on your platform.

## Can I use rama without using Async?

Yes—at a synchronous boundary. Rama is async-first and uses Tokio internally,
but `std` builds expose `rama::rt::blocking::{Runtime, Service, Stream, Io}`
and the `rama::BlockingService` trait. For example,
`EasyHttpWebClient::try_blocking()` creates a cloneable blocking HTTP client
that can also open blocking WebSocket connections.

For custom code, compose the usual async Rama services, then use
`Runtime::service`, `Runtime::stream`, or `Runtime::io` at the synchronous
boundary. `Runtime::service` preserves your service type and clones it per call;
pass an `Arc` yourself when calls should share a non-`Clone` service. The runtime
owns a dedicated thread and remains alive through its derived wrappers. Blocking
operations should not run directly on an async executor thread; use the async
API there or move the blocking call into `tokio::task::spawn_blocking` or
`tokio::task::block_in_place`.

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

Yes. While it is not recommended to do so you can use the `rama-tower` crate to achieve this.

You can find an example on how to do this at
<https://github.com/plabayo/rama/blob/main/examples/src/http_rama_tower.rs>.

Please make sure to read the lib docs at <https://ramaproxy.org/docs/rama/utils/tower/index.html>
if you're planning to make use of it.

## Can I build Web Services with Rama?

Yes you can, there are even some examples:

- [http_k8s_health.rs](https://github.com/plabayo/rama/tree/main/examples/src/http_k8s_health.rs):
  built-in web service that can be used as a k8s health service for proxies deploying as a k8s deployment;
- [http_key_value_store.rs](https://github.com/plabayo/rama/tree/main/examples/src/http_key_value_store.rs):
  a web service example showcasing how one might do a key value store web service using `Rama`;
- [http_web_service_dir_and_api.rs](https://github.com/plabayo/rama/tree/main/examples/src/http_web_service_dir_and_api.rs):
  a web service example showcasing how one can make a web service to serve a website which includes an XHR API;
- [/examples/src/http_web_router.rs](https://github.com/plabayo/rama/tree/main/examples/src/http_web_router.rs):
  a web service example showcasing demonstrating how to create a web router,
  which is excellent for the typical path-centric routing,
  and an approach you'll recognise from most other web frameworks out there.
- [/examples/src/http_record_har.rs](https://github.com/plabayo/rama/tree/main/examples/src/http_record_har.rs)
  Demo of HAR HTTP layer provided by rama

In light of Rama's support for the development of proxy services
these capabilities are also useful to write web services that run as part of a proxy service, e.g.:

- a k8s health service ([/examples/src/http_k8s_health.rs](https://github.com/plabayo/rama/tree/main/examples/src/http_k8s_health.rs));
- a metric exposure service;
- a minimal api service (e.g. to expose device profiles or certificates);
- a graphical interface / control panel;

Please consult [./web_servers.md](./web_servers.md) for more information.

## Help! I get trait-related compile errors that I do not understand!!

Rama's code is written in a very generic manner, which combined with the fact that it is written with a tokio
multithreaded work-stealing environment and at the same time with the goal to provide you with high level ergonomical features, results in a pretty complicated set of trait bounds and restrictions of all kinds.

As such it is very easy to write code — especially when you're new to `rama` — which will give a compiler error for which you have no clue how to resolve it. Sometimes the answer can be found in the compiler output if you know at what line to spot, but at times the answer is not there at all.

`rama` boxes as little as possible, so long type signatures show up in these errors.

> [!NOTE]
> You can learn more about [Dynamic- vs Static dispatch here](./intro/dynamic_dispatch.md).

Most commonly you get these errors for high level http service handlers. For a function that is not a valid
endpoint the compiler reports "`...` is not a valid web endpoint", with notes on the rules it has to follow.
The cause is usually one of these:

- add a service struct or function which does not implement `Clone` (a requirement);
- use something which is not `Send/Sync/'static`, while it is expected to be;
- return `impl IntoResponse` while an extractor's `Rejection` cannot be converted into an `ErrorResponse`;
- return `Result<O, E>` while `E` does not implement `From<Rejection>` for every extractor argument;
- return `Result<O, E>` where `O` does not implement `IntoResponse` or `E` does not implement `Into<ErrorResponse>`
  (implementing `IntoResponse` for `E` is enough).

The full rules are documented at [`EndpointServiceFn`](https://ramaproxy.org/docs/rama/http/service/web/trait.EndpointServiceFn.html).

There are other possibilities to get long wielded compiler errors as well. It is not feasible to list all possible reasons here, but know most likely it is among the lines of the examples above. If not, and you continue to be stuck, to feel free to join our discord at <https://discord.gg/29EetaSYCD> and reach out for help. We're here for you.

## my cargo check/build/... commands take forever

[Service stacks](./intro/service_stack.md) can become quiet complex in Rama. In case you notice that your current change
makes the `cargo check` command (or something similar) becomes very slow, it should hopefully be clear
why by checking `git diff` or a similar VCS action.

The most common reasons for this is if:

1. you have a very large function which also contains deeply nested generic types;
2. you have a lot of [`Either`] or optional service/layer stuff within your [Service stacks](./intro/service_stack.md).

It's especially (2) that can slow you down if you overuse it. This usually comes up in case you use
plenty of `Option<L>` layers to optionally create a layer based on a certain input/config variable.
While this might seem like a good idea, and it can be if used sparingly, it can really slow you down once you
use a couple of these. This is because under the hood this results in a [`MaybeLayeredService<S, L>`],
which holds either `L::Service` or your `S` service (stack), so the compiler has to type check
and generate code for both branches. Do that a couple of times and the number of branches multiplies.

Therefore it is recommended for optional layers/services to instead provide an option to create the same kind of layer/service
type, but in a "nop" mode. Meaning the (middleware) service would essentially do nothing more then passing the request and response.

Middleware provided by `rama` should provide this for all types that are commonly used in a setting where they might be opt-in.
Please do [open an issue](https://github.com/plabayo/rama/issues) if you notice a case for which this is not yet possible.

Another option is to use [`Either`] on the internal policy/config items used by your layer.

[`Either`]: https://ramaproxy.org/docs/rama/combinators/enum.Either.html
[`MaybeLayeredService<S, L>`]: https://ramaproxy.org/docs/rama/layer/struct.MaybeLayeredService.html

## In the echo server, why are tls.ja3 and tls.ja4 profiles null?

> Originally posted in <https://github.com/plabayo/rama/issues/543> by [@skilbjo](https://github.com/skilbjo).

In <https://echo.ramaproxy.org/> we usually show the following information per fingerprint "algorithm" (e.g. ja3 and ja4):

* the information for the actual incoming request/connection, often labeled as "verbose" or "hash"
* if possible the values for the embedded profile matching the given user-agent (based on the user-agent http header)

The latter is what the question is about. Rama only embeds profiles of the latest relevant User Agents used
in the real world in the context of user agent emulation. These are for example the majority marketshare web
browsers but can also be common network stacks used in native applications such as iOS or Android applications.

You can find all user agent profiles embedded with rama at: <https://github.com/plabayo/rama/blob/main/rama-ua/src/profile/format/embed_profiles.bin>
(a zstd-compressed profile archive; browse it with `rama ua view <file> --authorized`).

It is not within the scope of rama to provide an exhaustive database (embedded or not) of all possible
user-agents found in the while. You can however easily build this yourself by stacking the appropriate
rama layer services in your own rama-based network stacks.

## My proxy build with Rama fails with "Too many open files". What should I do?

If your Rama based proxy fails with "Too many open files", it means the process
has hit the per process file descriptor limit. Each connection consumes at least one file descriptor,
and high concurrency proxies can exhaust this limit quickly.

You should raise the soft file descriptor limit at startup using
[`rama::unix::utils::raise_nofile`](https://ramaproxy.org/docs/rama/unix/utils/fn.raise_nofile.html).

A practical default for proxies is `65_535`.
The function will automatically clamp the requested value to the system hard limit.

Call it once at the start of `main`, before you bind any listeners.
It returns a `std::io::Result<()>`, so you can propagate or log a failure.

If raising the limit fails or has no effect, your system hard limit may be too low.
In that case, increase it via your service manager or OS configuration,
for example by setting `LimitNOFILE=65535` in a systemd unit or adjusting `ulimit -n`
before launching the process.

## Would you be open to add support for X?

You might wonder if we support a certain protocol or feature.

The answer is usually the same: if it is related to or in function of networking,
than it can be considered in scope. For protocol support it usually does have to mean it is a protocol
that has an RFC or some equivalent public document used by multiple independent organisations.

There might of course be exceptions.

Please [open an issue](https://github.com/plabayo/rama/issues) or talk to us on Discord to get
the ball rolling in regards to your questions.
