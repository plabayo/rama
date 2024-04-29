# Web Servers

Rama is a modular service framework, but we want to make it very clear upfront
that it is not our primary goal to use it for developing web services, at least not for the majority of people.

That said, there is a lot of overlap, and for cases where you do need web-service like functionality in function of your proxy process you'll notice that rama on itself provides everything that you really need.

Examples of the kind of web services you might build with `rama` in function of your proxy service:

- a k8s health service (see code example at [/examples/http_k8s_health.rs](https://github.com/plabayo/rama/tree/main/examples/http_k8s_health.rs));
- a metric exposure service;
- a minimal api service (e.g. to expose device profiles or certificates);
- a graphical interface / control panel;

## Axum

In case you need a web server for a full fledged API or website, you might want to consider [Axum](https://docs.rs/axum/latest/axum) as an alternative. It runs on Tokio just like Rama, and can be run within the same process
as your proxy app. Given Rama does support web servers and more, you might as well stick to Rama for web services in support of your proxy.

To be clear, there is no web service that you can make with Axum that you cannot build with Rama instead.
And in fact a lot of ideas and even code were copied directly from Axum. The major difference is however
that Axum is focussed on being an excellent modular web framework for building websites and APIs, while Rama is not.
As such Axum has a lot of code to do the heavy lifting for you and make building such stacks more ergonomic.

Rama has these as well, but the user experience especially for compiler error diagnostics might be better with Axum, as they took a lot of care in getting that as right as can possibly be.

There are of course also other difference, some bigger then others. Point being, use Axum if you need to build
specialised Web Servers, use Rama in case your prime focus is on proxies instead.

If you are a bit like us,
do feel free to use Rama for using [Http Clients](./http_clients.md) and [Web Services](./web_servers.md). Either way the choice is yours, but keep in mind that Rama might still have some sharp edges, whereas an excellent project like [Axum](https://docs.rs/axum/latest/axum) will be a much smoother and easier experience for most.

## Proxy Web Services

A proxy service is of course also a type of web service, but for this context we are not talking about
proxy web services. Instead we are talking about serving Http API's, web pages or other static content. Such services can even be part of your Proxy Service:

- a k8s health service ([/examples/http_k8s_health.rs](https://github.com/plabayo/rama/tree/main/examples/http_k8s_health.rs));
- a metric exposure service;
- a minimal api service (e.g. to expose device profiles or certificates);
- a graphical interface / control panel;

## Examples

All rama [examples can be found in the `/examples` dir](https://github.com/plabayo/rama/tree/main/examples).

Here are some low level web service examples without fancy features:

- [/examples/http_listener_hello.rs](https://github.com/plabayo/rama/blob/main/examples/http_listener_hello.rs): is the most basic example on how to provide
  a root service with no needs for endpoints or anything else (e.g. good enough for some use cases related
  to health services or metrics exposures);
  - [/examples/http_health_check.rs](https://github.com/plabayo/rama/blob/main/examples/http_health_check.rs) is an even more minimal example
    of a health check service returning a _200 OK_ for any incoming request.
- [/examples/http_service_hello.rs](https://github.com/plabayo/rama/blob/main/examples/http_service_hello.rs): is an example similar to the previous
  example but shows how you can also operate on the underlying transport (TCP) layer, prior to passing it to your
  http service;

There's also a premade webservice that can be used as the health service for your proxy k8s workloads:

- [/examples/http_k8s_health.rs](https://github.com/plabayo/rama/tree/main/examples/http_k8s_health.rs):
  built-in web service that can be used as a k8s health service for proxies deploying as a k8s deployment;

The following are examples that use the high level concepts of Request/State extractors and IntoResponse converters,
that you'll recognise from `axum`, just as available for `rama` services:

- [/examples/http_key_value_store.rs](https://github.com/plabayo/rama/tree/main/examples/http_key_value_store.rs):
  a web service example showcasing how one might do a key value store web service using `Rama`;
- [/examples/http_web_service_dir_and_api.rs](https://github.com/plabayo/rama/tree/main/examples/http_web_service_dir_and_api.rs):
  a web service example showcasing how one can make a web service to serve a website which includes an XHR API;

For a production-like example of a web service you can also read the [`rama-fp` source code](https://github.com/plabayo/rama/tree/main/rama-fp/src).
This is the webservice behind the Rama fingerprinting service, which is used by the maintainers of 🦙 Rama (ラマ) to generate
the UA emulation data for the Http and TLS layers. It is not meant to fingerprint humans or users. Instead it is meant to help
automated processes look like a human.

> This example showcases how you can make use of the [`match_service`](https://ramaproxy.org/docs/rama/http/service/web/macro.match_service.html)
> macro to create a `Box`-free service router. Another example of this approach can be seen in the
> [http_service_match.rs](https://github.com/plabayo/rama/tree/main/examples/http_service_match.rs) example.
