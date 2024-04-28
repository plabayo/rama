# Web Servers

Rama is a modular proxy framework, and we want to make it very clear upfront
that it is not our goal to also be a framework for developing web services.
There is however overlap, and for cases where you do need web-service like functionality
in function of your proxy process you'll notice that rama on itself provides everything
that you really need.

Examples of the kind of web services you might build with `rama` in function of your proxy service:

- a k8s health service (see code example at <https://github.com/plabayo/rama/tree/main/examples/http_k8s_health.rs>);
- a metric exposure service;
- a minimal api service (e.g. to expose device profiles or certificates);
- a graphical interface / control panel;

## Axum

We recommend the usage of <https://docs.rs/axum/latest/axum/> in case you need a web server
for a full fledged API or website. It runs on Tokio as well, and can be run within the same process
as your proxy app. However, we believe that for anythng related to proxy technologies you should be able
to use Rama as-is. More on that later.

To be clear, there is no web service that you can make with Axum that you cannot build with Rama instead.
And in fact a lot of ideas and even code were copied directly from Axum. The major difference is however
that Axum is focussed on being an excellent modular web framework for building websites and APIs, while Rama is not.
As such Axum has a lot of code to do the heavy lifting for you and make building such stacks more ergonomic.
Rama has these as well, as we forked a lot of axum code to achieve, adapting it to the code and needs of Rama,
but of course the user experience especially for compiler error diagnostics might be better with Axum,
as they took a lot of care in getting that as right as can possibly be.

There are of course also other difference, some bigger then others. Point being, use Axum if you need to build
specialised Web Servers, use Rama in case your focus is on proxies instead. Or if you are a bit like us,
do feel free to use Rama also for that. Either way the choice is yours, but keep in mind that Rama is a proxy framework,
not a web service framework.

> 💡 The reason we want to stress this point is because people have often expectations with high demands when
> searching for and selecting web frameworks, nowawdays more then ever. This does however not mean that one cannot make
> web servers using rama.
>
> In fact we, at [plabayo](https://www.plabayo.tech) develop our company website
> (<https://www.plabayo.tech/>), Free and Open Source Bulletin Software "rora" (<https://github.com/plabayo/rora>),
> bucket (<https://github.com/plabayo/bucket>) and more all by building on top of rama. We do this because we like to know our
> technology stack in as much depth as practically possible, while still caring for our family, and because
> we as minimalists love the balance we strike by dogfeeding on "rama" not only for proxy purposes but
> for all our core web server needs as well.

## Proxy Web Services

A proxy service is of course also a type of web service, but for this context we are not talking about
proxy web services. There are however web services that you might never the less need as part of your
proxy binary, such as:

- A Health Check service is a very trivial service that is used to check if a service is still up and running
  by orchestration systems such as k8s;
- A minimal API web service can be useful for cases where you might need to provide your client with some upfront
  data prior to being able to make the actual request. An example of this is an API to expose the available
  web clients that can be emulated, in case you are making a distort proxy;
- The latter is an example of an intercept service, which can also be useful in case you want to be able to override
  content for specific domains or other rules.

All the above is well within the scope of Rama and can be handled. What is however not in scope is in case
you want to build the backend for your website or to build any other typical kind of backend service. Rama is
first and foremost a proxy framework.

## Examples

All rama [examples can be found in the `/examples` dir](https://github.com/plabayo/rama/tree/main/examples).

Here are some low level web service examples without fancy features:

- <https://github.com/plabayo/rama/blob/main/examples/http_listener_hello.rs>: is the most basic example on how to provide
  a root service with no needs for endpoints or anything else (e.g. good enough for some use cases related
  to health services or metrics exposures);
  - <https://github.com/plabayo/rama/blob/main/examples/http_health_check.rs> is an even more minimal example
    of a health check service returning a _200 OK_ for any incoming request.
- <https://github.com/plabayo/rama/blob/main/examples/http_service_hello.rs>: is an example similar to the previous
  example but shows how you can also operate on the underlying transport (TCP) layer, prior to passing it to your
  http service;
  
There's also a premade webservice that can be used as the health service for your proxy k8s workloads:

- [http_k8s_health.rs](https://github.com/plabayo/rama/tree/main/examples/http_k8s_health.rs):
  built-in web service that can be used as a k8s health service for proxies deploying as a k8s deployment;

The following are examples that use the high level concepts of Request/State extractors and IntoResponse converters,
that you'll recognise from `axum`, just as available for `rama`services:

- [http_key_value_store.rs](https://github.com/plabayo/rama/tree/main/examples/http_key_value_store.rs):
  a web service example showcasing how one might do a key value store web service using `Rama`;
- [http_web_service_dir_and_api.rs](https://github.com/plabayo/rama/tree/main/examples/http_web_service_dir_and_api.rs):
  a web service example showcasing how one can make a web service to serve a website which includes an XHR API;

For a production-like example of a web service you can also read the [`rama-fp` source code](https://github.com/plabayo/rama/tree/main/rama-fp/src).
This is the webservice behind the Rama fingerprinting service, which is used by the maintainers of 🦙 Rama (ラマ) to generate
the UA emulation data for the Http and TLS layers. It is not meant to fingerprint humans or users. Instead it is meant to help
automated processes look like a human.

> This example showcases how you can make use of the [`match_service`](https://ramaproxy.org/docs/rama/http/service/web/macro.match_service.html)
> macro to create a `Box`-free service router. Another example of this approach can be seen in the
> [http_service_match.rs](https://github.com/plabayo/rama/tree/main/examples/http_service_match.rs) example.
