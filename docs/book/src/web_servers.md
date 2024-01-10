# Web Servers

Rama is a modular proxy framework, and we want to make it very clear upfront
that it is not our goal to also be a framework for developing web services.
There is however overlap, and for cases where you do need web-service like functionality
in function of your proxy process you'll notice that rama on itself provides everything
that you really need. But because developing web servers for the purpose of websites, http API's,
or other kinds of web applications is not our focus you'll not find anything fancy or 'magical'
that you might be used to in other frameworks.

> We recommend the usage of <https://docs.rs/axum/latest/axum/> in case you need a web server
> for a full fledged API or website. It runs on Tokio as well, and can be run within the same process
> as your proxy app. However, we believe that for anythng related to proxy technologies you should be able
> to use Rama as-is. More on that later.
>
> To be clear, there is no web service that you can make with Axum that you cannot build with Rama instead.
> And in fact a lot of ideas and even code were copied directly from Axum. The major difference is however
> that Axum is focussed on being an excellent modular web framework for building websites and APIs, while Rama is not.
> As such Axum has a lot of code to do the heavy lifting for you and make building such stacks more ergonomic.
> Notably are the request Extractors (`FromRequestParts`) and Response creators (`IntoResponse`). The latter has
> been copied into Rama, the first not.

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

All rama [examples can be found in the `./examples` dir](https://github.com/plabayo/rama/tree/main/examples).

- <https://github.com/plabayo/rama/blob/main/examples/http_listener_hello.rs>: is the most basic example on how to provide
  a root service with no needs for endpoints or anything else (e.g. good enough for some use cases related
  to health services or metrics exposures);
  - <https://github.com/plabayo/rama/blob/main/examples/http_health_check.rs> is an even more minimal example
    of a health check service returning a _200 OK_ for any incoming request.
- <https://github.com/plabayo/rama/blob/main/examples/http_service_hello.rs>: is an example similar to the previous
  example but shows how you can also operate on the underlying transport (TCP) layer, prior to passing it to your
  http service;

There are also plans to provide a web router, which will be part of the first useable release of Rama.

TODO: document web router here a bit as one of its introductions.
