# 🔭 Telemetry

> One accurate measurement is worth a thousand expert opinions.
>
> — _Grace Hopper_.

[Tracing][tracing] is a technique used in software development to understand how a system is performing and where issues might be occurring. It involves tracking the flow of requests as they move through a system, and collecting data about each step along the way. This data is then used to create a detailed picture of how the system is behaving, and can help developers identify performance bottlenecks or other issues.

To implement [tracing], developers use a technique called "[spans]". A span is a unit of work in a system, such as a function call or a network request. Each span is given a unique identifier and is linked to other [spans] that are related to it. This allows developers to follow the flow of requests through a system and understand how they are being processed.

[Tracing][tracing] is closely related to logging, which is another technique used in software development to capture information about system behavior. However, while logging provides a record of events that have occurred in a system, [tracing] provides a more detailed view of how those events are related to each other and how they are affecting system performance.

[Tracing][tracing] is an important part of the overall telemetry story, which involves collecting data about a system's behavior and using that data to improve its performance. Metrics are another important part of telemetry, and involve collecting numerical data about system performance, such as response times or error rates.

## Tools

[Prometheus](https://prometheus.io/) is a popular open-source tool for collecting and storing metrics data. It provides a powerful query language for analyzing metrics, and can be used to generate alerts when certain conditions are met. [OpenTelemetry](https://opentelemetry.io/) is another open-source project that provides a standard way of collecting telemetry data from different types of systems and applications. It provides standards and specifications on how to structure, name and format telemetry data. Today it is _the_ standard and also the one Rama follows.

Tools like [Jaeger](https://www.jaegertracing.io/) are used to visualize and analyze [tracing] data. Jaeger provides a user interface for exploring [spans] and understanding how they are related to each other. It can also be used to generate reports and identify patterns in system behavior. Overall, [tracing] is an important technique for understanding how a system is performing and can help developers identify and fix issues before they become major problems.

## Rama Telemetry

Rama re-exports [OpenTelemetry](https://opentelemetry.io/) crates under [the `rama::opentelemtry` module](https://ramaproxy.org/docs/rama/telemetry/opentelemetry/index.html),
and provides middlewares for collecting metrics on:

- the http layer: <https://ramaproxy.org/docs/rama/http/layer/opentelemetry/index.html>
- the transport layer: <https://ramaproxy.org/docs/rama/net/stream/layer/opentelemetry/index.html>

Rama also provides a [Prometheus](https://prometheus.io/) exportor to easily export your [OpenTelemetry](https://opentelemetry.io/) metrics
over http, to be consumed by tools such as [Grafana](https://grafana.com/):

- <https://ramaproxy.org/docs/rama/http/service/web/struct.PrometheusMetricsHandler.html>

### Rama Telemetry Example

> Source Code: [/examples/http_telemetry.rs](https://github.com/plabayo/rama/tree/main/examples/http_telemetry.rs)

In this example you can see a web service which keeps track of a visitor counter as a custom opentelemetry counter metric. It also makes use of the rama provided [`RequestMetricsLayer`](https://ramaproxy.org/docs/rama/http/layer/opentelemetry/struct.RequestMetricsLayer.html) and [`NetworkMetricsLayer`](https://ramaproxy.org/docs/rama/net/stream/layer/opentelemetry/struct.NetworkMetricsLayer.html) layers to also some insights in the traffic both on the network- and application (http) layers. These metrics are exported using the [`PrometheusMetricsHandler`](https://ramaproxy.org/docs/rama/http/service/web/struct.PrometheusMetricsHandler.html).

With that example setup you can use a tool like [Grafana](https://grafana.com/) or [Prometheus](https://prometheus.io/) to make a dashboard with your own sharts.

[tracing]: https://tracing.rs/tracing/
[spans]: https://tracing.rs/tracing/#spans