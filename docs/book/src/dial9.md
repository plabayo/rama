# 🐕 dial9

[dial9] records Tokio scheduling and rama protocol activity for offline diagnostics.
Enable rama’s optional Dial9 support and attach an application-owned recorder.
One recorder can serve multiple runtimes; the application chooses storage,
profiling sources and when recording starts or stops.

The [local recording example] shows bounded disk storage, application events,
recorder health and copying completed segments into a diagnostics bundle.
Segment size, total size and rotation are configurable. Retained history depends
on traffic; leave disk headroom around the retention budget.

Rama correlates protocol operations across task boundaries, including HTTP
requests and streaming responses, WebSockets and QUIC. Applications can add
their own events to the same flow. The [Apple transparent proxy example] shows
an integration at a synchronous runtime boundary.

Recording has a cost. Start with lifecycle events and measure your workload
before adding profiling sources. Tokio’s unstable instrumentation expands task
coverage; platform support and further options are described [upstream][dial9].

[dial9]: https://github.com/dial9-rs/dial9
[local recording example]: https://github.com/plabayo/rama/blob/main/examples/src/dial9_local.rs
[Apple transparent proxy example]: https://github.com/plabayo/rama/tree/main/ffi/apple/examples/transparent_proxy
