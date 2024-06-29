# Http Clients

In [The "🗼 Services all the way down 🐢" chapter](./intro/services_all_the_way_down.md) you can read and learn that a big pillar of Rama's architecture is build on top of the [`Service`][rama-service] concept. A [`Service`][rama-service] takes as input a user-defined `State` (e.g. containing your database Pool) and a `Request`, and uses it to serve either a `Response` or `Error`. Such a [`Service`][rama-service] can produce the response "directly" (also called ☘️ Leaf services) or instead pass the request and state to an inner [`Service`][rama-service] which it wraps around (so called 🍔 Middlewares).

[rama-service]: https://ramaproxy.org/docs/rama/service/trait.Service.html

It's a powerful concept, originally introduced to Rust by [the Tower ecosystem](https://github.com/tower-rs/tower) and allows you build complex stacks specialised to your needs in a modular and easy manner. Even cooler is that this works for both clients and servers alike.

Rama provides an [`HttpClient`](https://ramaproxy.org/docs/rama/http/client/struct.HttpClient.html) which sends your _Http_ `Request` over the network and returns the `Response` if it receives and read one or an `Error` otherwise. Combined with [the many Layers (middleware)](https://ramaproxy.org/docs/rama/http/layer/index.html) that `Rama` provides and perhaps also some developed by you it is possible to create a powerful _Http_ client suited to your needs.

As a 🍒 cherry on the cake you can import the [`HttpClientExt`](https://ramaproxy.org/docs/rama/http/client/trait.HttpClientExt.html) trait in your Rust module to be able to use your _Http_ Client [`Service`][rama-service] stack using a high level API to build and send requests with ease.

## Http Client Example

> The full example can be found at <https://github.com/plabayo/rama/tree/main/examples/http_high_level_client.rs>.

```rust
use rama::http::client::HttpClientExt;

let client = ServiceBuilder::new()
    .layer(TraceLayer::new_for_http())
    .layer(DecompressionLayer::new())
    .layer(
        AddAuthorizationLayer::basic("john", "123")
            .as_sensitive(true)
            .if_not_present(),
    )
    .layer(RetryLayer::new(
        ManagedPolicy::default().with_backoff(ExponentialBackoff::default()),
    ))
    .service(HttpClient::default());

#[derive(Debug, Deserialize)]
struct Info {
    name: String,
    example: String,
    magic: u64,
}

let info: Info = client
    .get("http://example.com/info")
    .header("x-magic", "42")
    .typed_header(Accept::json())
    .send(Context::default())
    .await
    .unwrap()
    .try_into_json()
    .await
    .unwrap();
```
