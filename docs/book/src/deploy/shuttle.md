# 🚀 Rama x Shuttle

[![Crates.io](https://img.shields.io/crates/v/shuttle-rama.svg)](https://crates.io/crates/shuttle-rama)
[![Docs.rs](https://img.shields.io/docsrs/shuttle-rama/latest)](https://docs.rs/shuttle-rama/latest/shuttle_rama/index.html)

[Shuttle](https://www.shuttle.dev/) is a Rust-native cloud development platform that allows you to deploy your app while handling all of the underlying infrastructure. Rama is
[one of several officially supported frameworks](https://docs.shuttle.dev/welcome/introduction#supported-frameworks)
available in Shuttle’s SDK crate collection.

<div class="book-article-image-center">
<img style="width: 90%" src="../img/shuttle_x_rama.jpg" alt="visual representation of Rama and Shuttle in harmony">
</div>

## What is Shuttle?

Shuttle is designed with a strong focus on developer experience, aiming to make application development and deployment as effortless as possible. Its powerful capabilities simplify resource provisioning. For example, provisioning a database is as easy as using a macro:

```rust
#[shuttle_runtime::main]
async fn main(
    // Automatically provisions a Postgres database
    // and provides an authenticated connection pool
    #[shuttle_shared_db::Postgres] pool: sqlx::PgPool,
) -> Result<impl shuttle_rama::ShuttleService, shuttle_rama::ShuttleError> {
    // Application code
}
```

With Shuttle, you can hit the ground running and quickly turn your ideas into real, deployable applications. It enables rapid prototyping and deployment, helping you bring your vision to life faster than ever.

## `shuttle-rama`: Hello World

> 💡 Prerequisites:
>
> 1. Install Shuttle: <https://docs.shuttle.dev/getting-started/installation>
> 2. Create a Shuttle account or log in: <https://docs.shuttle.dev/getting-started/quick-start#login-to-your-account>

In this section, we’ll walk through a simple example of how to build and deploy a Rama-based service with Shuttle. You can get started in just three steps:

1. Initialize a new Rama project using the `shuttle init --template rama` command.
2. Copy and paste the contents of the example you wish to deploy—be sure to check the snippet tabs to ensure you're copying the correct code and files.
3. Run the `shuttle deploy` command.

Start with:

```sh
shuttle init --template rama
```

Next, copy the `src` files and `Cargo.toml` content from the example you want to use, available at <https://github.com/shuttle-hq/shuttle-examples/tree/main/rama>.

You can now run the project locally:

```sh
shuttle run
```

When you're ready to deploy:

```sh
shuttle deploy
```

And that's it—your Rama-based service is now live in the cloud. Enjoy!

To learn more, visit the [official Shuttle documentation](https://docs.shuttle.dev/welcome/introduction), check out [their FAQ](https://docs.shuttle.dev/pricing/faq), or join [their Discord community](https://discord.gg/shuttle).

## Limitations

What’s currently possible:

- Run an _HTTP_ Rama service as an “HTTP application” ([example](https://github.com/shuttle-hq/shuttle-examples/tree/main/rama/hello-world)).
- Run a _TCP_ Rama service as a “TCP acceptor” ([example](https://github.com/shuttle-hq/shuttle-examples/tree/develop/rama/hello-world-tcp)).

Rama is all about empowerment. While a lot is possible with Rama, not everything translates directly to Shuttle deployments. Here are some key limitations:

- Applications on Shuttle **always** run behind a load balancer.
  - The load balancer terminates TLS traffic; you cannot manage TLS yourself (yet). As a result, [Rama's TLS capabilities](https://docs.rs/rama/0.2.0/rama/tls/index.html) cannot be used on Shuttle.
  - Traffic between the load balancer and your app must use HTTP/1.1. This does not impact the HTTP versions supported between clients and the load balancer.
  - Currently, Shuttle only supports HTTP (HTTP/1.1 and HTTP/2). For now, running TCP services on Shuttle has limited practical use. It's recommended to focus on HTTP applications when targeting Shuttle.
- [UDP](https://docs.rs/rama/0.2.0/rama/udp/index.html) traffic is not yet supported on Shuttle.
- [Raw sockets](https://docs.rs/rama/latest/rama/net/socket/struct.Socket.html) are not officially supported, though limited use is possible. No support is provided.
- Incoming HTTP traffic is altered by Shuttle’s load balancer. Therefore, it is not the original client request. This prevents [fingerprinting techniques](https://ramaproxy.org/book/intro/user_agent.html#fingerprinting) from working (for now).

These limitations apply primarily to **ingress** traffic (from client to your service). **Egress** traffic (from your service outward) is unaffected by these restrictions—except for data volume constraints. So there’s still plenty of room for creativity. You can learn more about those limits at <https://www.shuttle.dev/pricing>.
