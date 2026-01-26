//! An example to showcase how one can build an authenticated socks5 CONNECT proxy server.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example socks5_connect_proxy --features=dns,socks5
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62021`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v -x socks5://127.0.0.1:62021 --proxy-user 'john:secret' http://www.example.com/
//! curl -v -x socks5h://127.0.0.1:62021 --proxy-user 'john:secret' http://www.example.com/
//! curl -v -x socks5://127.0.0.1:62021 --proxy-user 'john:secret' https://www.example.com/
//! curl -v -x socks5h://127.0.0.1:62021 --proxy-user 'john:secret' https://www.example.com/
//! ```
//!
//! You should see in all the above examples the responses from the server.
//!
//! In case you use wrong credentials you'll see something like:
//!
//! ```sh
//! $ curl -v -x socks5://127.0.0.1:62021 --proxy-user 'john:foo' http://www.example.com/
//! *   Trying 127.0.0.1:62021...
//! * Connected to 127.0.0.1 (127.0.0.1) port 62021
//! * User was rejected by the SOCKS5 server (1 1).
//! * Closing connection
//! curl: (97) User was rejected by the SOCKS5 server (1 1).
//! ```

use rama::{
    net::user::credentials::basic,
    proxy::socks5::Socks5Acceptor,
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
};

use std::time::Duration;

#[tokio::main]
async fn main() {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let graceful = rama::graceful::Shutdown::default();
    let exec = Executor::graceful(graceful.guard());

    let tcp_service = TcpListener::bind("127.0.0.1:62021", exec)
        .await
        .expect("bind proxy to 127.0.0.1:62021");
    let socks5_acceptor =
        Socks5Acceptor::default().with_authorizer(basic!("john", "secret").into_authorizer());
    graceful.spawn_task(tcp_service.serve(socks5_acceptor));

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}
