//! Linux transparent TCP proxy example using TPROXY.
//!
//! This example shows how to:
//!
//! - create a TCP listener with `IP_TRANSPARENT`;
//! - recover the original destination using
//!   `rama::net::socket::linux::ProxyTargetFromGetSocketnameLayer`;
//! - forward the intercepted stream to that destination.
//!
//! It is intentionally small and only demonstrates the ingress side of a Linux
//! transparent proxy. Production deployments usually also need explicit egress
//! bypass rules so the proxy does not capture its own outbound traffic.
//!
//! # Test status
//!
//! Unlike most examples in this repository, this one is not covered by the
//! regular integration example test suite.
//!
//! It requires all of the following at runtime:
//!
//! - Linux kernel support for TPROXY and policy routing;
//! - `nft` and `ip` userspace tooling;
//! - privileges such as `CAP_NET_ADMIN` or `root`;
//! - permission to modify host networking state.
//!
//! Those requirements are not available in normal CI environments, so this
//! example should be treated as a manual end-to-end validation example.
//! The helper scripts and test instructions below are the intended way to
//! verify it on a suitable Linux machine.
//!
//! # Platform support
//!
//! This example is intended for Linux only. On non-Linux platforms the binary
//! exits immediately with a short message.
//!
//! # Run the example
//!
//! ```sh
//! cargo build --example linux_tproxy_tcp --features=tcp,http && \
//!     sudo target/debug/examples/linux_tproxy_tcp
//! ```
//!
//! The proxy listens on `0.0.0.0:62052`.
//!
//! # Required Linux setup
//!
//! The listener uses `IP_TRANSPARENT`, which requires `CAP_NET_ADMIN`
//! privileges. Running the example with `sudo` is the easiest way to try it.
//!
//! The easiest path is to use the helper scripts in this directory:
//!
//! ```sh
//! sudo ./examples/linux_tproxy_tcp_setup.sh
//! ```
//!
//! and after testing:
//!
//! ```sh
//! sudo ./examples/linux_tproxy_tcp_cleanup.sh
//! ```
//!
//! These scripts use a dedicated `nftables` table and a dedicated policy
//! routing rule so cleanup is straightforward and low-risk. They also mark
//! matching locally generated traffic in `OUTPUT`, so requests created on the
//! same Linux host are intercepted too.
//!
//! The setup script defaults to:
//!
//! - listener port `62052`
//! - intercepted destination port `80`
//! - fwmark `1`
//! - route table `100`
//! - proxy uid exemption `0` (`root`)
//!
//! You can override them:
//!
//! ```sh
//! sudo PORT=62052 INTERCEPT_PORT=443 FWMARK=9 ROUTE_TABLE=109 PROXY_UID=1000 \
//!   ./examples/linux_tproxy_tcp_setup.sh
//! ```
//!
//! Manual `iptables` or manual `nftables` setup is also valid if you prefer a
//! different approach. The helper scripts are only one conservative default.
//! The default `PROXY_UID=0` exemption avoids proxy loops when the example runs
//! as `root`, which means a normal user `curl ...` is intercepted by default,
//! while `sudo curl ...` is not.
//!
//! # Test 1: direct host-local test
//!
//! ```sh
//! cargo run --example linux_tproxy_tcp --features=tcp
//! sudo ./examples/linux_tproxy_tcp_setup.sh
//! curl http://example.com
//! ```
//!
//! You should see a log in the proxy with the peer address and original
//! destination. If you use `sudo curl`, it will be exempt by default.
//!
//! # Test 2: watch the rule counters
//!
//! ```sh
//! watch -n1 'sudo nft -a list table inet rama_tproxy_tcp'
//! ```
//!
//! In another terminal:
//!
//! ```sh
//! curl http://example.com
//! ```
//!
//! You should see the explicit nft `counter packets ... bytes ...` values
//! increase on both the `output` and `prerouting` rules.




#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("the linux_tproxy_tcp example only supports Linux");
}

#[cfg(target_os = "linux")]
use ::{
    rama::{
        Layer, Service,
        net::{
            address::SocketAddress,
            proxy::IoForwardService,
            socket::{
                SocketOptions,
                linux::ProxyTargetFromGetSocketnameLayer,
                opts::{Domain, TcpKeepAlive},
            },
            stream::Socket,
        },
        rt::Executor,
        service::service_fn,
        tcp::{TcpStream, proxy::IoToProxyBridgeIoLayer, server::TcpListener},
        telemetry::tracing::{
            self,
            level_filters::LevelFilter,
            subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
        },
    },
    std::time::Duration,
};

#[cfg(target_os = "linux")]
const LISTEN_ADDR: SocketAddress = SocketAddress::default_ipv4(62052);

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    if let Err(err) = run().await {
        tracing::error!(error = %err, "linux tproxy tcp example failed");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let exec = Executor::default();

    let socket = SocketOptions {
        address: Some(LISTEN_ADDR),
        ip_transparent: Some(true),
        freebind: Some(true),
        reuse_address: Some(true),
        reuse_port: Some(true),
        tcp_no_delay: Some(true),
        tcp_keep_alive: Some(TcpKeepAlive {
            time: Some(Duration::from_mins(2)),
            interval: Some(Duration::from_secs(30)),
            #[cfg(not(target_os = "windows"))]
            retries: Some(5),
        }),
        ..SocketOptions::default_tcp()
    }
    .try_build_socket(Domain::IPv4)?;
    socket.listen(32_768)?;

    let listener = TcpListener::bind_socket(socket, exec.clone()).await?;

    tracing::info!(listen.address = %LISTEN_ADDR, "transparent tcp proxy listening");
    tracing::info!("make sure Linux policy routing and TPROXY rules are installed first");

    let service = ProxyTargetFromGetSocketnameLayer::new().into_layer(service_fn({
        let forward = IoToProxyBridgeIoLayer::extension_proxy_target(exec)
            .into_layer(IoForwardService::new());
        move |stream: TcpStream| {
            let forward = forward.clone();
            async move {
                let original_dst = stream.local_addr()?;
                let peer_addr = stream.peer_addr()?;
                tracing::info!(
                    network.peer.address = %peer_addr.ip_addr,
                    network.peer.port = peer_addr.port,
                    network.original.address = %original_dst.ip_addr,
                    network.original.port = original_dst.port,
                    "accepted intercepted tcp flow"
                );
                forward.serve(stream).await
            }
        }
    }));

    listener.serve(service).await;
    Ok(())
}
