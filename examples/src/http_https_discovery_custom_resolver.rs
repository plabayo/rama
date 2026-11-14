//! Send HTTPS using one explicitly chosen resolver for HTTPS and address records.
//!
//! Run with features `http-full,boring,dns-hickory`, optionally passing a URL.
//! Hickory owns DNS caching; discovery does not add another cache. The reusable
//! `HttpsServiceLayer::with_resolver` exposes the same contract for custom stacks.

#![expect(clippy::print_stdout, reason = "example response output")]

use rama::http::service::client::HttpClientExt as _;
use rama::{
    dns::client::HickoryDnsResolver,
    error::BoxError,
    graceful::WeakScope,
    http::{Body, client::EasyHttpConnectorBuilder},
    tls::client::TlsClientConfig,
};

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let resolver = HickoryDnsResolver::try_new_system()?;
    let client = EasyHttpConnectorBuilder::new()
        .with_default_transport_connector()
        .with_dns_resolver(resolver)
        .without_tls_proxy_support()
        .without_proxy_support()
        .with_tls_support_using_boringssl(TlsClientConfig::new().with_encrypted_client_hello(true))
        .with_default_http_connector::<Body>(WeakScope::detached())
        .with_default_connection_pool()
        .build_client();
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://example.com/".into());
    let response = client.get(url).send().await?;
    println!("{}", response.status());
    Ok(())
}
