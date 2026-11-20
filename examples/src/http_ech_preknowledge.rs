//! Supply endpoint-local ECH knowledge without any DNS lookup.
//!
//! Run with features `http-full,boring`, followed by an HTTPS URL, an IP:port
//! endpoint, and a binary ECHConfigList file obtained from your trusted source.
//! The server must support H2 and accept that ECH configuration. The URL keeps
//! its original HTTP authority and TLS identity; only the dial endpoint changes.

#![expect(clippy::print_stdout, reason = "example response output")]

use rama::http::service::client::HttpClientExt as _;
use rama::{
    bytes::Bytes,
    error::BoxError,
    extensions::Extensions,
    graceful::WeakScope,
    http::{
        client::EasyHttpConnectorBuilder,
        conn::{HttpOrigin, HttpServiceCandidate, HttpServiceCandidates},
    },
    net::{
        address::{HostWithPort, SocketAddress},
        tls::{ApplicationProtocol, TargetEchConfig},
    },
    tls::client::{EchRequirement, TlsClientConfig},
};

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let mut args = std::env::args().skip(1);
    let url = args
        .next()
        .ok_or("expected HTTPS URL, IP:port and ECHConfigList file")?;
    let endpoint: SocketAddress = args.next().ok_or("missing IP:port")?.parse()?;
    let target: HostWithPort = endpoint.to_string().parse()?;
    let ech = Bytes::from(std::fs::read(
        args.next().ok_or("missing ECHConfigList file")?,
    )?);
    let uri: rama::net::uri::Uri = url.parse()?;
    if uri.scheme() != Some(&rama::net::Protocol::HTTPS) {
        return Err("expected an HTTPS URL".into());
    }
    let origin = HttpOrigin::new(
        rama::net::Protocol::HTTPS,
        uri.host_with_opt_port()
            .ok_or("missing URL authority")?
            .into_host_with_port_or(443),
    )?;
    let facts = Extensions::new();
    facts.insert(TargetEchConfig::new(target.clone(), ech));
    let candidates = HttpServiceCandidates::new_with_extensions(
        origin,
        [(
            HttpServiceCandidate::new(ApplicationProtocol::HTTP_2, target),
            facts,
        )],
    )
    .with_origin_fallback(false);
    let client = EasyHttpConnectorBuilder::new(WeakScope::detached())
        .with_default_transport_connector()
        .without_dns_connector()
        .without_proxy_support()
        .with_tls_support_using_boringssl(TlsClientConfig::new())
        .with_default_http_connector()
        .with_default_connection_pool()
        .build_client();
    let response = client
        .get(url)
        .extension(candidates)
        .extension(EchRequirement::Required)
        .send()
        .await?;
    println!("{}", response.status());
    Ok(())
}
