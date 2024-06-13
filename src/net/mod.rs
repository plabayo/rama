//! protocol agnostic network modules

pub mod address;
pub mod stream;
pub mod user;

pub(crate) mod proto;
use std::net::SocketAddr;

#[doc(inline)]
pub use proto::Protocol;

/// Performs a DNS resolution.
///
/// The returned iterator may not actually yield any values depending on the
/// outcome of any resolution performed.
///
/// This API is not intended to cover all DNS use cases. Anything beyond the
/// basic use case should be done with a specialized library.
pub async fn lookup_host(
    host: address::Host,
    port: u16,
) -> std::io::Result<impl Iterator<Item = SocketAddr>> {
    match host {
        address::Host::Address(ip) => Ok(vec![SocketAddr::new(ip, port)].into_iter()),
        address::Host::Name(domain) => tokio::net::lookup_host(format!("{domain}:{port}"))
            .await
            .map(Iterator::collect)
            .map(Vec::into_iter),
    }
}
