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
pub async fn lookup_authority(
    authority: address::Authority,
) -> std::io::Result<impl Iterator<Item = SocketAddr>> {
    match authority.host() {
        address::Host::Address(ip) => Ok(vec![SocketAddr::new(*ip, authority.port())].into_iter()),
        address::Host::Name(_) => tokio::net::lookup_host(authority.to_string())
            .await
            .map(Iterator::collect)
            .map(Vec::into_iter),
    }
}
