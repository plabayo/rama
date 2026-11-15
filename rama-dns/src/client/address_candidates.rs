//! Lazy DNS sources shared by discovery and transport connectors.
use super::resolver::{DnsAddressResolver, HappyEyeballAddressResolverExt as _};
use rama_core::{
    error::{BoxError, ErrorContext as _},
    extensions::Extensions,
    futures::{StreamExt as _, stream::BoxStream},
};
use rama_net::{
    address::{Domain, Host},
    client::AddressCandidates,
};
use rama_utils::macros::generate_set_and_with;
use std::{net::IpAddr, sync::Arc};

/// A lazy, happy-eyeballs-ordered DNS address source.
///
/// Construction and cloning perform no DNS work. Each consumed stream resolves
/// using its current request policy; resolver caching remains the resolver's job.
/// Bind the source to a physical endpoint using `ConnectorTargetStream`.
/// No answer or hint limits are imposed; callers may supply a bounded resolver.
#[derive(Debug, Clone)]
pub struct DnsAddressCandidates<R> {
    resolver: R,
    domain: Domain,
    hints: Option<Arc<[IpAddr]>>,
}

impl<R> DnsAddressCandidates<R> {
    /// Store a resolver and domain without starting a lookup.
    pub fn new(resolver: R, domain: Domain) -> Self {
        Self {
            resolver,
            domain,
            hints: None,
        }
    }

    generate_set_and_with! {
        /// Supply endpoint-specific hints for use while DNS has no ready address.
        /// Caller resolver overrides suppress hints. IP-family policy and address
        /// deduplication are applied by the shared happy-eyeballs resolver.
        pub fn hints(mut self, hints: impl Into<Arc<[IpAddr]>>) -> Self {
            self.hints = Some(hints.into());
            self
        }
    }
}

impl<R: DnsAddressResolver> AddressCandidates for DnsAddressCandidates<R> {
    fn domain(&self) -> &Domain {
        &self.domain
    }

    fn stream<'a>(&'a self, extensions: &'a Extensions) -> BoxStream<'a, Result<IpAddr, BoxError>> {
        // Defer even resolver stream construction until the transport polls us.
        rama_core::futures::stream::once(async move {
            self.resolver
                .happy_eyeballs_resolver(Host::Name(self.domain.clone()))
                .with_extensions(extensions)
                .with_hints(self.hints.as_deref().unwrap_or_default())
                .lookup_ip()
                .map(|result| result.into_box_error())
        })
        .flatten()
        .boxed()
    }
}

#[cfg(test)]
mod tests;
