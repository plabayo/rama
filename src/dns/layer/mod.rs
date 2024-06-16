//! Layer to allow custom DNS Resolution within Rama.
//!
//! # Example
//!
//! ```rust
//! use rama::dns::layer::{DnsLayer, DynamicDnsResolver};
//! use rama::http::service::web::{WebService, extract::{Host, Extension}};
//! use rama::http::{Body, Request, RequestContext, Version, StatusCode};
//! use rama::service::{Context, Service, Layer};
//! use rama::net::stream::ServerSocketAddr;
//! use rama::net::Protocol;
//! use std::net::SocketAddr;
//!
//! #[tokio::main]
//! async fn main() {
//!     let dns_layer = DnsLayer::new()
//!         .dns_map_header("x-dns-map".parse().unwrap())
//!         .default_resolver();
//!
//!     let service = dns_layer.layer(WebService::default()
//!         .get("/", |Host(host): Host, Extension(resolved): Extension<ServerSocketAddr>| async move {
//!             assert_eq!(host, "www.example.com");
//!             let expected_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
//!             assert_eq!(resolved.addr(), &expected_addr);
//!             StatusCode::OK
//!         }),
//!     );
//!
//!     let mut ctx = Context::default();
//!     ctx.insert(RequestContext{
//!         http_version: Version::HTTP_11,
//!         protocol: Protocol::Http,
//!         authority: Some("www.example.com:80".try_into().unwrap()),
//!     });
//!
//!     let resp = service.serve(
//!         ctx,
//!         Request::builder()
//!             .uri("http://www.example.com")
//!             .header("x-dns-map", "www.example.com:80=127.0.0.1:8080")
//!             .body(Body::empty()).unwrap(),
//!     ).await.unwrap();
//!     assert_eq!(resp.status(), StatusCode::OK);
//! }
//! ```

use crate::{http::HeaderName, service::Layer};

mod error;
#[doc(inline)]
pub use error::DnsError;

mod dns_resolve;
#[doc(inline)]
pub use dns_resolve::DynamicDnsResolver;

pub(crate) mod dns_map;

mod service;
#[doc(inline)]
pub use service::DnsService;

/// Layer which produces a [`DnsService`] which will resolve the DNS of the given request.
///
/// See [`DnsService`] for more details.
///
/// [`DnsService`]: crate::dns::layer::DnsService
#[derive(Clone)]
pub struct DnsLayer<R> {
    resolver: R,
    resolver_header: Option<HeaderName>,
    dns_map_header: Option<HeaderName>,
}

impl<R> std::fmt::Debug for DnsLayer<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsLayer").finish()
    }
}

impl DnsLayer<()> {
    /// Creates a new [`DnsLayer`].
    pub fn new() -> Self {
        Self {
            resolver: (),
            resolver_header: None,
            dns_map_header: None,
        }
    }
}

impl Default for DnsLayer<()> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R> DnsLayer<R> {
    /// Set the opt-in header for the resolver,
    /// to ensure that the (DNS) resolver is only used when this header is present with the value "1".
    ///
    /// By default, no header is required.
    ///
    /// ## Remarks
    ///
    /// - You still need to define a resolver in order for this header to have any effect.
    /// - Setting this header will make the Request fail in case
    ///   the header is present with a value other then "", "0" or "1".
    pub fn resolve_header(mut self, header_name: HeaderName) -> Self {
        self.resolver_header = Some(header_name);
        self
    }

    /// Set the opt-in header for the DNS Map (query encoded),
    /// to force the DNS resolution to be resolved within the provided DNS Map
    ///
    /// By default, no header is required.
    ///
    /// ## Remarks
    ///
    /// - Setting this header will make the Request fail in case
    ///   the header value cannot be resolved to a DNS Map.
    pub fn dns_map_header(mut self, header_name: HeaderName) -> Self {
        self.dns_map_header = Some(header_name);
        self
    }

    /// Set the dynamic resolver to use for resolving the DNS.
    pub fn resolver<T: DynamicDnsResolver + Clone>(self, resolver: T) -> DnsLayer<T> {
        DnsLayer {
            resolver,
            resolver_header: self.resolver_header,
            dns_map_header: self.dns_map_header,
        }
    }

    /// Enable the default resolver to be used for resolving DNS.
    pub fn default_resolver(self) -> DnsLayer<impl DynamicDnsResolver + Clone> {
        DnsLayer {
            resolver: crate::net::lookup_authority,
            resolver_header: self.resolver_header,
            dns_map_header: self.dns_map_header,
        }
    }
}

impl<S, R> Layer<S> for DnsLayer<R>
where
    R: DynamicDnsResolver + Clone,
{
    type Service = DnsService<S, R>;

    fn layer(&self, inner: S) -> Self::Service {
        DnsService::new(
            inner,
            self.resolver.clone(),
            self.resolver_header.clone(),
            self.dns_map_header.clone(),
        )
    }
}
