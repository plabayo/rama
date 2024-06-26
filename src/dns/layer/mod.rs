//! Layers in function of DNS.
//!
//! # Example
//!
//! ## [`DnsMapLayer`]
//!
//! Example showing how to allow DNS lookup overwrites
//! using the [`DnsMapLayer`].
//!
//! ```rust
//! use rama::{
//!     dns::layer::DnsMapLayer,
//!     http::{get_request_context, HeaderName, Request},
//!     net::address::Host,
//!     service::{Context, Service, ServiceBuilder},
//! };
//! use std::{
//!     convert::Infallible,
//!     net::{IpAddr, Ipv4Addr},
//! };
//!
//! #[tokio::main]
//! async fn main() {
//!     let svc = ServiceBuilder::new()
//!         .layer(DnsMapLayer::new(HeaderName::from_static("x-dns-map")))
//!         .service_fn(|mut ctx: Context<()>, req: Request<()>| async move {
//!             let req_ctx = get_request_context!(ctx, req);
//!             let domain = match req_ctx.authority.as_ref().unwrap().host() {
//!                 Host::Name(domain) => domain,
//!                 Host::Address(ip) => panic!("unexpected host: {ip}"),
//!             };
//!
//!             let addresses: Vec<_> = ctx.dns().ipv4_lookup(domain.clone()).await.unwrap().collect();
//!             assert_eq!(addresses, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);
//!
//!             let addresses: Vec<_> = ctx.dns().ipv6_lookup(domain.clone()).await.unwrap().collect();
//!             assert!(addresses.is_empty());
//!
//!             Ok::<_, Infallible>(())
//!         });
//!
//!     let ctx = Context::default();
//!     let req = Request::builder()
//!         .header("x-dns-map", "example.com=127.0.0.1")
//!         .uri("http://example.com")
//!         .body(())
//!         .unwrap();
//!
//!     svc.serve(ctx, req).await.unwrap();
//! }
//! ```

mod dns_map;
pub use dns_map::{DnsMapLayer, DnsMapService};

mod dns_resolve;
pub use dns_resolve::{
    DnsResolveMode, DnsResolveModeLayer, DnsResolveModeService, DnsResolveModeUsernameParser,
};
