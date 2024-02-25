//! Utilities to allow custom DNS Resolution within Rama.
//!
//! # Example
//!
//! ```rust
//! use rama::http::layer::dns::{DnsLayer, DynamicDnsResolver, DnsResolvedSocketAddresses};
//! use rama::http::service::web::{WebService, extract::{Host, Extension}};
//! use rama::http::{Body, Request, StatusCode};
//! use rama::service::{Context, Service, Layer};
//! use std::net::SocketAddr;
//!
//! #[tokio::main]
//! async fn main() {
//!     let dns_layer = DnsLayer::new()
//!         .dns_map_header("x-dns-map".parse().unwrap())
//!         .default_resolver();
//!    
//!     let service = dns_layer.layer(WebService::default()
//!         .get("/", |Host(host): Host, Extension(resolved): Extension<DnsResolvedSocketAddresses>| async move {
//!             assert_eq!(host, "www.example.com");
//!             let expected_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
//!             assert_eq!(resolved.address(), &expected_addr);
//!             StatusCode::OK
//!         }),
//!     );
//!    
//!     let resp = service.serve(
//!         Context::default(),
//!         Request::builder()
//!             .uri("http://www.example.com")
//!             .header("x-dns-map", "www.example.com=127.0.0.1:8080")
//!             .body(Body::empty()).unwrap(),
//!     ).await.unwrap();
//!     assert_eq!(resp.status(), StatusCode::OK);
//! }
//! ```

mod error;
pub use error::DnsError;

mod dns_resolve;
pub use dns_resolve::DynamicDnsResolver;

pub(crate) mod dns_map;

mod service;
pub use service::{DnsResolvedSocketAddresses, DnsService};

mod layer;
pub use layer::DnsLayer;
