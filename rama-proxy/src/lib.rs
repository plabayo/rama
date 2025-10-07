//! rama proxy types and utilities
//!
//! Proxy protocols are implemented in their relevant crates:
//!
//! - HaProxy: `rama-haproxy`
//! - HttpProxy: `rama-http-backend`
//!
//! See the [`ProxyFilter`] for more information on how to select a proxy,
//! and the [`ProxyDB`] trait for how to implement a proxy database.
//!
//! If you wish to support proxy filters directly from the username,
//! you can use the [`ProxyFilterUsernameParser`] to extract the proxy filter
//! so it will be added to the [`Context`]'s [`Extensions`].
//!
//! The [`ProxyDB`] is used by Connection Pools to connect via a proxy,
//! in case a [`ProxyFilter`] is present in the [`Context`]'s [`Extensions`].
//!
//! # DB Live Reloads
//!
//! [`ProxyDB`] implementations like the [`MemoryProxyDB`] feel static in nature, and they are.
//! The goal is really to load it once and read it often as fast as possible.
//!
//! In fact, given that we access everything through shared references,
//! there is also no cheap way to mutate it all the time.
//!
//! As such the normal way to update data such as your proxy list
//! is by performing a rolling update of your actual rama-driven proxy workloads.
//!
//! That said. By using crates such as [left-right](https://crates.io/crates/left-right)
//! you can relatively affordable perform live reloads by having the writer on its own tokio
//! task and wrap the reader in a [`ProxyDB`] implementation. This way you can live reload based upon
//! a signal, or more realistically, every x minutes.
//!
//! [`Context`]: rama_core::Context
//! [`Extensions`]: rama_core::extensions::Extensions
//!
//! ## ProxyDB layer
//!
//! [`ProxyDB`] layer support to select a proxy based on the given [`Context`].
//!
//! This layer expects a [`ProxyFilter`] to be available in the [`Context`],
//! which can be added by using the `HeaderConfigLayer` (`rama-http`)
//! when operating on the HTTP layer and/or by parsing it via the TCP proxy username labels (e.g. `john-country-us-residential`),
//! in case you support that as part of your transport-layer authentication. And of course you can
//! combine the two approaches.
//!
//! You can also give a single [`Proxy`] as "proxy db".
//!
//! The end result is that a [`ProxyAddress`] will be set in case a proxy was selected,
//! an error is returned in case no proxy could be selected while one was expected
//! or of course because the inner [`Service`][`rama_core::Service`] failed.
//!
//! [`ProxyAddress`]: rama_net::address::ProxyAddress
//! [`ProxyDB`]: ProxyDB
//! [`Context`]: rama_core::Context
//!
//! # Example
//!
//! ```rust
//! use rama_http_types::{Body, Version, Request};
//! use rama_proxy::{
//!      MemoryProxyDB, MemoryProxyDBQueryError, ProxyCsvRowReader, Proxy,
//!      ProxyDBLayer, ProxyFilterMode,
//!      ProxyFilter,
//! };
//! use rama_core::{
//!    service::service_fn,
//!    extensions::{ExtensionsRef, ExtensionsMut},
//!    Service, Layer,
//! };
//! use rama_net::address::ProxyAddress;
//! use rama_utils::str::NonEmptyString;
//! use itertools::Itertools;
//! use std::{convert::Infallible, sync::Arc};
//!
//! #[tokio::main]
//! async fn main() {
//!     let db = MemoryProxyDB::try_from_iter([
//!         Proxy {
//!             id: NonEmptyString::from_static("42"),
//!             address: "12.34.12.34:8080".try_into().unwrap(),
//!             tcp: true,
//!             udp: true,
//!             http: true,
//!             https: false,
//!             socks5: true,
//!             socks5h: false,
//!             datacenter: false,
//!             residential: true,
//!             mobile: true,
//!             pool_id: None,
//!             continent: Some("*".into()),
//!             country: Some("*".into()),
//!             state: Some("*".into()),
//!             city: Some("*".into()),
//!             carrier: Some("*".into()),
//!             asn: None,
//!         },
//!         Proxy {
//!             id: NonEmptyString::from_static("100"),
//!             address: "123.123.123.123:8080".try_into().unwrap(),
//!             tcp: true,
//!             udp: false,
//!             http: true,
//!             https: false,
//!             socks5: false,
//!             socks5h: false,
//!             datacenter: true,
//!             residential: false,
//!             mobile: false,
//!             pool_id: None,
//!             continent: None,
//!             country: Some("US".into()),
//!             state: None,
//!             city: None,
//!             carrier: None,
//!             asn: None,
//!         },
//!     ])
//!     .unwrap();
//!
//!     let service =
//!         ProxyDBLayer::new(Arc::new(db)).filter_mode(ProxyFilterMode::Default)
//!         .into_layer(service_fn(async  |req: Request| {
//!             Ok::<_, Infallible>(req.extensions().get::<ProxyAddress>().unwrap().clone())
//!         }));
//!
//!     let mut req = Request::builder()
//!         .version(Version::HTTP_3)
//!         .method("GET")
//!         .uri("https://example.com")
//!         .body(Body::empty())
//!         .unwrap();
//!
//!     req.extensions_mut().insert(ProxyFilter {
//!         country: Some(vec!["BE".into()]),
//!         mobile: Some(true),
//!         residential: Some(true),
//!         ..Default::default()
//!     });
//!
//!     let proxy_address = service.serve(req).await.unwrap();
//!     assert_eq!(proxy_address.authority.to_string(), "12.34.12.34:8080");
//! }
//! ```
//!
//! ## Single Proxy Router
//!
//! Another example is a single proxy through which
//! one can connect with config for further downstream proxies
//! passed by username labels.
//!
//! Note that the username formatter is available for any proxy db,
//! it is not specific to the usage of a single proxy.
//!
//! ```rust
//! use rama_http_types::{Body, Version, Request};
//! use rama_proxy::{
//!    Proxy,
//!    ProxyDBLayer, ProxyFilterMode,
//!    ProxyFilter,
//! };
//! use rama_core::{
//!    service::service_fn,
//!    extensions::{ExtensionsRef, ExtensionsMut},
//!    Service, Layer,
//! };
//! use rama_net::address::ProxyAddress;
//! use rama_utils::str::NonEmptyString;
//! use itertools::Itertools;
//! use std::{convert::Infallible, sync::Arc};
//!
//! #[tokio::main]
//! async fn main() {
//!     let proxy = Proxy {
//!         id: NonEmptyString::from_static("1"),
//!         address: "john:secret@proxy.example.com:60000".try_into().unwrap(),
//!         tcp: true,
//!         udp: true,
//!         http: true,
//!         https: false,
//!         socks5: true,
//!         socks5h: false,
//!         datacenter: false,
//!         residential: true,
//!         mobile: false,
//!         pool_id: None,
//!         continent: Some("*".into()),
//!         country: Some("*".into()),
//!         state: Some("*".into()),
//!         city: Some("*".into()),
//!         carrier: Some("*".into()),
//!         asn: None,
//!     };
//!
//!     let service = ProxyDBLayer::new(Arc::new(proxy))
//!         .filter_mode(ProxyFilterMode::Default)
//!         .username_formatter(|_proxy: &Proxy, filter: &ProxyFilter, username: &str| {
//!             use std::fmt::Write;
//!
//!             let mut output = String::new();
//!
//!             if let Some(countries) =
//!                 filter.country.as_ref().filter(|t| !t.is_empty())
//!             {
//!                 let _ = write!(output, "country-{}", countries[0]);
//!             }
//!             if let Some(states) =
//!                 filter.state.as_ref().filter(|t| !t.is_empty())
//!             {
//!                 let _ = write!(output, "state-{}", states[0]);
//!             }
//!
//!             (!output.is_empty()).then(|| format!("{username}-{output}"))
//!         })
//!         .into_layer(service_fn(async |req: Request| {
//!             Ok::<_, Infallible>(req.extensions().get::<ProxyAddress>().unwrap().clone())
//!         }));
//!
//!     let mut req = Request::builder()
//!         .version(Version::HTTP_3)
//!         .method("GET")
//!         .uri("https://example.com")
//!         .body(Body::empty())
//!         .unwrap();
//!     req.extensions_mut().insert(ProxyFilter {
//!         country: Some(vec!["BE".into()]),
//!         residential: Some(true),
//!         ..Default::default()
//!     });
//!     let proxy_address = service.serve(req).await.unwrap();
//!     assert_eq!(
//!         "socks5://john-country-be:secret@proxy.example.com:60000",
//!         proxy_address.to_string()
//!     );
//! }
//! ```

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(not(test), warn(clippy::print_stdout, clippy::dbg_macro))]

mod username;
#[doc(inline)]
pub use username::ProxyFilterUsernameParser;

mod proxydb;

#[doc(inline)]
pub use proxydb::{
    Proxy, ProxyContext, ProxyDB, ProxyFilter, ProxyID, ProxyQueryPredicate, StringFilter,
};

#[doc(inline)]
pub use proxydb::layer::{ProxyDBLayer, ProxyDBService, ProxyFilterMode, UsernameFormatter};

#[cfg(feature = "live-update")]
#[doc(inline)]
pub use proxydb::{LiveUpdateProxyDB, LiveUpdateProxyDBSetter, proxy_db_updater};

#[cfg(feature = "memory-db")]
#[doc(inline)]
pub use proxydb::{
    MemoryProxyDB, MemoryProxyDBInsertError, MemoryProxyDBInsertErrorKind, MemoryProxyDBQueryError,
    MemoryProxyDBQueryErrorKind,
};

#[cfg(feature = "csv")]
#[doc(inline)]
pub use proxydb::{ProxyCsvRowReader, ProxyCsvRowReaderError, ProxyCsvRowReaderErrorKind};
