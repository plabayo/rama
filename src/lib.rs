#![doc = include_str!("lib_docs.md")]
#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![cfg_attr(test, allow(clippy::float_cmp))]

#[doc(inline)]
pub use ::rama_core::{
    Layer, Service, bytes, combinators, conversion, error, error_sink, extensions, futures, geo,
    layer, matcher, service, username,
};

#[cfg(feature = "std")]
#[doc(inline)]
pub use ::rama_core::{ServiceInput, graceful, io, rt, stream};

#[cfg(feature = "std")]
#[doc(inline)]
pub use ::rama_json as json;

#[cfg(all(feature = "std", feature = "crypto"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "std", feature = "crypto"))))]
#[doc(inline)]
pub use ::rama_crypto as crypto;

#[cfg(all(target_family = "unix", feature = "unix"))]
#[cfg_attr(docsrs, doc(cfg(all(target_family = "unix", feature = "unix"))))]
#[doc(inline)]
pub use ::rama_unix as unix;

#[cfg(all(feature = "std", feature = "tcp"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "std", feature = "tcp"))))]
#[doc(inline)]
pub use ::rama_tcp as tcp;

#[cfg(all(feature = "std", feature = "udp"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "std", feature = "udp"))))]
#[doc(inline)]
pub use ::rama_udp as udp;

#[cfg(feature = "std")]
pub mod telemetry;

#[cfg(any(
    all(feature = "std", feature = "tls"),
    all(feature = "std", feature = "rustls"),
    all(feature = "std", feature = "boring"),
    all(feature = "std", feature = "acme")
))]
pub mod tls;

#[cfg(all(feature = "std", feature = "dns"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "std", feature = "dns"))))]
#[doc(inline)]
pub use ::rama_dns as dns;

#[cfg(feature = "net")]
pub mod net {
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    #[doc(inline)]
    pub use ::rama_net::*;

    #[cfg(any(
        all(doc, docsrs),
        all(
            target_vendor = "apple",
            any(feature = "net-apple-networkextension", feature = "net-apple-xpc")
        )
    ))]
    #[cfg_attr(docsrs, doc(cfg(target_vendor = "apple")))]
    pub mod apple {
        //! Apple (vendor) specific network modules

        #[cfg(feature = "net-apple-networkextension")]
        #[cfg_attr(docsrs, doc(cfg(feature = "net-apple-networkextension")))]
        #[doc(inline)]
        pub use ::rama_net_apple_networkextension as networkextension;

        #[cfg(feature = "net-apple-xpc")]
        #[cfg_attr(docsrs, doc(cfg(feature = "net-apple-xpc")))]
        #[doc(inline)]
        pub use ::rama_net_apple_xpc as xpc;
    }
}

#[cfg(all(feature = "std", feature = "http"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "std", feature = "http"))))]
pub mod http;

#[cfg(any(
    all(feature = "std", feature = "proxy"),
    all(feature = "std", feature = "haproxy"),
    all(feature = "std", feature = "socks5")
))]
pub mod proxy {
    //! rama proxy support

    #[cfg(feature = "proxy")]
    #[cfg_attr(docsrs, doc(cfg(feature = "proxy")))]
    #[doc(inline)]
    pub use ::rama_proxy::*;

    #[cfg(feature = "haproxy")]
    #[cfg_attr(docsrs, doc(cfg(feature = "haproxy")))]
    #[doc(inline)]
    pub use ::rama_haproxy as haproxy;

    #[cfg(feature = "socks5")]
    #[cfg_attr(docsrs, doc(cfg(feature = "socks5")))]
    #[doc(inline)]
    pub use ::rama_socks5 as socks5;
}

/// Application server gateway protocols (FastCGI, and similar).
#[cfg(all(feature = "std", feature = "fastcgi"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "std", feature = "fastcgi"))))]
pub mod gateway {
    #[cfg(feature = "fastcgi")]
    #[cfg_attr(docsrs, doc(cfg(feature = "fastcgi")))]
    #[doc(inline)]
    pub use ::rama_fastcgi as fastcgi;
}

/// ttRPC ("gRPC for low-memory environments") support.
///
/// Unlike `grpc`, ttRPC does not ride on HTTP/2, it is a length-prefixed framing
/// directly on the byte stream, used by container runtimes and their plugins.
#[cfg(feature = "ttrpc")]
#[cfg_attr(docsrs, doc(cfg(feature = "ttrpc")))]
#[doc(inline)]
pub use ::rama_ttrpc as ttrpc;

#[cfg(all(feature = "std", feature = "ua"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "std", feature = "ua"))))]
#[doc(inline)]
pub use ::rama_ua as ua;

#[cfg(all(feature = "std", feature = "cli"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "std", feature = "cli"))))]
pub mod cli;

pub mod utils {
    //! utilities for rama

    #[doc(inline)]
    pub use ::rama_utils::*;

    #[cfg(feature = "tower")]
    #[cfg_attr(docsrs, doc(cfg(feature = "tower")))]
    #[doc(inline)]
    pub use ::rama_tower as tower;
}
