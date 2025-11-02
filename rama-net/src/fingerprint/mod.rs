//! fingerprint implementations for the network surface

#[cfg(feature = "http")]
mod akamai;

#[cfg(feature = "http")]
pub use akamai::{AkamaiH2, AkamaiH2ComputeError};

#[cfg(any(feature = "tls", feature = "http"))]
mod ja4;

#[cfg(feature = "http")]
pub use ja4::{Ja4H, Ja4HComputeError};

#[cfg(feature = "tls")]
pub use ja4::{Ja4, Ja4ComputeError};

#[cfg(feature = "tls")]
mod peet;

#[cfg(feature = "tls")]
pub use peet::{PeetComputeError, PeetPrint};

#[cfg(feature = "tls")]
mod ja3;

#[cfg(feature = "tls")]
pub use ja3::{Ja3, Ja3ComputeError};

#[cfg(feature = "tls")]
mod tls_utils {
    use private::ClientHelloProviderPriv;

    /// Sealed trait used by ja3/ja4 computation functions,
    /// to allow you to immediately compute from either a
    /// [`ClientHello`] or a [`ClientConfig`] data structure.
    ///
    /// [`ClientHello`]: crate::tls::client::ClientHello
    /// [`ClientConfig`]: crate::tls::client::ClientConfig
    pub trait ClientHelloProvider: ClientHelloProviderPriv {}
    impl<P: ClientHelloProviderPriv> ClientHelloProvider for P {}

    mod private {
        use crate::tls::{
            CipherSuite, ProtocolVersion,
            client::{ClientConfig, ClientHello, ClientHelloExtension},
        };

        pub trait ClientHelloProviderPriv {
            fn protocol_version(&self) -> ProtocolVersion;
            fn cipher_suites(&self) -> impl Iterator<Item = CipherSuite>;
            fn extensions(&self) -> impl Iterator<Item = &ClientHelloExtension>;
        }

        impl ClientHelloProviderPriv for &ClientHello {
            #[inline(always)]
            fn protocol_version(&self) -> ProtocolVersion {
                (*self).protocol_version()
            }

            #[inline(always)]
            fn cipher_suites(&self) -> impl Iterator<Item = CipherSuite> {
                (*self).cipher_suites().iter().copied()
            }

            #[inline(always)]
            fn extensions(&self) -> impl Iterator<Item = &ClientHelloExtension> {
                (*self).extensions().iter()
            }
        }

        impl ClientHelloProviderPriv for &ClientConfig {
            #[inline(always)]
            fn protocol_version(&self) -> ProtocolVersion {
                ProtocolVersion::TLSv1_2
            }

            #[inline(always)]
            fn cipher_suites(&self) -> impl Iterator<Item = CipherSuite> {
                self.cipher_suites.iter().flatten().copied()
            }

            #[inline(always)]
            fn extensions(&self) -> impl Iterator<Item = &ClientHelloExtension> {
                self.extensions.iter().flatten()
            }
        }
    }
}

#[cfg(feature = "tls")]
pub use tls_utils::ClientHelloProvider;

#[cfg(feature = "http")]
mod http_utils {
    use private::HttpRequestProviderPriv;
    use rama_http_types::{Method, Version, proto::h1::Http1HeaderMap};

    #[derive(Debug, Clone)]
    /// Minimal input data structure which can be used
    /// by ja4h computation functions instead of a reference
    /// to a [`rama_http_types::Request`].
    pub struct HttpRequestInput {
        pub header_map: Http1HeaderMap,
        pub http_method: Method,
        pub version: Version,
    }

    /// Sealed trait used by the ja4h computation functions,
    /// to allow you to immediately compute from either a
    /// [`rama_http_types::Request`] or a [`HttpRequestInput`] data structure.
    pub trait HttpRequestProvider: HttpRequestProviderPriv {}
    impl<P: HttpRequestProviderPriv> HttpRequestProvider for P {}

    mod private {
        use super::*;
        use rama_http_types::Request;

        pub trait HttpRequestProviderPriv {
            fn http_request_input(self) -> HttpRequestInput;
        }

        impl<B> HttpRequestProviderPriv for &Request<B> {
            fn http_request_input(self) -> HttpRequestInput {
                HttpRequestInput {
                    header_map: Http1HeaderMap::copy_from_req(self),
                    http_method: self.method().clone(),
                    version: self.version(),
                }
            }
        }

        impl HttpRequestProviderPriv for HttpRequestInput {
            #[inline(always)]
            fn http_request_input(self) -> HttpRequestInput {
                self
            }
        }
    }
}

#[cfg(feature = "http")]
pub use http_utils::{HttpRequestInput, HttpRequestProvider};
