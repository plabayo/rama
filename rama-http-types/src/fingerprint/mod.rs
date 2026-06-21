//! HTTP fingerprint implementations (JA4H, Akamai HTTP/2).

mod akamai;
#[doc(inline)]
pub use akamai::{AkamaiH2, AkamaiH2ComputeError};

mod ja4;
#[doc(inline)]
pub use ja4::{Ja4H, Ja4HComputeError};

mod http_utils {
    use private::HttpRequestProviderPriv;

    use crate::{Method, Version, proto::h1::Http1HeaderMap};

    #[derive(Debug, Clone)]
    /// Minimal input data structure which can be used
    /// by ja4h computation functions instead of a reference
    /// to a [`crate::Request`].
    pub struct HttpRequestInput {
        pub header_map: Http1HeaderMap,
        pub http_method: Method,
        pub version: Version,
    }

    /// Sealed trait used by the ja4h computation functions,
    /// to allow you to immediately compute from either a
    /// [`crate::Request`] or a [`HttpRequestInput`] data structure.
    pub trait HttpRequestProvider: HttpRequestProviderPriv {}
    impl<P: HttpRequestProviderPriv> HttpRequestProvider for P {}

    mod private {
        use super::*;
        use crate::Request;

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

#[doc(inline)]
pub use http_utils::{HttpRequestInput, HttpRequestProvider};
