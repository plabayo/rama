//! TLS implementations for Rama using rustls.
//!
//! # Rama
//!
//! Crate used by the end-user `rama` crate and `rama` crate authors alike.
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]

#[non_exhaustive]
/// CrateMarker type which is used to identify this crate when working around the orphan rule
///
/// More info: <https://ramaproxy.org/book/intro/patterns.html#working-around-the-orphan-rule-in-specific-cases>
pub struct RamaTlsRustlsCrateMarker;

#[cfg(feature = "dial9")]
#[cfg_attr(docsrs, doc(cfg(feature = "dial9")))]
pub mod dial9;

/// Generates the rustls `TlsStream<IO>` newtype wrapper and its trait
/// delegations (`AsyncRead`/`AsyncWrite`/`ExtensionsRef`/`From`).
///
/// Client and server only differ in which rustls stream they wrap, supplied as
/// `$rustls` (an identifier that must already be in scope at the call site).
macro_rules! rama_rustls_tls_stream {
    ($rustls:ident) => {
        ::pin_project_lite::pin_project! {
            #[derive(Debug)]
            pub struct TlsStream<IO> {
                #[pin]
                pub(super) stream: $rustls<IO>,
            }
        }

        impl<IO: ::rama_core::extensions::ExtensionsRef> TlsStream<IO> {
            pub fn new(stream: $rustls<IO>) -> Self {
                Self { stream }
            }
        }

        impl<IO: ::rama_core::extensions::ExtensionsRef> From<$rustls<IO>> for TlsStream<IO> {
            fn from(value: $rustls<IO>) -> Self {
                Self::new(value)
            }
        }

        impl<IO> From<TlsStream<IO>> for $rustls<IO> {
            fn from(value: TlsStream<IO>) -> Self {
                value.stream
            }
        }

        impl<IO: ::rama_core::extensions::ExtensionsRef> ::rama_core::extensions::ExtensionsRef
            for TlsStream<IO>
        {
            fn extensions(&self) -> &::rama_core::extensions::Extensions {
                self.stream.get_ref().0.extensions()
            }
        }

        #[warn(clippy::missing_trait_methods)]
        impl<IO: ::tokio::io::AsyncRead + ::tokio::io::AsyncWrite + Unpin> ::tokio::io::AsyncRead
            for TlsStream<IO>
        {
            fn poll_read(
                self: ::std::pin::Pin<&mut Self>,
                cx: &mut ::std::task::Context<'_>,
                buf: &mut ::tokio::io::ReadBuf<'_>,
            ) -> ::std::task::Poll<::std::io::Result<()>> {
                self.project().stream.poll_read(cx, buf)
            }
        }

        #[warn(clippy::missing_trait_methods)]
        impl<IO: ::tokio::io::AsyncRead + ::tokio::io::AsyncWrite + Unpin> ::tokio::io::AsyncWrite
            for TlsStream<IO>
        {
            fn poll_write(
                self: ::std::pin::Pin<&mut Self>,
                cx: &mut ::std::task::Context<'_>,
                buf: &[u8],
            ) -> ::std::task::Poll<::std::io::Result<usize>> {
                self.project().stream.poll_write(cx, buf)
            }

            fn poll_write_vectored(
                self: ::std::pin::Pin<&mut Self>,
                cx: &mut ::std::task::Context<'_>,
                bufs: &[::std::io::IoSlice<'_>],
            ) -> ::std::task::Poll<::std::io::Result<usize>> {
                self.project().stream.poll_write_vectored(cx, bufs)
            }

            fn poll_flush(
                self: ::std::pin::Pin<&mut Self>,
                cx: &mut ::std::task::Context<'_>,
            ) -> ::std::task::Poll<::std::io::Result<()>> {
                self.project().stream.poll_flush(cx)
            }

            fn poll_shutdown(
                self: ::std::pin::Pin<&mut Self>,
                cx: &mut ::std::task::Context<'_>,
            ) -> ::std::task::Poll<::std::io::Result<()>> {
                self.project().stream.poll_shutdown(cx)
            }

            fn is_write_vectored(&self) -> bool {
                self.stream.is_write_vectored()
            }
        }
    };
}

pub mod client;
pub mod server;
pub mod verify;

pub mod key_log;

mod type_conversion;

#[cfg(all(feature = "aws-lc", feature = "ring"))]
fn ensure_default_crypto_provider() {
    use std::sync::Once;

    static INSTALL_DEFAULT_PROVIDER: Once = Once::new();

    INSTALL_DEFAULT_PROVIDER.call_once(|| {
        if let Err(provider) = rustls::crypto::aws_lc_rs::default_provider().install_default() {
            rama_core::telemetry::tracing::debug!(
                ?provider,
                "rama-tls-rustls: failed to install aws-lc as the default rustls crypto provider"
            );
        }
    });
}

#[cfg(not(all(feature = "aws-lc", feature = "ring")))]
fn ensure_default_crypto_provider() {}

pub mod types {
    //! common tls types
    #[doc(inline)]
    pub use ::rama_tls::{
        ApplicationProtocol, CipherSuite, CompressionAlgorithm, ECPointFormat, ExtensionId,
        ProtocolVersion, SecureTransport, SignatureScheme, SupportedGroup, TlsTunnel, client,
    };
}

pub mod dep {
    //! Dependencies for rama rustls modules.
    //!
    //! Exported for your convenience.

    pub mod rustls {
        //! Re-export of the [`rustls`] and  [`tokio-rustls`] crates.
        //!
        //! To facilitate the use of `rustls` types in API's such as [`TlsAcceptorLayer`].
        //!
        //! [`rustls`]: https://docs.rs/rustls
        //! [`tokio-rustls`]: https://docs.rs/tokio-rustls
        //! [`TlsAcceptorLayer`]: crate::server::TlsAcceptorLayer

        #[doc(inline)]
        pub use rustls::*;

        pub mod client {
            //! Re-export of client module of the [`rustls`] and [`tokio-rustls`] crates.
            //!
            //! [`rustls`]: https://docs.rs/rustls
            //! [`tokio-rustls`]: https://docs.rs/tokio-rustls

            #[doc(inline)]
            pub use rustls::client::*;
            #[doc(inline)]
            pub use tokio_rustls::client::TlsStream;
        }

        pub mod server {
            //! Re-export of server module of the [`rustls`] and [`tokio-rustls`] crates.
            //!
            //! [`rustls`]: https://docs.rs/rustls
            //! [`tokio-rustls`]: https://docs.rs/tokio-rustls

            #[doc(inline)]
            pub use rustls::server::*;
            #[doc(inline)]
            pub use tokio_rustls::server::TlsStream;
        }
    }

    pub mod tokio_rustls {
        //! Full Re-export of the [`tokio-rustls`] crate.
        //!
        //! [`tokio-rustls`]: https://docs.rs/tokio-rustls
        #[doc(inline)]
        pub use tokio_rustls::*;
    }

    pub mod webpki_roots {
        //! Re-export of the [`webpki-roots`] provides.
        //!
        //! This module provides a function to load the Mozilla root CA store.
        //!
        //! This module is inspired by <certifi.io> and uses the data provided by
        //! [the Common CA Database (CCADB)](https://www.ccadb.org/). The underlying data is used via
        //! [the CCADB Data Usage Terms](https://www.ccadb.org/rootstores/usage#ccadb-data-usage-terms).
        //!
        //! The data in this crate is a derived work of the CCADB data. See copy of LICENSE at
        //! <https://github.com/plabayo/rama/blob/main/docs/thirdparty/licenses/rustls-webpki-roots>.
        //!
        //! [`webpki-roots`]: https://docs.rs/webpki-roots
        #[doc(inline)]
        pub use webpki_roots::*;
    }
}
