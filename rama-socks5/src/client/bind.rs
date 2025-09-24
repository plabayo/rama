//! Contains [`bind-flow`] types such as the [`Binder`],
//! used by a socks5 [`Client`] as part of the bind-handshake.
//!
//! [`bind-flow`]: crate::proto::Command::Bind
//! [`Client`]: crate::Socks5Client

use rama_core::stream::Stream;
use rama_core::telemetry::tracing;
use rama_net::address::{Authority, SocketAddress};
use std::fmt;

use super::core::HandshakeError;
use crate::proto::{ReplyKind, server};

/// [`Binder`] is used to await for the socks5 server
/// as it has to come back with a reply on whether or not
/// the server has established a connection with the socks5 server.
///
/// [`Binder`] is provided by using the [`Client::handshake_bind`] method,
/// and contains the [`bind_address`] to be given to the server so it knows
/// where to connect to.
///
/// [`Client::handshake_bind`]: crate::Socks5Client::handshake_bind
/// [`bind_address`]: Binder::bind_address
pub struct Binder<S> {
    stream: S,
    requested_bind_address: Option<SocketAddress>,
    selected_bind_address: SocketAddress,
}

/// Error that is returned in case the bind process while
/// [waiting for the (2nd) success reply](Binder::connect)
/// was not successfull.
pub struct BindError<S> {
    stream: S,
    error: HandshakeError,
}

impl<S> BindError<S> {
    #[inline]
    /// [`ReplyKind::GeneralServerFailure`] is returned in case of an error
    /// that is returned in case no reply was received from the (socks5) server.
    pub fn reply(&self) -> ReplyKind {
        self.error.reply()
    }

    /// Consume this error to take back ownership over the stream.
    ///
    /// NOTE that the stream is most likely in an unusable state,
    /// so for most scenarios you probably just want to drop it.
    pub fn into_stream(self) -> S {
        self.stream
    }
}

impl<S> fmt::Debug for BindError<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BindError")
            .field("stream", &format_args!("{}", std::any::type_name::<S>()))
            .field("error", &self.error)
            .finish()
    }
}

impl<S> fmt::Display for BindError<S> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl<S> std::error::Error for BindError<S> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.error.source()
    }
}

/// Output that is returned in case the bind process while
/// [waiting for the (2nd) success reply](Binder::connect)
/// was successfull.
pub struct BindOutput<S> {
    /// Stream to transfer data via the socks5 server to the target server.
    pub stream: S,
    /// Possibly the address of the server as seen by the socks5 server.
    pub server: Authority,
}

impl<S: Stream + Unpin> Binder<S> {
    pub(crate) fn new(
        stream: S,
        requested_bind_address: Option<SocketAddress>,
        selected_bind_address: SocketAddress,
    ) -> Self {
        Self {
            stream,
            requested_bind_address,
            selected_bind_address,
        }
    }

    /// Address of the address requested by
    /// the socks5 (bind) client, if requested at all.
    pub fn requested_bind_address(&self) -> Option<SocketAddress> {
        self.requested_bind_address
    }

    /// Address of the socket that the socks5 server has opened
    /// for the target server to connect to.
    pub fn selected_bind_address(&self) -> SocketAddress {
        self.selected_bind_address
    }

    /// Wait for the server to connect to the socks5 server
    /// using the [selected bind address].
    ///
    /// [selected bind address]: Self::selected_bind_address
    pub async fn connect(mut self) -> Result<BindOutput<S>, BindError<S>> {
        let server = match server::Reply::read_from(&mut self.stream).await {
            Ok(reply) => {
                if reply.reply != ReplyKind::Succeeded {
                    return Err(BindError {
                        stream: self.stream,
                        error: HandshakeError::reply_kind(reply.reply)
                            .with_context("server responded with non-success reply"),
                    });
                }
                reply.bind_address
            }
            Err(err) => {
                return Err(BindError {
                    stream: self.stream,
                    error: HandshakeError::protocol(err).with_context("read server reply"),
                });
            }
        };

        tracing::trace!(
            network.local.address = %self.selected_bind_address.ip_addr(),
            network.local.port = %self.selected_bind_address.port(),
            server.address = %server.host(),
            server.port = %server.port(),
            "socks5: bind handshake complete",
        );

        Ok(BindOutput {
            stream: self.stream,
            server,
        })
    }

    /// Drop the [`Binder`] and return back ownership of the stream.
    ///
    /// Note that most likely this is not what you want to do as it
    /// is in most cases not in a state useful to you.
    pub fn into_stream(self) -> S {
        self.stream
    }
}
