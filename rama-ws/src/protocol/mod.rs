//! Generic WebSocket message stream.

use rama_core::extensions::{Extensions, ExtensionsMut, ExtensionsRef};
use rama_core::telemetry::tracing;
use rama_core::{
    error::OpaqueError,
    telemetry::tracing::{debug, trace},
};
use std::{
    fmt,
    io::{self, Read, Write},
};

#[cfg(feature = "compression")]
use rama_http::headers::sec_websocket_extensions;

pub mod frame;

mod error;
mod message;

#[cfg(feature = "compression")]
mod per_message_deflate;

pub use error::ProtocolError;

#[cfg(test)]
mod tests;

use crate::protocol::{
    frame::{
        Frame, FrameCodec, Utf8Bytes,
        coding::{CloseCode, OpCode, OpCodeControl, OpCodeData},
    },
    message::{IncompleteMessage, IncompleteMessageType},
};

#[cfg(feature = "compression")]
use self::per_message_deflate::PerMessageDeflateState;

pub use self::{frame::CloseFrame, message::Message};

/// Indicates a Client or Server role of the websocket
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// This socket is a server
    Server,
    /// This socket is a client
    Client,
}

/// The configuration for WebSocket connection.
///
/// # Example
/// ```
/// # use rama_ws::protocol::WebSocketConfig;
///
/// let conf = WebSocketConfig::default()
///     .with_read_buffer_size(256 * 1024)
///     .with_write_buffer_size(256 * 1024);
/// ```
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct WebSocketConfig {
    /// Read buffer capacity. This buffer is eagerly allocated and used for receiving
    /// messages.
    ///
    /// For high read load scenarios a larger buffer, e.g. 128 KiB, improves performance.
    ///
    /// For scenarios where you expect a lot of connections and don't need high read load
    /// performance a smaller buffer, e.g. 4 KiB, would be appropriate to lower total
    /// memory usage.
    ///
    /// The default value is 128 KiB.
    pub read_buffer_size: usize,

    /// The target minimum size of the write buffer to reach before writing the data
    /// to the underlying stream.
    /// The default value is 128 KiB.
    ///
    /// If set to `0` each message will be eagerly written to the underlying stream.
    /// It is often more optimal to allow them to buffer a little, hence the default value.
    ///
    /// Note: [`flush`](WebSocket::flush) will always fully write the buffer regardless.
    pub write_buffer_size: usize,

    /// The max size of the write buffer in bytes. Setting this can provide backpressure
    /// in the case the write buffer is filling up due to write errors.
    /// The default value is unlimited.
    ///
    /// Note: The write buffer only builds up past [`write_buffer_size`](Self::write_buffer_size)
    /// when writes to the underlying stream are failing. So the **write buffer can not
    /// fill up if you are not observing write errors even if not flushing**.
    ///
    /// Note: Should always be at least [`write_buffer_size + 1 message`](Self::write_buffer_size)
    /// and probably a little more depending on error handling strategy.
    pub max_write_buffer_size: usize,

    /// The maximum size of an incoming message. `None` means no size limit. The default value is 64 MiB
    /// which should be reasonably big for all normal use-cases but small enough to prevent
    /// memory eating by a malicious user.
    pub max_message_size: Option<usize>,

    /// The maximum size of a single incoming message frame. `None` means no size limit. The limit is for
    /// frame payload NOT including the frame header. The default value is 16 MiB which should
    /// be reasonably big for all normal use-cases but small enough to prevent memory eating
    /// by a malicious user.
    pub max_frame_size: Option<usize>,

    /// When set to `true`, the server will accept and handle unmasked frames
    /// from the client. According to the RFC 6455, the server must close the
    /// connection to the client in such cases, however it seems like there are
    /// some popular libraries that are sending unmasked frames, ignoring the RFC.
    /// By default this option is set to `false`, i.e. according to RFC 6455.
    pub accept_unmasked_frames: bool,

    #[cfg(feature = "compression")]
    #[cfg_attr(docsrs, doc(cfg(feature = "compression")))]
    /// Per-message-deflate configuration, specify it
    /// to enable per-message (de)compression using the Deflate algorithm
    /// as specified by [`RFC7692`].
    ///
    /// [`RFC7692`]: https://datatracker.ietf.org/doc/html/rfc7692
    pub per_message_deflate: Option<PerMessageDeflateConfig>,
}

#[cfg(feature = "compression")]
#[cfg_attr(docsrs, doc(cfg(feature = "compression")))]
/// Per-message-deflate configuration as specified in [`RFC7692`]
///
/// [`RFC7692`]: https://datatracker.ietf.org/doc/html/rfc7692
#[derive(Debug, Clone, Copy)]
pub struct PerMessageDeflateConfig {
    /// Prevents Server Context Takeover
    ///
    /// This extension parameter enables a client to request that
    /// the server forgo context takeover, thereby eliminating
    /// the client's need to retain memory for the LZ77 sliding window between messages.
    ///
    /// A client's omission of this parameter indicates its capability to decompress messages
    /// even if the server utilizes context takeover.
    ///
    /// Servers should support this parameter and confirm acceptance by
    /// including it in their response;
    /// they may even include it if not explicitly requested by the client.
    pub server_no_context_takeover: bool,

    /// Manages Client Context Takeover
    ///
    /// This extension parameter allows a client to indicate to
    /// the server its intent not to use context takeover,
    /// even if the server doesn't explicitly respond with the same parameter.
    ///
    /// When a server receives this, it can either ignore it or include
    /// `client_no_context_takeover` in its response,
    /// which prevents the client from using context
    /// takeover and helps the server conserve memory.
    /// If the server's response omits this parameter,
    /// it signals its ability to decompress messages where
    /// the client does use context takeover.
    ///
    /// Clients are required to support this parameter in a server's response.
    pub client_no_context_takeover: bool,

    /// Limits Server Window Size
    ///
    /// This extension parameter allows a client to propose
    /// a maximum LZ77 sliding window size for the server
    /// to use when compressing messages, specified as a base-2 logarithm (8-15).
    ///
    /// This helps the client reduce its memory requirements.
    /// If a client omits this parameter,
    /// it signals its capacity to handle messages compressed with a window up to 32,768 bytes.
    ///
    /// A server accepts by echoing the parameter with an equal or smaller value;
    /// otherwise, it declines. Notably, a server may suggest a window size
    /// even if the client didn't initially propose one.
    pub server_max_window_bits: Option<u8>,

    /// Adjusts Client Window Size
    ///
    /// This extension parameter allows a client to propose,
    /// optionally with a value between 8 and 15 (base-2 logarithm),
    /// the maximum LZ77 sliding window size it will use for compression.
    ///
    /// This signals to the server that the client supports this parameter in responses and,
    /// if a value is provided, hints that the client won't exceed that window size
    /// for its own compression, regardless of the server's response.
    ///
    /// A server can then include client_max_window_bits in its response
    /// with an equal or smaller value, thereby limiting the client's window size
    /// and reducing its own memory overhead for decompression.
    ///
    /// If the server's response omits this parameter,
    /// it signifies its ability to decompress messages compressed with a client window
    /// up to 32,768 bytes.
    ///
    /// Servers must not include this parameter in their response
    /// if the client's initial offer didn't contain it.
    pub client_max_window_bits: Option<u8>,
}

#[cfg(feature = "compression")]
impl From<&sec_websocket_extensions::PerMessageDeflateConfig> for PerMessageDeflateConfig {
    fn from(value: &sec_websocket_extensions::PerMessageDeflateConfig) -> Self {
        Self {
            server_no_context_takeover: value.server_no_context_takeover,
            client_no_context_takeover: value.client_no_context_takeover,
            server_max_window_bits: value.server_max_window_bits,
            client_max_window_bits: value.client_max_window_bits,
        }
    }
}

#[cfg(feature = "compression")]
impl From<sec_websocket_extensions::PerMessageDeflateConfig> for PerMessageDeflateConfig {
    #[inline]
    fn from(value: sec_websocket_extensions::PerMessageDeflateConfig) -> Self {
        Self::from(&value)
    }
}

#[cfg(feature = "compression")]
impl From<&PerMessageDeflateConfig> for sec_websocket_extensions::PerMessageDeflateConfig {
    fn from(value: &PerMessageDeflateConfig) -> Self {
        Self {
            server_no_context_takeover: value.server_no_context_takeover,
            client_no_context_takeover: value.client_no_context_takeover,
            server_max_window_bits: value.server_max_window_bits,
            client_max_window_bits: value.client_max_window_bits,
            ..Default::default()
        }
    }
}

#[cfg(feature = "compression")]
impl From<PerMessageDeflateConfig> for sec_websocket_extensions::PerMessageDeflateConfig {
    #[inline]
    fn from(value: PerMessageDeflateConfig) -> Self {
        Self::from(&value)
    }
}

#[cfg(feature = "compression")]
#[allow(clippy::derivable_impls)]
impl Default for PerMessageDeflateConfig {
    fn default() -> Self {
        Self {
            // By default, allow context takeover in both directions
            server_no_context_takeover: false,
            client_no_context_takeover: false,

            // No limit: means default 15-bit window (32768 bytes)
            server_max_window_bits: None,
            client_max_window_bits: None,
        }
    }
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            read_buffer_size: 128 * 1024,
            write_buffer_size: 128 * 1024,
            max_write_buffer_size: usize::MAX,
            max_message_size: Some(64 << 20),
            max_frame_size: Some(16 << 20),
            accept_unmasked_frames: false,
            #[cfg(feature = "compression")]
            per_message_deflate: None,
        }
    }
}

impl WebSocketConfig {
    rama_utils::macros::generate_set_and_with! {
        /// Set [`Self::read_buffer_size`].
        #[must_use]
        pub fn read_buffer_size(mut self, read_buffer_size: usize) -> Self {
            self.read_buffer_size = read_buffer_size;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set [`Self::write_buffer_size`].
        #[must_use]
        pub fn write_buffer_size(mut self, write_buffer_size: usize) -> Self {
            self.write_buffer_size = write_buffer_size;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set [`Self::max_write_buffer_size`].
        #[must_use]
        pub fn max_write_buffer_size(mut self, max_write_buffer_size: usize) -> Self {
            self.max_write_buffer_size = max_write_buffer_size;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set [`Self::max_message_size`].
        #[must_use]
        pub fn max_message_size(mut self, max_message_size: Option<usize>) -> Self {
            self.max_message_size = max_message_size;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set [`Self::max_frame_size`].
        #[must_use]
        pub fn max_frame_size(mut self, max_frame_size: Option<usize>) -> Self {
            self.max_frame_size = max_frame_size;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set [`Self::accept_unmasked_frames`].
        #[must_use]
        pub fn accept_unmasked_frames(mut self, accept_unmasked_frames: bool) -> Self {
            self.accept_unmasked_frames = accept_unmasked_frames;
            self
        }
    }

    #[cfg(feature = "compression")]
    rama_utils::macros::generate_set_and_with! {
        /// Set [`Self::per_message_deflate`] with the default config..
        #[must_use]
        #[cfg_attr(docsrs, doc(cfg(feature = "compression")))]
        pub fn per_message_deflate_default(mut self) -> Self {
            self.per_message_deflate = Some(Default::default());
            self
        }
    }

    #[cfg(feature = "compression")]
    rama_utils::macros::generate_set_and_with! {
        /// Set [`Self::per_message_deflate`].
        #[must_use]
        #[cfg_attr(docsrs, doc(cfg(feature = "compression")))]
        pub fn per_message_deflate(mut self, per_message_deflate: Option<PerMessageDeflateConfig>) -> Self {
            self.per_message_deflate = per_message_deflate;
            self
        }
    }

    /// Panic if values are invalid.
    pub(crate) fn assert_valid(&self) {
        assert!(
            self.max_write_buffer_size > self.write_buffer_size,
            "WebSocketConfig::max_write_buffer_size must be greater than write_buffer_size, \
            see WebSocketConfig docs`"
        );
    }
}

/// WebSocket input-output stream.
///
/// This is THE structure you want to create to be able to speak the WebSocket protocol.
/// It may be created by calling `connect`, `accept` or `client` functions.
///
/// Use [`WebSocket::read`], [`WebSocket::send`] to received and send messages.
pub struct WebSocket<Stream> {
    /// The underlying socket.
    socket: Stream,
    /// The context for managing a WebSocket.
    context: WebSocketContext,
}

impl<Stream: fmt::Debug> fmt::Debug for WebSocket<Stream> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebSocket")
            .field("socket", &self.socket)
            .field("context", &self.context)
            .finish()
    }
}

impl<Stream> WebSocket<Stream> {
    /// Convert a raw socket into a WebSocket without performing a handshake.
    ///
    /// # Panics
    /// Panics if config is invalid e.g. `max_write_buffer_size <= write_buffer_size`.
    pub fn from_raw_socket(stream: Stream, role: Role, config: Option<WebSocketConfig>) -> Self {
        Self {
            socket: stream,
            context: WebSocketContext::new(role, config),
        }
    }

    /// Convert a raw socket into a WebSocket without performing a handshake.
    ///
    /// # Panics
    /// Panics if config is invalid e.g. `max_write_buffer_size <= write_buffer_size`.
    pub fn from_partially_read(
        stream: Stream,
        part: Vec<u8>,
        role: Role,
        config: Option<WebSocketConfig>,
    ) -> Self {
        Self {
            socket: stream,
            context: WebSocketContext::from_partially_read(part, role, config),
        }
    }

    /// Consumes the `WebSocket` and returns the underlying stream.
    pub(crate) fn into_inner(self) -> Stream {
        self.socket
    }

    /// Returns a shared reference to the inner stream.
    pub fn get_ref(&self) -> &Stream {
        &self.socket
    }
    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut Stream {
        &mut self.socket
    }

    /// Change the configuration.
    ///
    /// # Panics
    /// Panics if config is invalid e.g. `max_write_buffer_size <= write_buffer_size`.
    pub fn set_config(&mut self, set_func: impl FnOnce(&mut WebSocketConfig)) {
        self.context.set_config(set_func);
    }

    /// Read the configuration.
    pub fn get_config(&self) -> &WebSocketConfig {
        self.context.get_config()
    }

    /// Check if it is possible to read messages.
    ///
    /// Reading is impossible after receiving `Message::Close`. It is still possible after
    /// sending close frame since the peer still may send some data before confirming close.
    pub fn can_read(&self) -> bool {
        self.context.can_read()
    }

    /// Check if it is possible to write messages.
    ///
    /// Writing gets impossible immediately after sending or receiving `Message::Close`.
    pub fn can_write(&self) -> bool {
        self.context.can_write()
    }
}

impl<Stream: Read + Write> WebSocket<Stream> {
    /// Read a message from stream, if possible.
    ///
    /// This will also queue responses to ping and close messages. These responses
    /// will be written and flushed on the next call to [`read`](Self::read),
    /// [`write`](Self::write) or [`flush`](Self::flush).
    ///
    /// # Closing the connection
    /// When the remote endpoint decides to close the connection this will return
    /// the close message with an optional close frame.
    ///
    /// You should continue calling [`read`](Self::read), [`write`](Self::write) or
    /// [`flush`](Self::flush) to drive the reply to the close frame until [`ProtocolError::Io`] (close)
    /// is returned. Once that happens it is safe to drop the underlying connection.
    pub fn read(&mut self) -> Result<Message, ProtocolError> {
        self.context.read(&mut self.socket)
    }

    /// Writes and immediately flushes a message.
    /// Equivalent to calling [`write`](Self::write) then [`flush`](Self::flush).
    pub fn send(&mut self, message: Message) -> Result<(), ProtocolError> {
        self.write(message)?;
        self.flush()
    }

    /// Write a message to the provided stream, if possible.
    ///
    /// A subsequent call should be made to [`flush`](Self::flush) to flush writes.
    ///
    /// In the event of stream write failure the message frame will be stored
    /// in the write buffer and will try again on the next call to [`write`](Self::write)
    /// or [`flush`](Self::flush).
    ///
    /// If the write buffer would exceed the configured [`WebSocketConfig::max_write_buffer_size`]
    /// [`Err(WriteBufferFull(msg_frame))`](ProtocolError::WriteBufferFull) is returned.
    ///
    /// This call will generally not flush. However, if there are queued automatic messages
    /// they will be written and eagerly flushed.
    ///
    /// For example, upon receiving ping messages this crate queues pong replies automatically.
    /// The next call to [`read`](Self::read), [`write`](Self::write) or [`flush`](Self::flush)
    /// will write & flush the pong reply. This means you should not respond to ping frames manually.
    ///
    /// You can however send pong frames manually in order to indicate a unidirectional heartbeat
    /// as described in [RFC 6455](https://tools.ietf.org/html/rfc6455#section-5.5.3). Note that
    /// if [`read`](Self::read) returns a ping, you should [`flush`](Self::flush) before passing
    /// a custom pong to [`write`](Self::write), otherwise the automatic queued response to the
    /// ping will not be sent as it will be replaced by your custom pong message.
    ///
    /// # Errors
    /// - If the WebSocket's write buffer is full, [`ProtocolError::WriteBufferFull`] will be returned
    ///   along with the equivalent passed message frame.
    /// - If the connection is closed and should be dropped, this will return [`ProtocolError::Io`] (close).
    /// - If you try again after [`ProtocolError::Io`] (close) was returned either from here or from
    ///   [`read`](Self::read), [`ProtocolError::Io`] with reason will be returned. This indicates a program
    ///   error on your part.
    /// - [`ProtocolError::Io`] is returned if the underlying connection returns an error
    ///   (consider these fatal except for WouldBlock).
    /// - [`ProtocolError::Io`] if your message size is bigger than the configured max message size.
    pub fn write(&mut self, message: Message) -> Result<(), ProtocolError> {
        self.context.write(&mut self.socket, message)
    }

    /// Flush writes.
    ///
    /// Ensures all messages previously passed to [`write`](Self::write) and automatic
    /// queued pong responses are written & flushed into the underlying stream.
    pub fn flush(&mut self) -> Result<(), ProtocolError> {
        self.context.flush(&mut self.socket)
    }

    /// Close the connection.
    ///
    /// This function guarantees that the close frame will be queued.
    /// There is no need to call it again. Calling this function is
    /// the same as calling `write(Message::Close(..))`.
    ///
    /// After queuing the close frame you should continue calling [`read`](Self::read) or
    /// [`flush`](Self::flush) to drive the close handshake to completion.
    ///
    /// The websocket RFC defines that the underlying connection should be closed
    /// by the server. This crate takes care of this asymmetry for you.
    ///
    /// When the close handshake is finished (we have both sent and received
    /// a close message), [`read`](Self::read) or [`flush`](Self::flush) will return
    /// [`ProtocolError::Io`] (close) if this endpoint is the server.
    ///
    /// If this endpoint is a client, [`ProtocolError::Io`] (close) will only be
    /// returned after the server has closed the underlying connection.
    ///
    /// It is thus safe to drop the underlying connection as soon as [`ProtocolError::Io`] (close)
    /// is returned from [`read`](Self::read) or [`flush`](Self::flush).
    pub fn close(&mut self, code: Option<CloseFrame>) -> Result<(), ProtocolError> {
        self.context.close(&mut self.socket, code)
    }
}

impl<Stream: ExtensionsRef> ExtensionsRef for WebSocket<Stream> {
    fn extensions(&self) -> &Extensions {
        self.socket.extensions()
    }
}

impl<Stream: ExtensionsMut> ExtensionsMut for WebSocket<Stream> {
    fn extensions_mut(&mut self) -> &mut Extensions {
        self.socket.extensions_mut()
    }
}

/// A context for managing WebSocket stream.
#[derive(Debug)]
pub struct WebSocketContext {
    /// Server or client?
    role: Role,
    /// encoder/decoder of frame.
    frame: FrameCodec,
    /// The state of processing, either "active" or "closing".
    state: WebSocketState,
    #[cfg(feature = "compression")]
    /// The state used in function per-message compression,
    /// only set in case the extension is enabled.
    per_message_deflate_state: Option<PerMessageDeflateState>,
    /// Receive: an incomplete message being processed.
    incomplete: Option<IncompleteMessage>,
    /// Send in addition to regular messages E.g. "pong" or "close".
    additional_send: Option<Frame>,
    /// True indicates there is an additional message (like a pong)
    /// that failed to flush previously and we should try again.
    unflushed_additional: bool,
    /// The configuration for the websocket session.
    config: WebSocketConfig,
}

impl WebSocketContext {
    /// Create a WebSocket context that manages a post-handshake stream.
    ///
    /// # Panics
    /// Panics if config is invalid e.g. `max_write_buffer_size <= write_buffer_size`.
    #[must_use]
    pub fn new(role: Role, config: Option<WebSocketConfig>) -> Self {
        let conf = config.unwrap_or_default();
        Self::_new(role, FrameCodec::new(conf.read_buffer_size), conf)
    }

    /// Create a WebSocket context that manages an post-handshake stream.
    ///
    /// # Panics
    /// Panics if config is invalid e.g. `max_write_buffer_size <= write_buffer_size`.
    #[must_use]
    pub fn from_partially_read(part: Vec<u8>, role: Role, config: Option<WebSocketConfig>) -> Self {
        let conf = config.unwrap_or_default();
        Self::_new(
            role,
            FrameCodec::from_partially_read(part, conf.read_buffer_size),
            conf,
        )
    }

    fn _new(role: Role, mut frame: FrameCodec, config: WebSocketConfig) -> Self {
        config.assert_valid();
        frame.set_max_out_buffer_len(config.max_write_buffer_size);
        frame.set_out_buffer_write_len(config.write_buffer_size);
        Self {
            role,
            frame,
            state: WebSocketState::Active,
            #[cfg(feature = "compression")]
            per_message_deflate_state: config
                .per_message_deflate
                .map(|cfg| PerMessageDeflateState::new(role, cfg)),
            incomplete: None,
            additional_send: None,
            unflushed_additional: false,
            config,
        }
    }

    /// Change the configuration.
    ///
    /// # Panics
    /// Panics if config is invalid e.g. `max_write_buffer_size <= write_buffer_size`.
    pub fn set_config(&mut self, set_func: impl FnOnce(&mut WebSocketConfig)) {
        set_func(&mut self.config);
        self.config.assert_valid();
        self.frame
            .set_max_out_buffer_len(self.config.max_write_buffer_size);
        self.frame
            .set_out_buffer_write_len(self.config.write_buffer_size);
    }

    /// Read the configuration.
    pub fn get_config(&self) -> &WebSocketConfig {
        &self.config
    }

    /// Check if it is possible to read messages.
    ///
    /// Reading is impossible after receiving `Message::Close`. It is still possible after
    /// sending close frame since the peer still may send some data before confirming close.
    pub fn can_read(&self) -> bool {
        self.state.can_read()
    }

    /// Check if it is possible to write messages.
    ///
    /// Writing gets impossible immediately after sending or receiving `Message::Close`.
    pub fn can_write(&self) -> bool {
        self.state.is_active()
    }

    /// Read a message from the provided stream, if possible.
    ///
    /// This function sends pong and close responses automatically.
    /// However, it never blocks on write.
    pub fn read<Stream>(&mut self, stream: &mut Stream) -> Result<Message, ProtocolError>
    where
        Stream: Read + Write,
    {
        // Do not read from already closed connections.
        self.state.check_not_terminated()?;

        loop {
            if self.additional_send.is_some() || self.unflushed_additional {
                // Since we may get ping or close, we need to reply to the messages even during read.
                match self.flush(stream) {
                    Ok(_) => {}
                    Err(ProtocolError::Io(err)) if err.kind() == io::ErrorKind::WouldBlock => {
                        // If blocked continue reading, but try again later
                        self.unflushed_additional = true;
                    }
                    Err(err) => return Err(err),
                }
            } else if self.role == Role::Server && !self.state.can_read() {
                self.state = WebSocketState::Terminated;
                return Err(ProtocolError::Io(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    OpaqueError::from_display("Connection closed normally by me-the-server"),
                )));
            }

            // If we get here, either write blocks or we have nothing to write.
            // Thus if read blocks, just let it return WouldBlock.
            if let Some(message) = self.read_message_frame(stream)? {
                trace!("Received message {message}");
                return Ok(message);
            }
        }
    }

    /// Write a message to the provided stream.
    ///
    /// A subsequent call should be made to [`flush`](Self::flush) to flush writes.
    ///
    /// In the event of stream write failure the message frame will be stored
    /// in the write buffer and will try again on the next call to [`write`](Self::write)
    /// or [`flush`](Self::flush).
    ///
    /// If the write buffer would exceed the configured [`WebSocketConfig::max_write_buffer_size`]
    /// [`Err(WriteBufferFull(msg_frame))`](ProtocolError::WriteBufferFull) is returned.
    pub fn write<Stream>(
        &mut self,
        stream: &mut Stream,
        message: Message,
    ) -> Result<(), ProtocolError>
    where
        Stream: Read + Write,
    {
        // When terminated, return AlreadyClosed.
        self.state.check_not_terminated()?;

        // Do not write after sending a close frame.
        if !self.state.is_active() {
            return Err(ProtocolError::SendAfterClosing);
        }

        let frame = match message {
            Message::Text(data) => {
                #[cfg(feature = "compression")]
                match self.per_message_deflate_state.as_mut() {
                    Some(deflate_state) => {
                        let data = match deflate_state.encoder.encode(data.as_bytes()) {
                            Ok(data) => data,
                            Err(err) => return Err(ProtocolError::DeflateError(err)),
                        };
                        let mut msg = Frame::message(data, OpCode::Data(OpCodeData::Text), true);
                        msg.header_mut().rsv1 = true;
                        msg
                    }
                    None => Frame::message(data, OpCode::Data(OpCodeData::Text), true),
                }
                #[cfg(not(feature = "compression"))]
                Frame::message(data, OpCode::Data(OpCodeData::Text), true)
            }
            Message::Binary(data) => {
                #[cfg(feature = "compression")]
                match self.per_message_deflate_state.as_mut() {
                    Some(deflate_state) => {
                        let data = match deflate_state.encoder.encode(data.as_ref()) {
                            Ok(data) => data,
                            Err(err) => return Err(ProtocolError::DeflateError(err)),
                        };
                        let mut msg = Frame::message(data, OpCode::Data(OpCodeData::Binary), true);
                        msg.header_mut().rsv1 = true;
                        msg
                    }
                    None => Frame::message(data, OpCode::Data(OpCodeData::Binary), true),
                }
                #[cfg(not(feature = "compression"))]
                Frame::message(data, OpCode::Data(OpCodeData::Binary), true)
            }
            Message::Ping(data) => Frame::ping(data),
            Message::Pong(data) => {
                self.set_additional(Frame::pong(data));
                // Note: user pongs can be user flushed so no need to flush here
                return self._write(stream, None).map(|_| ());
            }
            Message::Close(code) => return self.close(stream, code),
            Message::Frame(f) => f,
        };

        let should_flush = self._write(stream, Some(frame))?;
        if should_flush {
            self.flush(stream)?;
        }
        Ok(())
    }

    /// Flush writes.
    ///
    /// Ensures all messages previously passed to [`write`](Self::write) and automatically
    /// queued pong responses are written & flushed into the `stream`.
    #[inline]
    pub fn flush<Stream>(&mut self, stream: &mut Stream) -> Result<(), ProtocolError>
    where
        Stream: Read + Write,
    {
        self._write(stream, None)?;
        self.frame.write_out_buffer(stream)?;
        stream.flush()?;
        self.unflushed_additional = false;
        Ok(())
    }

    /// Writes any data in the out_buffer, `additional_send` and given `data`.
    ///
    /// Does **not** flush.
    ///
    /// Returns true if the write contents indicate we should flush immediately.
    fn _write<Stream>(
        &mut self,
        stream: &mut Stream,
        data: Option<Frame>,
    ) -> Result<bool, ProtocolError>
    where
        Stream: Read + Write,
    {
        if let Some(data) = data {
            self.buffer_frame(stream, data)?;
        }

        // Upon receipt of a Ping frame, an endpoint MUST send a Pong frame in
        // response, unless it already received a Close frame. It SHOULD
        // respond with Pong frame as soon as is practical. (RFC 6455)
        let should_flush = if let Some(msg) = self.additional_send.take() {
            trace!("Sending pong/close");
            match self.buffer_frame(stream, msg) {
                Err(ProtocolError::WriteBufferFull(msg)) => {
                    // if an system message would exceed the buffer put it back in
                    // `additional_send` for retry. Otherwise returning this error
                    // may not make sense to the user, e.g. calling `flush`.
                    if let Message::Frame(msg) = msg {
                        self.set_additional(msg);
                        false
                    } else {
                        unreachable!();
                    }
                }
                Err(err) => return Err(err),
                Ok(_) => true,
            }
        } else {
            self.unflushed_additional
        };

        // If we're closing and there is nothing to send anymore, we should close the connection.
        if self.role == Role::Server && !self.state.can_read() {
            // The underlying TCP connection, in most normal cases, SHOULD be closed
            // first by the server, so that it holds the TIME_WAIT state and not the
            // client (as this would prevent it from re-opening the connection for 2
            // maximum segment lifetimes (2MSL), while there is no corresponding
            // server impact as a TIME_WAIT connection is immediately reopened upon
            // a new SYN with a higher seq number). (RFC 6455)
            self.frame.write_out_buffer(stream)?;
            self.state = WebSocketState::Terminated;
            Err(ProtocolError::Io(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                OpaqueError::from_display("Connection closed normally by me-the-server (EOF)"),
            )))
        } else {
            Ok(should_flush)
        }
    }

    /// Close the connection.
    ///
    /// This function guarantees that the close frame will be queued.
    /// There is no need to call it again. Calling this function is
    /// the same as calling `send(Message::Close(..))`.
    pub fn close<Stream>(
        &mut self,
        stream: &mut Stream,
        code: Option<CloseFrame>,
    ) -> Result<(), ProtocolError>
    where
        Stream: Read + Write,
    {
        if self.state == WebSocketState::Active {
            self.state = WebSocketState::ClosedByUs;
            let frame = Frame::close(code);
            self._write(stream, Some(frame))?;
        }
        self.flush(stream)
    }

    /// Try to decode one message frame. May return None.
    fn read_message_frame(
        &mut self,
        stream: &mut impl Read,
    ) -> Result<Option<Message>, ProtocolError> {
        let Some(frame) = self.frame.read_frame(
            stream,
            self.config.max_frame_size,
            matches!(self.role, Role::Server),
            self.config.accept_unmasked_frames,
        )?
        else {
            // Connection closed by peer
            return match std::mem::replace(&mut self.state, WebSocketState::Terminated) {
                WebSocketState::ClosedByPeer | WebSocketState::CloseAcknowledged => {
                    Err(ProtocolError::Io(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        OpaqueError::from_display("Connection closed normally by peer"),
                    )))
                }
                WebSocketState::Active
                | WebSocketState::ClosedByUs
                | WebSocketState::Terminated => Err(ProtocolError::ResetWithoutClosingHandshake),
            };
        };

        if !self.state.can_read() {
            return Err(ProtocolError::ReceivedAfterClosing);
        }

        #[cfg(feature = "compression")]
        // to ensure that this is valid in later branches,
        // as this is not always true despite an extension active that supports it
        let mut rsv1_set = false;

        // MUST be 0 unless an extension is negotiated that defines meanings
        // for non-zero values.  If a nonzero value is received and none of
        // the negotiated extensions defines the meaning of such a nonzero
        // value, the receiving endpoint MUST _Fail the WebSocket
        // Connection_.
        {
            let hdr = frame.header();
            if hdr.rsv1 {
                #[cfg(feature = "compression")]
                {
                    rsv1_set = true;
                    if self.per_message_deflate_state.is_none() {
                        tracing::debug!(
                            "rsv1 bit is set but PMD state is none: no use case for it"
                        );
                        return Err(ProtocolError::NonZeroReservedBits);
                    }
                }
                #[cfg(not(feature = "compression"))]
                {
                    tracing::debug!("rsv1 bit is set but compression feature no enabled");
                    return Err(ProtocolError::NonZeroReservedBits);
                }
            } else if hdr.rsv2 || hdr.rsv3 {
                tracing::debug!("rsv2 or rsv3 bit set: not expected ever");
                return Err(ProtocolError::NonZeroReservedBits);
            }
        }

        if self.role == Role::Client && frame.is_masked() {
            // A client MUST close a connection if it detects a masked frame. (RFC 6455)
            return Err(ProtocolError::MaskedFrameFromServer);
        }

        match frame.header().opcode {
            OpCode::Control(ctl) => {
                #[cfg(feature = "compression")]
                if rsv1_set {
                    tracing::debug!("rsv1 bit set in control frame: not expected");
                    return Err(ProtocolError::NonZeroReservedBits);
                }

                match ctl {
                    // All control frames MUST have a payload length of 125 bytes or less
                    // and MUST NOT be fragmented. (RFC 6455)
                    _ if !frame.header().is_final => Err(ProtocolError::FragmentedControlFrame),
                    _ if frame.payload().len() > 125 => Err(ProtocolError::ControlFrameTooBig),
                    OpCodeControl::Close => {
                        Ok(self.do_close(frame.into_close()?).map(Message::Close))
                    }
                    OpCodeControl::Reserved(i) => Err(ProtocolError::UnknownControlFrameType(i)),
                    OpCodeControl::Ping => {
                        let data = frame.into_payload();
                        // No ping processing after we sent a close frame.
                        if self.state.is_active() {
                            self.set_additional(Frame::pong(data.clone()));
                        }
                        Ok(Some(Message::Ping(data)))
                    }
                    OpCodeControl::Pong => Ok(Some(Message::Pong(frame.into_payload()))),
                }
            }

            OpCode::Data(data) => {
                let fin = frame.header().is_final;

                #[cfg(feature = "compression")]
                if matches!(data, OpCodeData::Continue) && rsv1_set {
                    tracing::debug!("rsv1 bit set in CONTINUE frame: not expected");
                    return Err(ProtocolError::NonZeroReservedBits);
                }

                let payload = match (data, self.incomplete.as_mut()) {
                    (OpCodeData::Continue, None) => {
                        #[cfg(feature = "compression")]
                        if let Some(deflate_state) = self.per_message_deflate_state.as_mut() {
                            if fin {
                                let (compressed_data, msg_type) =
                                    deflate_state.decompress_incomplete_msg.fin_buffer(
                                        frame.into_payload(),
                                        self.config.max_message_size,
                                    )?;
                                return match deflate_state.decoder.decode(compressed_data.as_ref())
                                {
                                    Ok(raw_data) => match msg_type {
                                        IncompleteMessageType::Text => {
                                            Ok(Some(Message::Text(Utf8Bytes::try_from(raw_data)?)))
                                        }
                                        IncompleteMessageType::Binary => {
                                            Ok(Some(Message::Binary(raw_data.into())))
                                        }
                                    },
                                    Err(err) => Err(ProtocolError::DeflateError(err)),
                                };
                            }

                            deflate_state
                                .decompress_incomplete_msg
                                .extend(frame.into_payload(), self.config.max_message_size)?;
                            Ok(None)
                        } else {
                            return Err(ProtocolError::UnexpectedContinueFrame);
                        }

                        #[cfg(not(feature = "compression"))]
                        return Err(ProtocolError::UnexpectedContinueFrame);
                    }
                    (OpCodeData::Continue, Some(incomplete)) => {
                        incomplete.extend(frame.into_payload(), self.config.max_message_size)?;
                        Ok(None)
                    }
                    (_, Some(_)) => Err(ProtocolError::ExpectedFragment(data)),
                    (OpCodeData::Text, _) => {
                        Ok(Some((frame.into_payload(), IncompleteMessageType::Text)))
                    }
                    (OpCodeData::Binary, _) => {
                        Ok(Some((frame.into_payload(), IncompleteMessageType::Binary)))
                    }
                    (OpCodeData::Reserved(i), _) => Err(ProtocolError::UnknownDataFrameType(i)),
                }?;

                match (payload, fin) {
                    (None, true) =>
                    {
                        #[allow(
                            clippy::expect_used,
                            reason = "we can only reach here if incomplete is Some"
                        )]
                        Ok(Some(
                            self.incomplete
                                .take()
                                .expect("incomplete to be there")
                                .complete()?,
                        ))
                    }
                    (None, false) => Ok(None),
                    (Some((payload, t)), true) => {
                        check_max_size(payload.len(), self.config.max_message_size)?;

                        #[cfg(feature = "compression")]
                        if rsv1_set {
                            if let Some(deflate_state) = self.per_message_deflate_state.as_mut() {
                                let compressed_data = payload;
                                let raw_data = deflate_state
                                    .decoder
                                    .decode(&compressed_data)
                                    .map_err(ProtocolError::DeflateError)?;
                                match t {
                                    IncompleteMessageType::Text => {
                                        Ok(Some(Message::Text(Utf8Bytes::try_from(raw_data)?)))
                                    }
                                    IncompleteMessageType::Binary => {
                                        Ok(Some(Message::Binary(raw_data.into())))
                                    }
                                }
                            } else {
                                tracing::debug!(
                                    "rsv1 bit set in text frame but deflate state is none"
                                );
                                Err(ProtocolError::NonZeroReservedBits)
                            }
                        } else {
                            match t {
                                IncompleteMessageType::Text => {
                                    Ok(Some(Message::Text(payload.try_into()?)))
                                }
                                IncompleteMessageType::Binary => Ok(Some(Message::Binary(payload))),
                            }
                        }

                        #[cfg(not(feature = "compression"))]
                        match t {
                            IncompleteMessageType::Text => {
                                Ok(Some(Message::Text(payload.try_into()?)))
                            }
                            IncompleteMessageType::Binary => Ok(Some(Message::Binary(payload))),
                        }
                    }
                    (Some((payload, t)), false) => {
                        #[cfg(feature = "compression")]
                        if rsv1_set {
                            if let Some(deflate_state) = self.per_message_deflate_state.as_mut() {
                                deflate_state.decompress_incomplete_msg.reset(t);
                                deflate_state
                                    .decompress_incomplete_msg
                                    .extend(payload, self.config.max_message_size)?;
                                Ok(None)
                            } else {
                                tracing::debug!(
                                    "rsv1 bit set in non-fin bin/text frame but deflate state is none"
                                );
                                Err(ProtocolError::NonZeroReservedBits)
                            }
                        } else {
                            let mut incomplete = IncompleteMessage::new(t);
                            incomplete.extend(payload, self.config.max_message_size)?;
                            self.incomplete = Some(incomplete);
                            Ok(None)
                        }
                        #[cfg(not(feature = "compression"))]
                        {
                            let mut incomplete = IncompleteMessage::new(t);
                            incomplete.extend(payload, self.config.max_message_size)?;
                            self.incomplete = Some(incomplete);
                            Ok(None)
                        }
                    }
                }
            }
        } // match opcode
    }

    /// Received a close frame. Tells if we need to return a close frame to the user.
    #[allow(clippy::option_option)]
    fn do_close(&mut self, close: Option<CloseFrame>) -> Option<Option<CloseFrame>> {
        rama_core::telemetry::tracing::trace!("Received close frame: {close:?}");
        match self.state {
            WebSocketState::Active => {
                self.state = WebSocketState::ClosedByPeer;

                let close = close.map(|frame| {
                    if !frame.code.is_allowed() {
                        CloseFrame {
                            code: CloseCode::Protocol,
                            reason: Utf8Bytes::from_static("Protocol violation"),
                        }
                    } else {
                        frame
                    }
                });

                let reply = Frame::close(close.clone());
                debug!("Replying to close with {reply:?}");
                self.set_additional(reply);

                Some(close)
            }
            WebSocketState::ClosedByPeer | WebSocketState::CloseAcknowledged => {
                // It is already closed, just ignore.
                None
            }
            WebSocketState::ClosedByUs => {
                // We received a reply.
                self.state = WebSocketState::CloseAcknowledged;
                Some(close)
            }
            WebSocketState::Terminated => unreachable!(),
        }
    }

    /// Write a single frame into the write-buffer.
    fn buffer_frame<Stream>(
        &mut self,
        stream: &mut Stream,
        mut frame: Frame,
    ) -> Result<(), ProtocolError>
    where
        Stream: Read + Write,
    {
        match self.role {
            Role::Server => {}
            Role::Client => {
                // 5.  If the data is being sent by the client, the frame(s) MUST be
                // masked as defined in Section 5.3. (RFC 6455)
                frame.set_random_mask();
            }
        }

        trace!("Sending frame: {frame:?}");
        self.frame.buffer_frame(stream, frame)
    }

    /// Replace `additional_send` if it is currently a `Pong` message.
    fn set_additional(&mut self, add: Frame) {
        let empty_or_pong = self
            .additional_send
            .as_ref()
            .is_none_or(|f| f.header().opcode == OpCode::Control(OpCodeControl::Pong));
        if empty_or_pong {
            self.additional_send.replace(add);
        }
    }
}

fn check_max_size(size: usize, max_size: Option<usize>) -> Result<(), ProtocolError> {
    if let Some(max_size) = max_size
        && size > max_size
    {
        return Err(ProtocolError::MessageTooLong { size, max_size });
    }
    Ok(())
}

/// The current connection state.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum WebSocketState {
    /// The connection is active.
    Active,
    /// We initiated a close handshake.
    ClosedByUs,
    /// The peer initiated a close handshake.
    ClosedByPeer,
    /// The peer replied to our close handshake.
    CloseAcknowledged,
    /// The connection does not exist anymore.
    Terminated,
}

impl WebSocketState {
    /// Tell if we're allowed to process normal messages.
    fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Tell if we should process incoming data. Note that if we send a close frame
    /// but the remote hasn't confirmed, they might have sent data before they receive our
    /// close frame, so we should still pass those to client code, hence ClosedByUs is valid.
    fn can_read(self) -> bool {
        matches!(self, Self::Active | Self::ClosedByUs)
    }

    /// Check if the state is active, return error if not.
    fn check_not_terminated(self) -> Result<(), ProtocolError> {
        match self {
            Self::Terminated => Err(ProtocolError::Io(io::Error::new(
                io::ErrorKind::NotConnected,
                OpaqueError::from_display("Trying to work with closed connection"),
            ))),
            Self::Active | Self::CloseAcknowledged | Self::ClosedByPeer | Self::ClosedByUs => {
                Ok(())
            }
        }
    }
}
