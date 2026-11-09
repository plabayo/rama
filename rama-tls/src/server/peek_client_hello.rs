use std::{num::NonZeroUsize, time::Duration};

use rama_core::{
    Service,
    error::{BoxError, ErrorContext},
    extensions::ExtensionsRef,
    io::{
        HeapReader, PeekIoProvider, PrefixedIo,
        peek::{
            PeekOutput, PeekPolicy, PeekStopReason, PeekVerdict, PeekWaiter,
            peek_input_until_verdict_growing_with_output, peek_input_until_verdict_with_options,
        },
    },
    service::RejectService,
    telemetry::tracing,
};
use rama_utils::octets::kib;

use crate::client::{
    ClientHello, ClientHelloHandshakePrefix, ClientHelloPeekStatus, ClientHelloReassemblyConfig,
    MalformedTlsPolicy, parse_client_hello_handshake_prefix_with_config,
};

use super::NoTlsRejectError;

/// A peek [`Service`] which returns the [`ClientHello`] to the inner
/// service for tls-detected traffic, and otherwise make use of the Reject service.
///
/// The difference with [`SniRouter`] is that the entire
/// [`ClientHello`] is parsed and returned instead of just the SNI. Use the router
/// in case all you care about is the SNI. Both use the same validated hello.
///
/// By default non-tls traffic is rejected using [`RejectService`].
/// Use [`PeekTlsClientHelloService::with_fallback`] to configure the fallback service.
/// Non-TLS traffic invokes that fallback. By default malformed, over-limit, or
/// EOF-truncated TLS also invokes it, with a [`ClientHelloPeekStatus`] extension
/// identifying the failure. Use [`PeekTlsClientHelloService::with_malformed_tls_policy`]
/// to opt into rejection. With the default [`PeekPolicy::FAIL_OPEN`], a
/// timed-out prefix also invokes the fallback. Strict SNI routing should select
/// [`MalformedTlsPolicy::Reject`] and a [`PeekPolicy`] that never falls back on
/// partial input, see [`PeekTlsClientHelloService::with_peek_policy`].
///
/// Use the standalone [`peek_client_hello_from_input`] function if you prefer
/// this is as a standalone function instead.
///
/// [`SniRouter`]: super::SniRouter
#[derive(Debug, Clone, ExtensionsRef)]
pub struct PeekTlsClientHelloService<S, F = RejectService<(), NoTlsRejectError>> {
    #[extensions_ref]
    service: S,
    fallback: F,
    peek_timeout: Option<Duration>,
    peek_policy: PeekPolicy,
    reassembly_config: ClientHelloReassemblyConfig,
    malformed_tls_policy: MalformedTlsPolicy,
}

impl<S> PeekTlsClientHelloService<S> {
    /// Create a new [`PeekTlsClientHelloService`].
    pub fn new(service: S) -> Self {
        Self {
            service,
            fallback: RejectService::new(NoTlsRejectError),
            peek_timeout: None,
            peek_policy: PeekPolicy::FAIL_OPEN,
            reassembly_config: ClientHelloReassemblyConfig::default(),
            malformed_tls_policy: MalformedTlsPolicy::default(),
        }
    }

    /// Attach a fallback [`Service`] to this [`PeekTlsClientHelloService`].
    ///
    /// Used for non-TLS traffic and whenever the configured peek policies select fallback.
    pub fn with_fallback<F>(self, fallback: F) -> PeekTlsClientHelloService<S, F> {
        PeekTlsClientHelloService {
            service: self.service,
            fallback,
            peek_timeout: self.peek_timeout,
            peek_policy: self.peek_policy,
            reassembly_config: self.reassembly_config,
            malformed_tls_policy: self.malformed_tls_policy,
        }
    }
}

impl<S, F> PeekTlsClientHelloService<S, F> {
    rama_utils::macros::generate_set_and_with! {
        /// Choose whether unparseable, over-limit, or EOF-truncated TLS is
        /// sent to the fallback (the default) or rejected.
        /// This does not change the reassembly bounds or peek policy.
        pub fn malformed_tls_policy(mut self, policy: MalformedTlsPolicy) -> Self {
            self.malformed_tls_policy = policy;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Configure ClientHello size, record count, and legacy-version checks.
        /// Defaults to 256 KiB across 256 records with tolerant legacy versions.
        pub fn reassembly_config(mut self, config: ClientHelloReassemblyConfig) -> Self {
            self.reassembly_config = config;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the maximum time spent peeking for a TLS ClientHello.
        ///
        /// A timeout is inconclusive. Use
        /// [`PeekTlsClientHelloService::with_peek_policy`] to choose whether it
        /// invokes the fallback, rejects the connection or keeps waiting.
        pub fn peek_timeout(mut self, peek_timeout: Option<Duration>) -> Self {
            self.peek_timeout = peek_timeout;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set how a peek timeout or [`PeekInterrupt`] is handled.
        ///
        /// Defaults to [`PeekPolicy::FAIL_OPEN`]. Non-TLS traffic invokes
        /// the fallback; malformed TLS follows the separate malformed-TLS policy.
        ///
        /// [`PeekInterrupt`]: rama_core::io::peek::PeekInterrupt
        pub fn peek_policy(mut self, peek_policy: PeekPolicy) -> Self {
            self.peek_policy = peek_policy;
            self
        }
    }
}

/// Functional API to try to peek TLS:CH from an existing I/O input,
/// returning the stream as-is with the read data prefixed from memory.
///
/// A timeout invokes the fallback. Use [`peek_client_hello_from_input_with_config`]
/// to configure the [`PeekWaiter`]. Unparseable TLS also selects fallback by
/// default; use [`peek_client_hello_from_input_with_policies`] to opt into
/// rejection or obtain the inspection status.
///
/// Use [`PeekTlsClientHelloService`] if you prefer it as a rama [`Service`] instead.
pub async fn peek_client_hello_from_input<PeekableInput>(
    input: PeekableInput,
    timeout: Option<Duration>,
) -> Result<
    (
        PeekableInput::Mapped<TlsClientHelloPrefixedIo<PeekableInput::PeekIo>>,
        Option<ClientHello>,
    ),
    std::io::Error,
>
where
    PeekableInput: PeekIoProvider<PeekIo: Unpin>,
{
    peek_client_hello_from_input_with_config(
        input,
        PeekWaiter::new(timeout),
        ClientHelloReassemblyConfig::default(),
    )
    .await
}

/// Peek a ClientHello with an explicit [`PeekWaiter`] and reassembly configuration.
///
/// Unparseable, over-limit, and EOF-truncated TLS selects fallback. Use
/// [`peek_client_hello_from_input_with_policies`] to opt into rejection or obtain
/// the inspection status.
pub async fn peek_client_hello_from_input_with_config<PeekableInput>(
    input: PeekableInput,
    waiter: PeekWaiter,
    config: ClientHelloReassemblyConfig,
) -> Result<
    (
        PeekableInput::Mapped<TlsClientHelloPrefixedIo<PeekableInput::PeekIo>>,
        Option<ClientHello>,
    ),
    std::io::Error,
>
where
    PeekableInput: PeekIoProvider<PeekIo: Unpin>,
{
    let (input, hello, _) = peek_client_hello_from_input_with_policies(
        input,
        waiter,
        MalformedTlsPolicy::default(),
        config,
    )
    .await?;
    Ok((input, hello))
}

/// Peek a ClientHello with an explicit [`PeekWaiter`], parse-failure, and reassembly policies.
///
/// Preserves every consumed wire byte, including record headers and any bytes
/// read beyond the hello. A TLS content type (20 through 24) followed by the
/// legacy major version 3 identifies TLS. Malformed headers, non-ClientHello
/// messages, limit violations, and EOF within that prefix follow
/// `malformed_tls_policy`: reject, or return the stream with no hello for fallback.
/// The third return value records why inspection failed. Services insert this
/// [`ClientHelloPeekStatus`] into their input's extensions before dispatching.
/// A lone content-type byte at EOF remains unclassified. Fallback stops peeking
/// at the failure; it does not raise or disable the reassembly bounds.
/// Cutoffs follow the [`PeekPolicy`] of the `waiter`, which is shared by the
/// header and body phases; read failures always return an error.
pub async fn peek_client_hello_from_input_with_policies<PeekableInput>(
    mut input: PeekableInput,
    mut waiter: PeekWaiter,
    malformed_tls_policy: MalformedTlsPolicy,
    config: ClientHelloReassemblyConfig,
) -> Result<
    (
        PeekableInput::Mapped<TlsClientHelloPrefixedIo<PeekableInput::PeekIo>>,
        Option<ClientHello>,
        ClientHelloPeekStatus,
    ),
    std::io::Error,
>
where
    PeekableInput: PeekIoProvider<PeekIo: Unpin>,
{
    let mut peek_buf = [0u8; TLS_HEADER_PEEK_LEN];
    let peekable_io = input.peek_io_mut();

    // Fail fast on non-TLS prefixes (see `client_hello_header_verdict`) instead of
    // blocking until the full 5-byte window arrives; no attempt cap so a
    // fragmented but still-plausible TLS header keeps reading (bounded by the
    // buffer, EOF, and the waiter).
    let PeekOutput {
        data,
        peek_size,
        stop_reason,
    } = peek_input_until_verdict_with_options(
        peekable_io,
        &mut peek_buf,
        0,
        &mut waiter,
        None,
        client_hello_header_verdict,
    )
    .await;

    waiter.check::<std::io::Error>()?;

    if stop_reason == PeekStopReason::ReadError {
        return Err(std::io::Error::other("I/O failure reading TLS header"));
    }
    // Identify the TLS record family by content type and legacy major version;
    // the content-type byte alone can also belong to a non-TLS binary protocol.
    let tls_candidate = peek_size >= 2 && matches!(peek_buf[0], 20..=24) && peek_buf[1] == 3;
    if data.is_none()
        && tls_candidate
        && !stop_reason.is_cutoff()
        && malformed_tls_policy == MalformedTlsPolicy::Reject
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed or truncated TLS ClientHello header",
        ));
    }

    let is_tls = data.is_some();
    tracing::trace!("tls prefix header read (is tls: {is_tls})");

    if !is_tls {
        if TLS_HEADER_PEEK_LEN.saturating_sub(peek_size) > 0 {
            tracing::trace!(
                "move tls peek buffer cursor due to reading not enough (read: {peek_size})"
            );
        }

        let prefix_data = HeapReader::from(&peek_buf[..peek_size.min(TLS_HEADER_PEEK_LEN)]);
        let peeked_input = input.map_peek_io(|io| PrefixedIo::new(prefix_data, io));

        tracing::trace!("return without a ClientHello after header classification");
        let failure = if stop_reason.is_cutoff() || tls_candidate {
            Some(stop_reason)
        } else {
            None
        };
        return Ok((peeked_input, None, ClientHelloPeekStatus { failure }));
    }

    // Grow with actual input, bounded by handshake bytes plus record headers
    // and the final record's tail. Keep the original framing for replay.
    let read_chunk = NonZeroUsize::new(kib(1)).unwrap_or(NonZeroUsize::MIN);

    let mut v = Vec::with_capacity(read_chunk.get() + TLS_HEADER_PEEK_LEN);
    v.extend_from_slice(&peek_buf[..]);

    let output = peek_input_until_verdict_growing_with_output(
        peekable_io,
        &mut v,
        config.max_wire_size(),
        read_chunk,
        &mut waiter,
        |buffer| match parse_client_hello_handshake_prefix_with_config(buffer, config) {
            ClientHelloHandshakePrefix::Complete(hello) => PeekVerdict::Match(hello),
            ClientHelloHandshakePrefix::Incomplete => PeekVerdict::NeedMore,
            ClientHelloHandshakePrefix::Invalid => PeekVerdict::Reject,
        },
    )
    .await;

    waiter.check::<std::io::Error>()?;

    match output.stop_reason {
        PeekStopReason::Match | PeekStopReason::Timeout | PeekStopReason::Interrupted => {}
        PeekStopReason::ReadError => {
            return Err(std::io::Error::other("I/O failure reading TLS ClientHello"));
        }
        _ if malformed_tls_policy == MalformedTlsPolicy::Reject => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed, truncated, or over-limit TLS ClientHello",
            ));
        }
        _ => {} // Explicit fallback preserves the bounded prefix and unread stream.
    }

    let prefix_data = HeapReader::from(v);
    let peeked_input = input.map_peek_io(|io| PrefixedIo::new(prefix_data, io));

    let status = ClientHelloPeekStatus {
        failure: output.data.is_none().then_some(output.stop_reason),
    };
    Ok((peeked_input, output.data, status))
}

impl<PeekableInput, Output, S, F> Service<PeekableInput> for PeekTlsClientHelloService<S, F>
where
    PeekableInput: PeekIoProvider<PeekIo: Unpin> + ExtensionsRef,
    Output: Send + 'static,
    S: Service<
            InputWithClientHello<
                PeekableInput::Mapped<TlsClientHelloPrefixedIo<PeekableInput::PeekIo>>,
            >,
            Output = Output,
            Error: Into<BoxError>,
        >,
    F: Service<
            PeekableInput::Mapped<TlsClientHelloPrefixedIo<PeekableInput::PeekIo>>,
            Output = Output,
            Error: Into<BoxError>,
        >,
{
    type Output = Output;
    type Error = BoxError;

    async fn serve(&self, input: PeekableInput) -> Result<Self::Output, Self::Error> {
        let extensions = input.extensions().clone();
        let waiter = PeekWaiter::new(self.peek_timeout)
            .with_policy(self.peek_policy)
            .maybe_with_interrupt(extensions.get_arc());
        let (peeked_input, maybe_client_hello, status) =
            peek_client_hello_from_input_with_policies(
                input,
                waiter,
                self.malformed_tls_policy,
                self.reassembly_config,
            )
            .await
            .context("I/O error while peeking TLS:CH from existing input")?;

        extensions.insert(status);
        if let Some(client_hello) = maybe_client_hello {
            self.service
                .serve(InputWithClientHello {
                    input: peeked_input,
                    client_hello,
                })
                .await
                .map_err(Into::into)
        } else {
            self.fallback.serve(peeked_input).await.map_err(Into::into)
        }
    }
}

// Inspect enough of the prefix to distinguish a TLS record from non-TLS
// binary traffic. The content type alone is ambiguous. Once a TLS major
// version follows it, a non-handshake content type is invalid for ClientHello.
fn client_hello_header_verdict(buffer: &[u8]) -> PeekVerdict<()> {
    match buffer {
        // TLS record content types 20..=24: change_cipher_spec, alert,
        // handshake, application_data, heartbeat. One byte is ambiguous.
        [] | [20..=24] => PeekVerdict::NeedMore,
        // The legacy TLS major version is 3 (SSL 3.0 through TLS 1.3).
        // The shared classifier requires handshake (22) and a recognized minor.
        [20..=24, 3, ..] => super::peek::tls_record_header_verdict(buffer),
        _ => PeekVerdict::Reject,
    }
}

const TLS_HEADER_PEEK_LEN: usize = 5;

/// [`PrefixedIo`] alias used by [`PeekTlsClientHelloService`].
pub type TlsClientHelloPrefixedIo<S> = PrefixedIo<HeapReader, S>;

/// An `input` with a Client Hello (tls) attached to it,
/// usually used in combination with [`PeekTlsClientHelloService`].
#[derive(Debug, Clone)]
pub struct InputWithClientHello<Input> {
    pub input: Input,
    pub client_hello: ClientHello,
}

#[cfg(test)]
mod test {
    use rama_core::{
        ServiceInput,
        error::error_chain,
        service::{RejectError, service_fn},
    };
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use rama_core::io::{Io, peek::PeekTimeoutError};

    use super::*;

    type PeekedCursor = TlsClientHelloPrefixedIo<ServiceInput<std::io::Cursor<Vec<u8>>>>;

    const CH_ONE_ONE_ONE_ONE: &[u8] = &[
        0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03, 0x02, 0x15, 0xfd, 0xe2,
        0x92, 0xc0, 0x46, 0x9f, 0x92, 0xbe, 0xd7, 0xe9, 0x1a, 0x3c, 0x50, 0x5e, 0x55, 0x49, 0x17,
        0xa6, 0xf8, 0xa5, 0xca, 0xa4, 0x6d, 0x60, 0xcc, 0xea, 0xf7, 0x25, 0xf0, 0x6e, 0x20, 0x41,
        0x20, 0x18, 0x66, 0x5c, 0xae, 0x08, 0xb0, 0x10, 0x96, 0x3c, 0xad, 0xb4, 0x13, 0xe1, 0x92,
        0xce, 0x96, 0xad, 0x9d, 0x45, 0x05, 0xb7, 0xa6, 0x4c, 0x01, 0x71, 0x08, 0x74, 0x0d, 0x1f,
        0x35, 0x00, 0x2a, 0x3a, 0x3a, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2c, 0xc0, 0x2b,
        0xcc, 0xa9, 0xc0, 0x30, 0xc0, 0x2f, 0xcc, 0xa8, 0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x14, 0xc0,
        0x13, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x35, 0x00, 0x2f, 0xc0, 0x08, 0xc0, 0x12, 0x00, 0x0a,
        0x01, 0x00, 0x01, 0x89, 0xda, 0xda, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x12, 0x00,
        0x00, 0x0f, 0x6f, 0x6e, 0x65, 0x2e, 0x6f, 0x6e, 0x65, 0x2e, 0x6f, 0x6e, 0x65, 0x2e, 0x6f,
        0x6e, 0x65, 0x00, 0x17, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x0c,
        0x00, 0x0a, 0xfa, 0xfa, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x00, 0x0b, 0x00,
        0x02, 0x01, 0x00, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
        0x16, 0x00, 0x14, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x08, 0x05,
        0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01, 0x00, 0x12, 0x00, 0x00, 0x00, 0x33, 0x00,
        0x2b, 0x00, 0x29, 0xfa, 0xfa, 0x00, 0x01, 0x00, 0x00, 0x1d, 0x00, 0x20, 0x7c, 0xe1, 0xc6,
        0xc2, 0x01, 0x69, 0x42, 0xba, 0x2b, 0xec, 0x07, 0x2f, 0x04, 0xbd, 0xb6, 0x2a, 0x7e, 0x04,
        0x6b, 0x96, 0x98, 0x51, 0x4e, 0x80, 0xb3, 0x2a, 0x4c, 0x4f, 0x1f, 0x39, 0x82, 0x2b, 0x00,
        0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x2b, 0x00, 0x0b, 0x0a, 0x6a, 0x6a, 0x03, 0x04, 0x03,
        0x03, 0x03, 0x02, 0x03, 0x01, 0x00, 0x1b, 0x00, 0x03, 0x02, 0x00, 0x01, 0x3a, 0x3a, 0x00,
        0x01, 0x00, 0x00, 0x15, 0x00, 0xd3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    const TLS_BUT_NO_SNI: &[u8] = &[
        0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03, 0x28, 0x5b, 0x8f, 0x90,
        0x22, 0x2a, 0x90, 0x95, 0x89, 0xa9, 0x62, 0x1f, 0xdb, 0x68, 0xbe, 0x4c, 0x0e, 0xdf, 0xe4,
        0x76, 0x50, 0x48, 0xa5, 0x40, 0x56, 0x5f, 0x9a, 0xba, 0x19, 0x29, 0x66, 0xdd, 0x20, 0x7a,
        0x7f, 0x7e, 0xc7, 0xbd, 0xfb, 0x88, 0x07, 0xd9, 0xf5, 0x99, 0xfa, 0xf3, 0x0d, 0x37, 0x30,
        0x52, 0x4d, 0x44, 0xe4, 0x26, 0xc0, 0xd1, 0x9a, 0xcd, 0x78, 0xf6, 0x7a, 0xf1, 0x7a, 0x66,
        0xe1, 0x00, 0x3e, 0x13, 0x02, 0x13, 0x03, 0x13, 0x01, 0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f,
        0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0,
        0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39,
        0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00,
        0x35, 0x00, 0x2f, 0x00, 0xff, 0x01, 0x00, 0x01, 0x75, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00,
        0x01, 0x02, 0x00, 0x0a, 0x00, 0x16, 0x00, 0x14, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00,
        0x19, 0x00, 0x18, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x00, 0x10,
        0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e,
        0x31, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0x0d,
        0x00, 0x2a, 0x00, 0x28, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08,
        0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01,
        0x06, 0x01, 0x03, 0x03, 0x03, 0x01, 0x03, 0x02, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x00,
        0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00,
        0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0xe0, 0xb9, 0xfb, 0x5a, 0xd5, 0x60,
        0x30, 0x39, 0xad, 0xfb, 0xd3, 0x94, 0xa2, 0xff, 0x08, 0x71, 0x9b, 0xcc, 0x6f, 0xbe, 0x9e,
        0xcc, 0x7b, 0xad, 0x3c, 0xd0, 0xde, 0xe8, 0x3e, 0x5d, 0xba, 0x6b, 0x00, 0x15, 0x00, 0xca,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[tokio::test]
    async fn binary_non_tls_prefixes_reach_fallback_with_original_bytes() {
        // A content-type-shaped first byte does not by itself identify TLS.
        for bytes in [
            &b"\x17hello world"[..],
            &b"\x16GET / HTTP/1.1\r\n"[..],
            &b"\x14\x00\x00"[..],
            &b"\x16\x02"[..],
            &b"\x16"[..],
        ] {
            for policy in [PeekPolicy::FAIL_OPEN, PeekPolicy::FAIL_CLOSED] {
                let (mut io, hello) = peek_client_hello_from_input_with_config(
                    std::io::Cursor::new(bytes.to_vec()),
                    PeekWaiter::new(None).with_policy(policy),
                    ClientHelloReassemblyConfig::default(),
                )
                .await
                .unwrap();
                assert!(hello.is_none());
                let mut replay = Vec::new();
                io.read_to_end(&mut replay).await.unwrap();
                assert_eq!(replay, bytes);
            }
        }
    }

    #[tokio::test]
    async fn tls_failure_policy_controls_fallback_and_marks_replayed_bytes() {
        use crate::client::test_support::{fragments, hello, record};
        let message = hello(0);
        let full = fragments(&message, 2);
        let mut cases = vec![
            vec![0x16, 3],
            vec![0x16, 3, 1],
            vec![0x16, 3, 1, 0],
            vec![0x16, 3, 5],
            vec![0x17, 3, 3, 0, 1, 0],
            vec![0x16, 3, 1, 0, 0],
            vec![0x16, 3, 1, 0x40, 1],
            vec![0x16, 3, 1, 0x40, 0, 1, 4, 0, 0],
            fragments(&hello(400), 1),
            record(&[1, 0, 0, 0]),
        ];
        cases.extend((5..full.len()).map(|end| full[..end].to_vec()));
        for timeout_policy in [PeekPolicy::FAIL_OPEN, PeekPolicy::FAIL_CLOSED] {
            for malformed_policy in [MalformedTlsPolicy::Reject, MalformedTlsPolicy::Fallback] {
                for bytes in &cases {
                    let fallback_calls = Arc::new(AtomicUsize::new(0));
                    let calls = fallback_calls.clone();
                    let router = PeekTlsClientHelloService::new(service_fn(async || {
                        Ok::<_, Infallible>(Vec::<u8>::new())
                    }))
                    .with_peek_policy(timeout_policy)
                    .with_malformed_tls_policy(malformed_policy)
                    .with_fallback(service_fn(
                        move |mut io: PeekedCursor| {
                            let calls = calls.clone();
                            async move {
                                calls.fetch_add(1, Ordering::SeqCst);
                                let status =
                                    io.extensions().get_ref::<ClientHelloPeekStatus>().unwrap();
                                assert!(matches!(
                                    status.failure,
                                    Some(PeekStopReason::Rejected | PeekStopReason::Eof)
                                ));
                                let mut replay = Vec::new();
                                io.read_to_end(&mut replay).await.unwrap();
                                Ok::<_, Infallible>(replay)
                            }
                        },
                    ));
                    let result = router
                        .serve(ServiceInput::new(std::io::Cursor::new(bytes.clone())))
                        .await;
                    if malformed_policy == MalformedTlsPolicy::Reject {
                        result.unwrap_err();
                        assert_eq!(fallback_calls.load(Ordering::SeqCst), 0);
                    } else {
                        assert_eq!(result.unwrap(), *bytes);
                        assert_eq!(fallback_calls.load(Ordering::SeqCst), 1);
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn fallback_does_not_wait_past_reassembly_limits_and_keeps_unread_bytes() {
        use crate::client::test_support::{fragments, hello, record};
        let message = hello(400);
        let single = record(&message);
        let mut split = record(&message[..1]);
        split.extend(fragments(&message[1..], 64));
        for (wire, sent, config) in [
            (
                single,
                9,
                ClientHelloReassemblyConfig::default().with_max_handshake_size(64),
            ),
            (
                split,
                6,
                ClientHelloReassemblyConfig::default().with_max_records(1),
            ),
        ] {
            let (mut client, server) = tokio::io::duplex(wire.len());
            client.write_all(&wire[..sent]).await.unwrap();
            // The client remains open and sends no further bytes until the
            // peeker stops. A raised/disabled bound would hang here.
            let (mut input, hello, status) = tokio::time::timeout(
                Duration::from_secs(1),
                peek_client_hello_from_input_with_policies(
                    server,
                    PeekWaiter::new(None).with_policy(PeekPolicy::FAIL_CLOSED),
                    MalformedTlsPolicy::Fallback,
                    config,
                ),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(hello.is_none());
            assert_eq!(status.failure, Some(PeekStopReason::Rejected));
            client.write_all(&wire[sent..]).await.unwrap();
            drop(client);
            let mut replay = Vec::new();
            input.read_to_end(&mut replay).await.unwrap();
            assert_eq!(replay, wire);
        }
    }

    #[tokio::test]
    async fn peek_status_shadows_stale_failures_and_preserves_bridge_extensions() {
        use crate::client::test_support::{hello, record};
        use rama_core::io::BridgeIo;
        for wire in [b"GET / HTTP/1.1\r\n".to_vec(), record(&hello(0))] {
            let input = ServiceInput::new(std::io::Cursor::new(wire));
            input.extensions().insert(ClientHelloPeekStatus {
                failure: Some(PeekStopReason::Eof),
            });
            let extensions = input.extensions().clone();
            let service = service_fn(
                async |input: InputWithClientHello<
                    BridgeIo<PeekedCursor, std::io::Cursor<Vec<u8>>>,
                >| {
                    assert!(
                        input
                            .input
                            .extensions()
                            .get_ref::<ClientHelloPeekStatus>()
                            .unwrap()
                            .failure
                            .is_none()
                    );
                    Ok::<_, Infallible>(())
                },
            );
            let fallback = service_fn(
                async |input: BridgeIo<PeekedCursor, std::io::Cursor<Vec<u8>>>| {
                    assert!(
                        input
                            .extensions()
                            .get_ref::<ClientHelloPeekStatus>()
                            .unwrap()
                            .failure
                            .is_none()
                    );
                    Ok::<_, Infallible>(())
                },
            );
            PeekTlsClientHelloService::new(service)
                .with_fallback(fallback)
                .serve(BridgeIo(input, std::io::Cursor::new(Vec::new())))
                .await
                .unwrap();
            assert!(
                extensions
                    .get_ref::<ClientHelloPeekStatus>()
                    .unwrap()
                    .failure
                    .is_none()
            );
        }
    }

    #[tokio::test]
    async fn peeker_config_and_large_record_fragmented_hello_replay() {
        use crate::client::test_support::{fragments, hello};
        let message = hello(60_000);
        let mut wire = fragments(&message, kib(16));
        wire.extend_from_slice(b"next record");
        let router = PeekTlsClientHelloService::new(service_fn(
            async |mut req: InputWithClientHello<
                TlsClientHelloPrefixedIo<ServiceInput<std::io::Cursor<Vec<u8>>>>,
            >| {
                assert_eq!(
                    req.client_hello.ext_server_name().unwrap().as_str(),
                    "x.com"
                );
                let mut replay = Vec::new();
                req.input.read_to_end(&mut replay).await.unwrap();
                Ok::<_, Infallible>(replay)
            },
        ))
        .with_fallback(service_fn(async || Ok::<_, Infallible>(Vec::<u8>::new())));
        assert_eq!(
            router
                .serve(ServiceInput::new(std::io::Cursor::new(wire.clone())))
                .await
                .unwrap(),
            wire
        );
        router
            .with_malformed_tls_policy(MalformedTlsPolicy::Reject)
            .with_reassembly_config(
                ClientHelloReassemblyConfig::default().with_max_handshake_size(message.len() - 1),
            )
            .serve(ServiceInput::new(std::io::Cursor::new(wire)))
            .await
            .unwrap_err();
    }

    #[tokio::test]
    async fn test_client_hello_peek_service() {
        let tls_service = service_fn(async |input: InputWithClientHello<_>| {
            let sni = input
                .client_hello
                .ext_server_name()
                .map(ToString::to_string);
            Ok::<_, Infallible>(sni)
        });
        let plain_service = service_fn(async || Ok::<_, Infallible>(Some("plain".to_owned())));

        let peek_tls_svc = PeekTlsClientHelloService::new(tls_service).with_fallback(plain_service);
        let response = peek_tls_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"".to_vec())))
            .await
            .unwrap();
        assert_eq!(Some("plain".to_owned()), response);

        let response = peek_tls_svc
            .serve(ServiceInput::new(std::io::Cursor::new(
                CH_ONE_ONE_ONE_ONE.to_vec(),
            )))
            .await
            .unwrap();
        assert_eq!(Some("one.one.one.one".to_owned()), response);

        let response = peek_tls_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"foo".to_vec())))
            .await
            .unwrap();
        assert_eq!(Some("plain".to_owned()), response);

        let response = peek_tls_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"foobar".to_vec())))
            .await
            .unwrap();
        assert_eq!(Some("plain".to_owned()), response);

        let response = peek_tls_svc
            .serve(ServiceInput::new(std::io::Cursor::new(
                TLS_BUT_NO_SNI.to_vec(),
            )))
            .await
            .unwrap();
        assert_eq!(None, response);
    }

    #[tokio::test]
    async fn test_peek_router_read_eof() {
        async fn tls_service_fn(
            InputWithClientHello {
                mut input,
                client_hello,
            }: InputWithClientHello<impl Io + Unpin>,
        ) -> Result<&'static str, BoxError> {
            let mut v = Vec::default();
            _ = input.read_to_end(&mut v).await?;
            assert_eq!(CH_ONE_ONE_ONE_ONE, v);
            assert!(client_hello.ext_server_name().is_some());
            assert_eq!(
                "one.one.one.one",
                client_hello.ext_server_name().unwrap().to_string()
            );
            Ok("ok")
        }
        let tls_service = service_fn(tls_service_fn);

        let peek_tls_svc =
            PeekTlsClientHelloService::new(tls_service).with_fallback(RejectService::<
                &'static str,
                RejectError,
            >::new(
                RejectError::default()
            ));

        let response = peek_tls_svc
            .serve(ServiceInput::new(std::io::Cursor::new(
                CH_ONE_ONE_ONE_ONE.to_vec(),
            )))
            .await
            .unwrap();
        assert_eq!("ok", response);
    }

    #[tokio::test]
    async fn test_peek_router_read_no_tls_eof() {
        let cases = ["", "foo", "abcd", "abcde", "foobarbazbananas"];
        for content in cases {
            async fn tls_service_fn() -> Result<Vec<u8>, BoxError> {
                Ok("tls".as_bytes().to_vec())
            }
            let tls_service = service_fn(tls_service_fn);

            async fn plain_service_fn(mut stream: impl Io + Unpin) -> Result<Vec<u8>, BoxError> {
                let mut v = Vec::default();
                _ = stream.read_to_end(&mut v).await?;
                Ok(v)
            }
            let plain_service = service_fn(plain_service_fn);

            let peek_tls_svc =
                PeekTlsClientHelloService::new(tls_service).with_fallback(plain_service);

            let response = peek_tls_svc
                .serve(ServiceInput::new(std::io::Cursor::new(
                    content.as_bytes().to_vec(),
                )))
                .await
                .unwrap();

            assert_eq!(content.as_bytes(), &response[..]);
        }
    }

    #[tokio::test]
    async fn test_partial_client_hello_does_not_prefix_zero_padding() {
        const SPLIT_AT: usize = 64;
        const PEEK_TIMEOUT: Duration = Duration::from_millis(10);

        let (mut client, server) = tokio::io::duplex(CH_ONE_ONE_ONE_ONE.len());
        let (prefix_sent_tx, prefix_sent_rx) = tokio::sync::oneshot::channel();
        let (continue_tx, continue_rx) = tokio::sync::oneshot::channel();
        let writer = tokio::spawn(async move {
            client
                .write_all(&CH_ONE_ONE_ONE_ONE[..SPLIT_AT])
                .await
                .unwrap();
            prefix_sent_tx.send(()).unwrap();
            continue_rx.await.unwrap();
            client
                .write_all(&CH_ONE_ONE_ONE_ONE[SPLIT_AT..])
                .await
                .unwrap();
        });
        prefix_sent_rx.await.unwrap();

        let (mut input, client_hello, status) = peek_client_hello_from_input_with_policies(
            server,
            PeekWaiter::new(Some(PEEK_TIMEOUT)).with_policy(PeekPolicy::FAIL_OPEN),
            MalformedTlsPolicy::Reject,
            ClientHelloReassemblyConfig::default(),
        )
        .await
        .unwrap();
        assert!(client_hello.is_none());
        assert_eq!(status.failure, Some(PeekStopReason::Timeout));
        continue_tx.send(()).unwrap();

        let mut bytes = Vec::new();
        input.read_to_end(&mut bytes).await.unwrap();
        writer.await.unwrap();

        assert_eq!(CH_ONE_ONE_ONE_ONE, bytes);
    }

    #[tokio::test]
    async fn fail_open_timeout_marks_fallback_for_partial_header_and_body() {
        for prefix_len in [1, 2, 64] {
            let (mut client, server) = tokio::io::duplex(CH_ONE_ONE_ONE_ONE.len());
            client
                .write_all(&CH_ONE_ONE_ONE_ONE[..prefix_len])
                .await
                .unwrap();
            let fallback = service_fn(
                move |mut input: TlsClientHelloPrefixedIo<
                    ServiceInput<tokio::io::DuplexStream>,
                >| async move {
                    assert_eq!(
                        input
                            .extensions()
                            .get_ref::<ClientHelloPeekStatus>()
                            .unwrap()
                            .failure,
                        Some(PeekStopReason::Timeout)
                    );
                    let mut replay = vec![0; prefix_len];
                    input.read_exact(&mut replay).await.unwrap();
                    assert_eq!(replay, CH_ONE_ONE_ONE_ONE[..prefix_len]);
                    Ok::<_, Infallible>(())
                },
            );
            PeekTlsClientHelloService::new(service_fn(async || {
                Err::<(), _>(std::io::Error::other(
                    "incomplete hello must not dispatch TLS",
                ))
            }))
            .with_peek_timeout(Duration::from_millis(10))
            .with_fallback(fallback)
            .serve(ServiceInput::new(server))
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn partial_client_hello_fail_closed_returns_timeout_without_fallback() {
        const SPLIT_AT: usize = 64;

        let fallback_calls = Arc::new(AtomicUsize::new(0));
        let fallback_calls_for_service = Arc::clone(&fallback_calls);
        let fallback = service_fn(move || {
            fallback_calls_for_service.fetch_add(1, Ordering::SeqCst);
            async { Ok::<_, Infallible>("fallback") }
        });
        let router =
            PeekTlsClientHelloService::new(service_fn(async || Ok::<_, Infallible>("tls")))
                .with_peek_timeout(Duration::from_millis(10))
                .with_peek_policy(PeekPolicy::FAIL_CLOSED)
                .with_malformed_tls_policy(MalformedTlsPolicy::Fallback)
                .with_fallback(fallback);
        let (mut client, server) = tokio::io::duplex(CH_ONE_ONE_ONE_ONE.len());
        client
            .write_all(&CH_ONE_ONE_ONE_ONE[..SPLIT_AT])
            .await
            .unwrap();

        let error = router.serve(ServiceInput::new(server)).await.unwrap_err();

        assert!(error_chain_has_peek_timeout(error.as_ref()));
        assert_eq!(0, fallback_calls.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn malformed_client_hello_is_rejected_under_both_timeout_policies() {
        let malformed = [
            0x16, 0x03, 0x03, 0x00, 0x06, 0x02, 0x00, 0x00, 0x02, 0xaa, 0xbb,
        ];

        for policy in [PeekPolicy::FAIL_OPEN, PeekPolicy::FAIL_CLOSED] {
            let router =
                PeekTlsClientHelloService::new(service_fn(async || Ok::<_, Infallible>("tls")))
                    .with_peek_timeout(Duration::from_millis(10))
                    .with_peek_policy(policy)
                    .with_malformed_tls_policy(MalformedTlsPolicy::Reject)
                    .with_fallback(service_fn(async || Ok::<_, Infallible>("fallback")));

            router
                .serve(ServiceInput::new(std::io::Cursor::new(malformed.to_vec())))
                .await
                .unwrap_err();
        }
    }

    fn error_chain_has_peek_timeout(error: &(dyn std::error::Error + 'static)) -> bool {
        error_chain(error).any(|error| {
            error.is::<PeekTimeoutError>()
                || error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::TimedOut)
        })
    }

    #[tokio::test]
    async fn test_peek_router_read_tls_no_sni_eof() {
        async fn tls_service_fn(
            InputWithClientHello {
                mut input,
                client_hello,
            }: InputWithClientHello<impl Io + Unpin>,
        ) -> Result<&'static str, BoxError> {
            let mut v = Vec::default();
            _ = input.read_to_end(&mut v).await?;
            assert_eq!(TLS_BUT_NO_SNI, v);
            assert!(client_hello.ext_server_name().is_none());
            Ok("ok")
        }
        let tls_service = service_fn(tls_service_fn);

        let peek_tls_svc =
            PeekTlsClientHelloService::new(tls_service).with_fallback(RejectService::<
                &'static str,
                RejectError,
            >::new(
                RejectError::default()
            ));

        let response = peek_tls_svc
            .serve(ServiceInput::new(std::io::Cursor::new(
                TLS_BUT_NO_SNI.to_vec(),
            )))
            .await
            .unwrap();
        assert_eq!("ok", response);
    }

    /// Bridge scenarios as seen by a transparent proxy: the egress is connected
    /// while ingress is peeked through TLS, then HTTP, then passthrough.
    #[cfg(feature = "http")]
    mod bridge {
        use std::time::Duration;

        use rama_core::{
            Layer as _,
            io::{
                BridgeIo,
                peek::{PeekAction, PeekEgressFirstByteLayer},
            },
        };
        use rama_net::http::server::HttpPeekRouter;
        use tokio::io::{DuplexStream, duplex};

        use super::*;

        const PEEK_TIMEOUT: Duration = Duration::from_millis(200);
        const HOUR: Duration = Duration::from_secs(3600);

        type Bridge = BridgeIo<ServiceInput<DuplexStream>, ServiceInput<DuplexStream>>;

        fn bridge() -> (DuplexStream, DuplexStream, Bridge) {
            let (client, ingress) = duplex(4096);
            let (server, egress) = duplex(4096);
            let bridge = BridgeIo(ServiceInput::new(ingress), ServiceInput::new(egress));
            (client, server, bridge)
        }

        fn stack(
            policy: PeekPolicy,
        ) -> impl Service<Bridge, Output = &'static str, Error = BoxError> {
            let http = HttpPeekRouter::new(service_fn(async || Ok::<_, Infallible>("http")))
                .with_peek_timeout(PEEK_TIMEOUT)
                .with_peek_policy(policy)
                .with_fallback(service_fn(async || Ok::<_, Infallible>("passthrough")));
            PeekEgressFirstByteLayer::new().into_layer(
                PeekTlsClientHelloService::new(service_fn(async || Ok::<_, Infallible>("tls")))
                    .with_peek_timeout(PEEK_TIMEOUT)
                    .with_peek_policy(policy)
                    .with_fallback(http),
            )
        }

        /// Sends `first`, then `rest` after `delay`, keeping both peers open.
        fn client_sends(
            mut client: DuplexStream,
            server: DuplexStream,
            first: &'static [u8],
            delay: Duration,
            rest: &'static [u8],
        ) -> tokio::task::JoinHandle<(DuplexStream, DuplexStream)> {
            tokio::spawn(async move {
                client.write_all(first).await.unwrap();
                tokio::time::sleep(delay).await;
                client.write_all(rest).await.unwrap();
                (client, server)
            })
        }

        async fn route(
            policy: PeekPolicy,
            first: &'static [u8],
            rest: &'static [u8],
        ) -> &'static str {
            let (client, server, input) = bridge();
            let _peers = client_sends(client, server, first, Duration::from_millis(500), rest);
            tokio::time::timeout(HOUR, stack(policy).serve(input))
                .await
                .unwrap()
                .unwrap()
        }

        #[tokio::test(start_paused = true)]
        async fn delayed_client_hello_skips_inspection_only_when_idle_timeouts_fall_back() {
            assert_eq!(
                "passthrough",
                route(PeekPolicy::FAIL_OPEN, b"", CH_ONE_ONE_ONE_ONE).await
            );

            // A server-first peer still ends the idle wait, via the egress probe.
            let policy = PeekPolicy::FAIL_OPEN.with_timeout_idle(PeekAction::Wait);
            assert_eq!("tls", route(policy, b"", CH_ONE_ONE_ONE_ONE).await);
        }

        #[tokio::test(start_paused = true)]
        async fn slow_client_hello_tail_skips_inspection_only_when_partial_timeouts_fall_back() {
            let (head, tail) = CH_ONE_ONE_ONE_ONE.split_at(64);
            assert_eq!(
                "passthrough",
                route(PeekPolicy::FAIL_OPEN, head, tail).await
            );

            let policy = PeekPolicy::FAIL_OPEN.with_timeout_partial(PeekAction::Wait);
            assert_eq!("tls", route(policy, head, tail).await);
        }

        #[tokio::test(start_paused = true)]
        async fn slow_client_hello_tail_fails_closed_instead_of_bypassing() {
            let (head, tail) = CH_ONE_ONE_ONE_ONE.split_at(64);
            let (client, server, input) = bridge();
            let _peers = client_sends(client, server, head, Duration::from_millis(500), tail);
            let policy = PeekPolicy::FAIL_OPEN.with_timeout_partial(PeekAction::Fail);
            let error = stack(policy).serve(input).await.unwrap_err();
            assert!(error_chain_has_peek_timeout(error.as_ref()));
        }

        #[tokio::test(start_paused = true)]
        async fn server_first_protocol_falls_back_before_the_peek_timeout() {
            let (_client, mut server, input) = bridge();
            server
                .write_all(b"220 mail.example.com ESMTP ready\r\n")
                .await
                .unwrap();

            let start = tokio::time::Instant::now();
            let policy = PeekPolicy::FAIL_CLOSED;
            let label = stack(policy).serve(input).await.unwrap();
            assert_eq!("passthrough", label);
            assert!(start.elapsed() < PEEK_TIMEOUT);
        }

        #[tokio::test(start_paused = true)]
        async fn http_client_is_still_detected_with_the_egress_probe() {
            let policy = PeekPolicy::FAIL_CLOSED;
            assert_eq!(
                "http",
                route(policy, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", b"").await
            );
        }
    }
}
