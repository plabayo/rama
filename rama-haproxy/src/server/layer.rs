use crate::protocol::{HeaderResult, PartialResult, v1, v2};
use rama_core::{
    Layer, Service,
    bytes::Bytes,
    error::{BoxError, ErrorContext, ErrorExt, extra::OpaqueError},
    extensions::{Extension, ExtensionsRef},
    io::{HeapReader, Io, PrefixedIo},
    telemetry::tracing,
};
use rama_net::address::Domain;
use rama_net::forwarded::{Forwarded, ForwardedElement};
use rama_utils::macros::generate_set_and_with;
use std::net::SocketAddr;
use tokio::io::AsyncReadExt;

/// Absolute upper bound on a single PROXY header: the v2 fixed header (16 bytes)
/// plus the maximum advertised payload length (`u16::MAX`).
///
/// See vendored spec `rama-haproxy/specifications/proxy-protocol.txt`, section 2.2.
const MAX_HEADER_LENGTH: usize = 16 + u16::MAX as usize;

/// Initial buffer size used for reading the PROXY header. Sized to comfortably
/// hold any v1 header (≤ 107 bytes) and a typical v2 header without TLVs in
/// a single allocation.
const INITIAL_BUFFER_CAPACITY: usize = 128;

/// Configurable strictness toggles for the PROXY protocol server.
///
/// The defaults follow rama's proxy-first philosophy: be lenient with what is
/// accepted from the wire (the protocol is regularly served by upstream
/// software that diverges slightly from the spec) while still enforcing the
/// security-critical invariants required by the specification (in particular,
/// section 2.2.5: a present `PP2_TYPE_CRC32C` TLV "MUST be verified").
///
/// All knobs are opt-in towards stricter behaviour. [`Self::strict`] turns on
/// every *spec-mandated* check; [`Self::reject_local_command`] is intentionally
/// left off there because the spec explicitly permits the `LOCAL` command —
/// flip it on per-deployment if you want to reject it.
#[derive(Debug, Clone, Copy)]
pub struct HaProxyStrictness {
    /// Maximum number of bytes accepted for a single PROXY header.
    /// Default: `16 + u16::MAX` — the largest spec-legal v2 header.
    pub max_header_length: usize,
    /// When `true` and a `PP2_TYPE_CRC32C` TLV is present, the header is
    /// rejected if the CRC32C value does not match the recomputed value.
    /// Default: `true` (spec MUST in section 2.2.5).
    pub verify_crc32c_when_present: bool,
    /// When `true`, reject any v2 header that does not carry a CRC32C TLV.
    /// Default: `false`.
    pub require_crc32c: bool,
    /// When `true`, reject v1 `UNKNOWN` and v2 `AF_UNSPEC` headers.
    /// Default: `false`.
    pub reject_unknown_address_family: bool,
    /// When `true`, reject v2 headers using the `LOCAL` command.
    /// The spec mandates ignoring address info in `LOCAL` connections, which
    /// rama always does — this flag goes one step further and treats a
    /// `LOCAL` frame as an error rather than passing the connection through.
    /// Default: `false`.
    pub reject_local_command: bool,
    /// When `true`, a v2 header is rejected if its TLV area cannot be parsed
    /// in full (truncated TLV, advertised length beyond available bytes).
    /// Default: `false`.
    pub fail_on_malformed_tlv: bool,
}

impl HaProxyStrictness {
    /// The default strictness configuration as a `const`, suitable for use
    /// from other `const fn` constructors.
    const DEFAULT: Self = Self {
        max_header_length: MAX_HEADER_LENGTH,
        verify_crc32c_when_present: true,
        require_crc32c: false,
        reject_unknown_address_family: false,
        reject_local_command: false,
        fail_on_malformed_tlv: false,
    };
}

impl Default for HaProxyStrictness {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl HaProxyStrictness {
    /// A maximally lenient configuration — nothing is rejected beyond what the
    /// parser itself can already not understand (invalid version byte etc.).
    /// CRC32C verification is also disabled.
    #[must_use]
    pub const fn lenient() -> Self {
        Self {
            max_header_length: MAX_HEADER_LENGTH,
            verify_crc32c_when_present: false,
            require_crc32c: false,
            reject_unknown_address_family: false,
            reject_local_command: false,
            fail_on_malformed_tlv: false,
        }
    }

    /// A strict configuration suitable for trusted-frontline gateways that
    /// want to enforce every spec-mandated check.
    ///
    /// Note: [`Self::reject_local_command`] is left **off** here because the
    /// spec explicitly permits the `LOCAL` command (the receiver is required
    /// to accept the connection and ignore the address info, which rama
    /// always does). Enable it separately if your deployment wants to refuse
    /// `LOCAL` frames.
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            max_header_length: MAX_HEADER_LENGTH,
            verify_crc32c_when_present: true,
            require_crc32c: true,
            reject_unknown_address_family: true,
            reject_local_command: false,
            fail_on_malformed_tlv: true,
        }
    }
}

/// A single TLV (Type-Length-Value) entry as carried in a PROXY protocol v2
/// header.
///
/// `kind` is a typed [`v2::Type`] — unknown wire kinds are preserved as
/// `Type::Unknown(u8)` so vendor-specific TLVs (e.g. AWS 0xEA, Azure 0xEE,
/// GCP) are still inspectable.
#[derive(Debug, Clone)]
pub struct HaProxyTlv {
    /// The TLV kind.
    pub kind: v2::Type,
    /// The TLV value.
    pub value: Bytes,
}

/// A snapshot of the PROXY protocol v2 TLVs attached to the incoming
/// connection, exposed as an extension on the IO stream so downstream
/// services can inspect them.
///
/// Only present for v2 headers — v1 has no TLV concept. Typical PROXY v2
/// senders attach 0–4 TLVs (CRC32C, NOOP padding, AUTHORITY/SNI, UNIQUE_ID,
/// occasionally a vendor TLV); this type keeps them in iteration order.
#[derive(Debug, Clone, Default, Extension)]
#[extension(tags(proxy))]
pub struct HaProxyTlvs {
    entries: Vec<HaProxyTlv>,
}

impl HaProxyTlvs {
    /// All TLV entries in iteration order.
    #[must_use]
    pub fn entries(&self) -> &[HaProxyTlv] {
        &self.entries
    }

    /// Returns the value of the first TLV with the given kind, if any.
    #[must_use]
    pub fn get(&self, kind: v2::Type) -> Option<&Bytes> {
        self.entries
            .iter()
            .find(|tlv| tlv.kind == kind)
            .map(|tlv| &tlv.value)
    }

    /// Returns the value of the `PP2_TYPE_AUTHORITY` TLV (host name carried
    /// through the proxy, e.g. SNI) parsed as a [`Domain`], when present and
    /// well-formed.
    ///
    /// Per PROXY protocol spec section 2.2.5, this TLV "is typically passed
    /// by the client to indicate the original host it was trying to connect
    /// to" — i.e. a hostname. Returning a typed [`Domain`] both validates
    /// the value and surfaces it in a form ready to be plugged into rama's
    /// addressing/DNS plumbing.
    ///
    /// Use [`Self::get`] with `v2::Type::Authority` if you need the raw
    /// bytes (e.g. to round-trip a non-domain value some non-spec sender
    /// might have placed there).
    #[must_use]
    pub fn authority(&self) -> Option<Domain> {
        self.get(v2::Type::Authority)
            .and_then(|v| Domain::try_from(v.as_ref()).ok())
    }

    /// Returns the value of the `PP2_TYPE_UNIQUE_ID` TLV, when present.
    #[must_use]
    pub fn unique_id(&self) -> Option<&Bytes> {
        self.get(v2::Type::UniqueId)
    }
}

/// The PROXY protocol command extracted from a v2 header, exposed as an
/// extension on the IO stream. Useful for services that want to distinguish
/// `LOCAL` connections (e.g. upstream health checks) from real proxied flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Extension)]
#[extension(tags(proxy))]
pub enum HaProxyCommand {
    /// `LOCAL` — the upstream proxy initiated this connection on its own
    /// behalf. The spec requires the receiver to ignore the address info,
    /// which rama does.
    Local,
    /// `PROXY` — the connection is being proxied for a remote client.
    Proxy,
}

impl From<v2::Command> for HaProxyCommand {
    fn from(c: v2::Command) -> Self {
        match c {
            v2::Command::Local => Self::Local,
            v2::Command::Proxy => Self::Proxy,
        }
    }
}

/// Layer to decode the HaProxy Protocol
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct HaProxyLayer {
    peek: bool,
    strictness: HaProxyStrictness,
}

impl HaProxyLayer {
    /// Create a new [`HaProxyLayer`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            peek: false,
            strictness: HaProxyStrictness::DEFAULT,
        }
    }

    generate_set_and_with!(
        /// Instruct [`HaProxyLayer`] to peek prior to comitting to the `HaProxy` protocol.
        ///
        /// Doing so makes it possible to support traffic with or without the use of that data.
        /// This can be useful to run services locally (not behind a loadbalancer) as well as in the
        /// the cloud (production, behind a loadbalancer).
        pub fn peek(mut self, value: bool) -> Self {
            self.peek = value;
            self
        }
    );

    generate_set_and_with!(
        /// Override the strictness configuration applied to incoming PROXY headers.
        pub fn strictness(mut self, value: HaProxyStrictness) -> Self {
            self.strictness = value;
            self
        }
    );
}

impl<S> Layer<S> for HaProxyLayer {
    type Service = HaProxyService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HaProxyService {
            inner,
            peek: self.peek,
            strictness: self.strictness,
        }
    }
}

/// Service to decode the HaProxy Protocol
///
/// This service will decode the HaProxy Protocol header and pass the decoded
/// information to the inner service.
#[derive(Debug, Clone)]
pub struct HaProxyService<S> {
    inner: S,
    peek: bool,
    strictness: HaProxyStrictness,
}

impl<S> HaProxyService<S> {
    /// Create a new [`HaProxyService`] with the given inner service.
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            peek: false,
            strictness: HaProxyStrictness::DEFAULT,
        }
    }

    generate_set_and_with!(
        /// Instruct [`HaProxyService`] to peek prior to comitting to the `HaProxy` protocol.
        ///
        /// Doing so makes it possible to support traffic with or without the use of that data.
        /// This can be useful to run services locally (not behind a loadbalancer) as well as in the
        /// the cloud (production, behind a loadbalancer).
        pub fn peek(mut self, value: bool) -> Self {
            self.peek = value;
            self
        }
    );

    generate_set_and_with!(
        /// Override the strictness configuration applied to incoming PROXY headers.
        pub fn strictness(mut self, value: HaProxyStrictness) -> Self {
            self.strictness = value;
            self
        }
    );
}

/// Outcome of the peek phase: whether the upstream traffic looks like a
/// PROXY header at all, and if so, which version.
enum PeekOutcome {
    /// Definitely a v1 header; bytes already consumed are in the buffer.
    V1,
    /// Definitely a v2 header; bytes already consumed are in the buffer.
    V2,
    /// Not a PROXY header. The buffered bytes should be replayed to the inner
    /// service as-is.
    NotProxy,
}

/// Performs the peek-mode disambiguation by reading enough bytes to decide
/// whether the upstream traffic is v1, v2, or neither.
///
/// The previous implementation issued a single `read()` and compared the full
/// 12-byte buffer to the v2 signature — but `read()` can return fewer bytes,
/// causing legitimate fragmented PROXY headers to be misclassified as plain
/// traffic and silently corrupted. This version reads incrementally until it
/// can make a definitive decision.
async fn peek_disambiguate<IO: tokio::io::AsyncRead + Unpin>(
    stream: &mut IO,
    buffer: &mut Vec<u8>,
) -> Result<PeekOutcome, BoxError> {
    // PROXY v1 prefix is "PROXY" (5 bytes); v2 prefix is 12 bytes starting
    // with 0x0D 0x0A. The two prefixes differ at byte 0, so a single byte is
    // enough to pick a candidate.
    let v1_prefix = v1::PROTOCOL_PREFIX.as_bytes();
    let v2_prefix = v2::PROTOCOL_PREFIX;

    // Read at least one byte.
    let mut scratch = [0u8; 16];
    while buffer.is_empty() {
        let n = stream
            .read(&mut scratch)
            .await
            .context("haproxy peek: initial read")?;
        if n == 0 {
            // EOF before any bytes: nothing to commit to either protocol.
            return Ok(PeekOutcome::NotProxy);
        }
        buffer.extend_from_slice(&scratch[..n]);
    }

    // First byte decides the candidate protocol.
    let candidate_v1 = buffer[0] == v1_prefix[0];
    let candidate_v2 = buffer[0] == v2_prefix[0];
    if !candidate_v1 && !candidate_v2 {
        return Ok(PeekOutcome::NotProxy);
    }

    let target_len = if candidate_v1 {
        v1_prefix.len()
    } else {
        v2_prefix.len()
    };

    while buffer.len() < target_len {
        let n = stream
            .read(&mut scratch)
            .await
            .context("haproxy peek: prefix read")?;
        if n == 0 {
            // EOF before we could disambiguate: assume not PROXY and let the
            // inner service deal with the bytes.
            return Ok(PeekOutcome::NotProxy);
        }
        buffer.extend_from_slice(&scratch[..n]);

        // Early bail: if the bytes seen so far already diverge from the
        // candidate prefix, this is not a PROXY header.
        let expected = if candidate_v1 { v1_prefix } else { v2_prefix };
        let cmp_len = buffer.len().min(expected.len());
        if buffer[..cmp_len] != expected[..cmp_len] {
            return Ok(PeekOutcome::NotProxy);
        }
    }

    if candidate_v1 && &buffer[..v1_prefix.len()] == v1_prefix {
        Ok(PeekOutcome::V1)
    } else if candidate_v2 && &buffer[..v2_prefix.len()] == v2_prefix {
        Ok(PeekOutcome::V2)
    } else {
        Ok(PeekOutcome::NotProxy)
    }
}

impl<S, IO> Service<IO> for HaProxyService<S>
where
    S: Service<PrefixedIo<HeapReader, IO>, Error: Into<BoxError>>,
    IO: Io + Unpin + ExtensionsRef,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, mut stream: IO) -> Result<Self::Output, Self::Error> {
        let max_header_length = self
            .strictness
            .max_header_length
            .min(MAX_HEADER_LENGTH)
            .max(v1::PROTOCOL_PREFIX.len());

        let mut buffer: Vec<u8> = Vec::with_capacity(INITIAL_BUFFER_CAPACITY);

        if self.peek {
            tracing::trace!("haproxy protocol peeking enabled: start detection");
            match peek_disambiguate(&mut stream, &mut buffer).await? {
                PeekOutcome::V1 => {
                    tracing::trace!(
                        "haproxy protocol peeked: v1 detected: continue with haproxy handling"
                    );
                }
                PeekOutcome::V2 => {
                    tracing::trace!(
                        "haproxy protocol peeked: v2 detected: continue with haproxy handling"
                    );
                }
                PeekOutcome::NotProxy => {
                    tracing::trace!(
                        "no haproxy protocol detected... delegating immediately to inner..."
                    );
                    let mem = HeapReader::new(buffer);
                    let stream = PrefixedIo::new(mem, stream);
                    return self.inner.serve(stream).await.into_box_error();
                }
            }
        } else {
            tracing::trace!("haproxy protocol enforced: skip peeking");
        }

        let header = loop {
            // Always attempt to parse first — if the peek phase already left
            // us with a complete header (small v1 case) this avoids a needless
            // extra read.
            let header = HeaderResult::parse(&buffer);
            if header.is_complete() {
                break header;
            }

            if buffer.len() >= max_header_length {
                return Err(format!(
                    "haproxy: buffer exhausted (read {} bytes, configured max {max_header_length}) before parsing completed",
                    buffer.len()
                )
                .into());
            }

            // Grow the buffer geometrically up to the configured max.
            let old_len = buffer.len();
            let mut next_cap = old_len.saturating_mul(2).max(INITIAL_BUFFER_CAPACITY);
            if next_cap > max_header_length {
                next_cap = max_header_length;
            }
            buffer.resize(next_cap, 0);

            let n = stream.read(&mut buffer[old_len..]).await?;
            buffer.truncate(old_len + n);

            if n == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)
                    .context("HaProxy header incomplete"));
            }

            tracing::debug!("Incomplete header. Read {} bytes so far.", buffer.len());
        };

        let consumed = match header {
            HeaderResult::V1(Ok(ref header)) => self.apply_v1(&stream, header)?,
            HeaderResult::V2(Ok(ref header)) => self.apply_v2(&stream, header)?,
            HeaderResult::V1(Err(error)) => return Err(error.into()),
            HeaderResult::V2(Err(error)) => return Err(error.into()),
        };

        // put back the data that is read too much
        let mem: HeapReader = buffer[consumed..].into();
        let stream = PrefixedIo::new(mem, stream);

        // read the rest of the data
        self.inner.serve(stream).await.into_box_error()
    }
}

impl<S> HaProxyService<S> {
    fn apply_v1<IO: ExtensionsRef>(
        &self,
        stream: &IO,
        header: &v1::Header<'_>,
    ) -> Result<usize, BoxError> {
        if self.strictness.reject_unknown_address_family
            && matches!(header.addresses, v1::Addresses::Unknown)
        {
            return Err(OpaqueError::from_static_str(
                "haproxy v1: UNKNOWN address family rejected by strictness configuration",
            )
            .into_box_error());
        }

        match header.addresses {
            v1::Addresses::Tcp4(info) => {
                let peer_addr: SocketAddr = (info.source_address, info.source_port).into();
                insert_forwarded(stream, peer_addr);
            }
            v1::Addresses::Tcp6(info) => {
                let peer_addr: SocketAddr = (info.source_address, info.source_port).into();
                insert_forwarded(stream, peer_addr);
            }
            v1::Addresses::Unknown => (),
        }

        Ok(header.header.len())
    }

    fn apply_v2<IO: ExtensionsRef>(
        &self,
        stream: &IO,
        header: &v2::Header<'_>,
    ) -> Result<usize, BoxError> {
        if self.strictness.reject_unknown_address_family
            && matches!(header.addresses, v2::Addresses::Unspecified)
        {
            return Err(OpaqueError::from_static_str(
                "haproxy v2: AF_UNSPEC rejected by strictness configuration",
            )
            .into_box_error());
        }

        if self.strictness.reject_local_command && header.command == v2::Command::Local {
            return Err(OpaqueError::from_static_str(
                "haproxy v2: LOCAL command rejected by strictness configuration",
            )
            .into_box_error());
        }

        // CRC32C verification — section 2.2.5 of the spec mandates that a
        // present `PP2_TYPE_CRC32C` value MUST be verified.
        //
        // Note: `MalformedBeforeCrc` means we couldn't decide whether a CRC
        // TLV exists at all, so we must not treat it as "CRC invalid". That
        // case is handled by `fail_on_malformed_tlv` further below — keeping
        // the two concerns orthogonal.
        let crc_status = header.verify_crc32c();
        if self.strictness.verify_crc32c_when_present && crc_status == v2::Crc32cStatus::Invalid {
            return Err(
                OpaqueError::from_static_str("haproxy v2: CRC32C TLV present but invalid")
                    .into_box_error(),
            );
        }
        if self.strictness.require_crc32c
            && !matches!(
                crc_status,
                v2::Crc32cStatus::Valid | v2::Crc32cStatus::Invalid
            )
        {
            return Err(
                OpaqueError::from_static_str("haproxy v2: required CRC32C TLV missing")
                    .into_box_error(),
            );
        }

        // Collect TLVs into an extension before consuming them.
        let consumed_len = header.header.len();
        let mut tlv_entries: Vec<HaProxyTlv> = Vec::new();
        let mut tlv_malformed = false;
        for tlv in header.tlvs() {
            match tlv {
                Ok(tlv) => tlv_entries.push(HaProxyTlv {
                    kind: tlv.kind,
                    value: Bytes::copy_from_slice(tlv.value.as_ref()),
                }),
                Err(e) => {
                    tracing::debug!(error = %e, "haproxy v2: malformed TLV in header");
                    tlv_malformed = true;
                    break;
                }
            }
        }

        if self.strictness.fail_on_malformed_tlv && tlv_malformed {
            return Err(OpaqueError::from_static_str(
                "haproxy v2: malformed TLV area rejected by strictness configuration",
            )
            .into_box_error());
        }

        // Spec section 2.2: the receiver MUST ignore any address information
        // when the command is LOCAL. We honour this by not injecting a
        // `Forwarded` element at all in that case.
        if header.command == v2::Command::Proxy {
            match header.addresses {
                v2::Addresses::IPv4(info) => {
                    let peer_addr: SocketAddr = (info.source_address, info.source_port).into();
                    insert_forwarded(stream, peer_addr);
                }
                v2::Addresses::IPv6(info) => {
                    let peer_addr: SocketAddr = (info.source_address, info.source_port).into();
                    insert_forwarded(stream, peer_addr);
                }
                v2::Addresses::Unix(_) | v2::Addresses::Unspecified => (),
            }
        }

        // Expose command + TLVs to downstream services.
        stream
            .extensions()
            .insert(HaProxyCommand::from(header.command));
        if !tlv_entries.is_empty() {
            stream.extensions().insert(HaProxyTlvs {
                entries: tlv_entries,
            });
        }

        Ok(consumed_len)
    }
}

fn insert_forwarded<IO: ExtensionsRef>(stream: &IO, peer_addr: SocketAddr) {
    let el = ForwardedElement::new_forwarded_for(peer_addr);
    let forwarded = if let Some(mut forwarded) = stream.extensions().get_ref::<Forwarded>().cloned()
    {
        forwarded.append(el);
        forwarded
    } else {
        Forwarded::new(el)
    };
    stream.extensions().insert(forwarded);
}

#[cfg(test)]
mod test {
    use rama_core::{ServiceInput, service::service_fn};

    use super::*;

    async fn echo(mut stream: impl Io + Unpin) -> Result<Vec<u8>, BoxError> {
        let mut v = Vec::default();
        _ = stream.read_to_end(&mut v).await?;
        Ok(v)
    }

    #[tokio::test]
    async fn test_haproxy_peek_direct() {
        let proxy_svc = HaProxyService::new(service_fn(echo)).with_peek(true);

        let request = ServiceInput::new(std::io::Cursor::new(b"foo".to_vec()));
        let response = proxy_svc.serve(request).await.unwrap();

        assert_eq!("foo", String::from_utf8(response).unwrap());

        let request = ServiceInput::new(std::io::Cursor::new(
            b"Hello, this is a test to check if it works.".to_vec(),
        ));
        let response = proxy_svc.serve(request).await.unwrap();

        assert_eq!(
            "Hello, this is a test to check if it works.",
            String::from_utf8(response).unwrap()
        );
    }

    #[tokio::test]
    async fn test_haproxy_peek_with_haproxy_v1() {
        let proxy_svc = HaProxyService::new(service_fn(echo));

        let request = ServiceInput::new(std::io::Cursor::new(
            b"PROXY TCP4 192.0.2.1 198.51.100.1 12345 80\r\n".to_vec(),
        ));
        let response = proxy_svc.serve(request).await.unwrap();

        assert_eq!("", String::from_utf8(response).unwrap());

        let request = ServiceInput::new(std::io::Cursor::new(
            b"PROXY TCP4 192.0.2.1 198.51.100.1 12345 80\r\nfoo".to_vec(),
        ));
        let response = proxy_svc.serve(request).await.unwrap();

        assert_eq!("foo", String::from_utf8(response).unwrap());

        let proxy_svc = proxy_svc.with_peek(true);

        let request = ServiceInput::new(std::io::Cursor::new(
            b"PROXY TCP4 192.0.2.1 198.51.100.1 12345 80\r\n".to_vec(),
        ));
        let response = proxy_svc.serve(request).await.unwrap();

        assert_eq!("", String::from_utf8(response).unwrap());

        let request = ServiceInput::new(std::io::Cursor::new(
            b"PROXY TCP4 192.0.2.1 198.51.100.1 12345 80\r\nfoo".to_vec(),
        ));
        let response = proxy_svc.serve(request).await.unwrap();

        assert_eq!("foo", String::from_utf8(response).unwrap());
    }

    #[tokio::test]
    async fn test_haproxy_peek_with_haproxy_v2() {
        const DATA: &[u8] = &[
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54,
            0x0A, // Signature
            0x21, // Version (0x2) + Command (PROXY = 0x1)
            0x11, // Family (IPv4 = 0x1) + Protocol (TCP = 0x1)
            0x00, 0x0C, // Address length = 12 bytes
            // Source IP: 192.0.2.1
            0xC0, 0x00, 0x02, 0x01, // Dest IP: 198.51.100.1
            0xC6, 0x33, 0x64, 0x01, // Source Port: 12345 (0x3039)
            0x30, 0x39, // Dest Port: 443 (0x01BB)
            0x01, 0xBB, // foo data
            0x66, 0x6F, 0x6F,
        ];

        let proxy_svc = HaProxyService::new(service_fn(echo));
        let request = ServiceInput::new(std::io::Cursor::new(DATA.to_vec()));
        let response = proxy_svc.serve(request).await.unwrap();
        assert_eq!("foo", String::from_utf8(response).unwrap());

        let proxy_svc = proxy_svc.with_peek(true);
        let request = ServiceInput::new(std::io::Cursor::new(DATA.to_vec()));
        let response = proxy_svc.serve(request).await.unwrap();
        assert_eq!("foo", String::from_utf8(response).unwrap());
    }

    /// Regression test for the peek-mode short-read bug: the v2 prefix and
    /// payload arrive in multiple `read()` calls. Previously the peek logic
    /// compared a partially-filled buffer to the full 12-byte v2 signature,
    /// failed to match, and silently forwarded the bytes to the inner service.
    #[tokio::test]
    async fn test_haproxy_peek_v2_fragmented() {
        const DATA: &[u8] = &[
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, // sig
            0x21, 0x11, 0x00, 0x0C, 0xC0, 0x00, 0x02, 0x01, 0xC6, 0x33, 0x64, 0x01, 0x30, 0x39,
            0x01, 0xBB, // header
            b'b', b'a', b'r', // payload
        ];

        struct Chunked {
            chunks: std::collections::VecDeque<Vec<u8>>,
        }
        impl tokio::io::AsyncRead for Chunked {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                if let Some(chunk) = self.chunks.pop_front() {
                    let n = chunk.len().min(buf.remaining());
                    buf.put_slice(&chunk[..n]);
                    if n < chunk.len() {
                        self.chunks.push_front(chunk[n..].to_vec());
                    }
                }
                std::task::Poll::Ready(Ok(()))
            }
        }
        impl tokio::io::AsyncWrite for Chunked {
            fn poll_write(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                std::task::Poll::Ready(Ok(buf.len()))
            }
            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
        }

        let chunked = Chunked {
            chunks: vec![
                DATA[..4].to_vec(),
                DATA[4..12].to_vec(),
                DATA[12..].to_vec(),
            ]
            .into(),
        };

        let input = ServiceInput::new(chunked);
        let proxy_svc = HaProxyService::new(service_fn(echo)).with_peek(true);
        let response = proxy_svc.serve(input).await.unwrap();
        assert_eq!("bar", String::from_utf8(response).unwrap());
    }

    /// Strict mode: `LOCAL` command is rejected.
    #[tokio::test]
    async fn test_haproxy_v2_local_command_strict_reject() {
        const DATA: &[u8] = &[
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54,
            0x0A, // Signature
            0x20, // Version (0x2) + Command (LOCAL = 0x0)
            0x00, // AF_UNSPEC + UNSPEC
            0x00, 0x00, // length 0
        ];
        let strictness = HaProxyStrictness {
            reject_local_command: true,
            ..HaProxyStrictness::default()
        };
        let proxy_svc = HaProxyService::new(service_fn(echo)).with_strictness(strictness);
        let request = ServiceInput::new(std::io::Cursor::new(DATA.to_vec()));
        proxy_svc.serve(request).await.unwrap_err();
    }

    /// Default (lenient) mode: a `LOCAL` command must NOT inject a
    /// `Forwarded` element, even when address bytes are technically present
    /// — spec section 2.2 requires the receiver to ignore them.
    #[tokio::test]
    async fn test_haproxy_v2_local_command_ignores_addresses() {
        // LOCAL command, but with IPv4 address info present that an attacker
        // could try to spoof a Forwarded for. The spec says ignore it.
        const DATA: &[u8] = &[
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54,
            0x0A, // Signature
            0x20, // Version (0x2) + Command (LOCAL = 0x0)
            0x11, // IPv4 + TCP
            0x00, 0x0C, // length 12
            0xDE, 0xAD, 0xBE, 0xEF, // src "ip" (must be ignored)
            0xCA, 0xFE, 0xBA, 0xBE, // dst "ip"
            0x30, 0x39, 0x01, 0xBB, // ports
            b'h', b'i',
        ];

        let cmd = capture_command(DATA).await;
        let fwd = capture_forwarded(DATA).await;
        assert_eq!(cmd, Some(HaProxyCommand::Local));
        assert!(
            fwd.is_none(),
            "LOCAL command must not inject Forwarded element"
        );
    }

    /// PROXY command with IPv4 addresses DOES inject the Forwarded element.
    #[tokio::test]
    async fn test_haproxy_v2_proxy_command_injects_forwarded() {
        const DATA: &[u8] = &[
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54,
            0x0A, // Signature
            0x21, // Version + PROXY
            0x11, // IPv4 + TCP
            0x00, 0x0C, // length 12
            0xC0, 0x00, 0x02, 0x01, // 192.0.2.1
            0xC6, 0x33, 0x64, 0x01, // 198.51.100.1
            0x30, 0x39, 0x01, 0xBB, // ports
        ];

        let cmd = capture_command(DATA).await;
        let fwd = capture_forwarded(DATA).await;
        assert_eq!(cmd, Some(HaProxyCommand::Proxy));
        assert!(fwd.is_some());
    }

    /// Helper: run a haproxy service against `data` and return the
    /// `Forwarded` extension seen by the inner service.
    async fn capture_forwarded(data: &[u8]) -> Option<Forwarded> {
        let captured: std::sync::Arc<parking_lot::Mutex<Option<Forwarded>>> =
            std::sync::Arc::new(parking_lot::Mutex::new(None));
        let captured_clone = captured.clone();
        let inner = service_fn(move |stream| {
            let captured = captured_clone.clone();
            async move {
                let fwd = <_ as ExtensionsRef>::extensions(&stream)
                    .get_ref::<Forwarded>()
                    .cloned();
                *captured.lock() = fwd;
                Ok::<_, BoxError>(())
            }
        });

        let proxy_svc = HaProxyService::new(inner);
        let request = ServiceInput::new(std::io::Cursor::new(data.to_vec()));
        proxy_svc.serve(request).await.unwrap();
        let guard = captured.lock();
        guard.clone()
    }

    /// Helper: run a haproxy service against `data` and return the
    /// `HaProxyCommand` extension seen by the inner service.
    async fn capture_command(data: &[u8]) -> Option<HaProxyCommand> {
        let captured: std::sync::Arc<parking_lot::Mutex<Option<HaProxyCommand>>> =
            std::sync::Arc::new(parking_lot::Mutex::new(None));
        let captured_clone = captured.clone();
        let inner = service_fn(move |stream| {
            let captured = captured_clone.clone();
            async move {
                let cmd = <_ as ExtensionsRef>::extensions(&stream)
                    .get_ref::<HaProxyCommand>()
                    .copied();
                *captured.lock() = cmd;
                Ok::<_, BoxError>(())
            }
        });

        let proxy_svc = HaProxyService::new(inner);
        let request = ServiceInput::new(std::io::Cursor::new(data.to_vec()));
        proxy_svc.serve(request).await.unwrap();
        let guard = captured.lock();
        *guard
    }

    /// CRC32C TLV with an invalid value must be rejected by default.
    #[tokio::test]
    async fn test_haproxy_v2_crc32c_invalid_is_rejected() {
        // Build a v2 header that carries a CRC32C TLV with bogus contents.
        let mut header = Vec::from(v2::PROTOCOL_PREFIX);
        header.push(0x21); // version + proxy
        header.push(0x11); // ipv4 + tcp
        header.extend([0x00, 0x13]); // length = 12 + 7 (TLV)
        header.extend([192, 0, 2, 1]);
        header.extend([198, 51, 100, 1]);
        header.extend([0x30, 0x39]);
        header.extend([0x01, 0xBB]);
        // CRC32C TLV: kind=0x03, length=4, value=00000000 (wrong)
        header.extend([0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00]);

        let proxy_svc = HaProxyService::new(service_fn(echo));
        let request = ServiceInput::new(std::io::Cursor::new(header));
        proxy_svc.serve(request).await.unwrap_err();
    }

    /// CRC32C TLV with a correct value passes verification.
    #[tokio::test]
    async fn test_haproxy_v2_crc32c_valid_is_accepted() {
        let mut header = Vec::from(v2::PROTOCOL_PREFIX);
        header.push(0x21);
        header.push(0x11);
        header.extend([0x00, 0x13]); // 12 + 7
        header.extend([192, 0, 2, 1]);
        header.extend([198, 51, 100, 1]);
        header.extend([0x30, 0x39]);
        header.extend([0x01, 0xBB]);
        // CRC32C placeholder
        header.extend([0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00]);
        // Compute the expected CRC over the header with the CRC value zeroed
        // (already the case since we wrote zeros) and patch it in.
        let crc = {
            let mut h = crate::protocol::v2::Crc32cHasher::new();
            h.update(&header);
            h.finalize()
        };
        let crc_value_offset = header.len() - 4;
        header[crc_value_offset..crc_value_offset + 4].copy_from_slice(&crc.to_be_bytes());

        // Append payload data after the header.
        header.extend(b"ok");

        let proxy_svc = HaProxyService::new(service_fn(echo));
        let request = ServiceInput::new(std::io::Cursor::new(header));
        let response = proxy_svc.serve(request).await.unwrap();
        assert_eq!("ok", String::from_utf8(response).unwrap());
    }

    /// Strict mode demands a CRC32C TLV: a header without one is rejected.
    #[tokio::test]
    async fn test_haproxy_v2_require_crc32c() {
        const DATA: &[u8] = &[
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54,
            0x0A, // Signature
            0x21, 0x11, 0x00, 0x0C, // header
            0xC0, 0x00, 0x02, 0x01, 0xC6, 0x33, 0x64, 0x01, 0x30, 0x39, 0x01, 0xBB,
        ];
        let strictness = HaProxyStrictness {
            require_crc32c: true,
            ..HaProxyStrictness::default()
        };
        let proxy_svc = HaProxyService::new(service_fn(echo)).with_strictness(strictness);
        let request = ServiceInput::new(std::io::Cursor::new(DATA.to_vec()));
        proxy_svc.serve(request).await.unwrap_err();
    }

    /// Regression: with `require_crc32c=true`, a header whose TLV stream is
    /// malformed before reaching a CRC32C TLV must be rejected as
    /// "CRC missing" (we couldn't confirm a CRC TLV is present — fail safe).
    #[tokio::test]
    async fn test_haproxy_v2_require_crc32c_with_malformed_before_crc_rejects() {
        // 12-byte addresses + a truncated TLV (length=99, only 1 byte of
        // value follows). No CRC32C TLV anywhere.
        let mut header = Vec::from(v2::PROTOCOL_PREFIX);
        header.push(0x21);
        header.push(0x11);
        header.extend([0x00, 0x10]); // 12 addresses + 4 truncated TLV bytes
        header.extend([192, 0, 2, 1]);
        header.extend([198, 51, 100, 1]);
        header.extend([0x30, 0x39]);
        header.extend([0x01, 0xBB]);
        header.extend([0x04, 0x00, 0x63, 0xAA]); // NoOp TLV claiming length=99

        let strictness = HaProxyStrictness {
            require_crc32c: true,
            ..HaProxyStrictness::default()
        };
        let proxy_svc = HaProxyService::new(service_fn(echo)).with_strictness(strictness);
        let request = ServiceInput::new(std::io::Cursor::new(header));
        let err = proxy_svc.serve(request).await.unwrap_err();
        assert!(
            err.to_string().contains("CRC32C"),
            "expected CRC32C-missing-style error, got: {err}",
        );
    }

    /// Regression: a header whose TLV area is malformed but does NOT carry a
    /// CRC32C TLV must NOT be rejected as "CRC invalid" by the default
    /// `verify_crc32c_when_present=true` strictness.
    ///
    /// `fail_on_malformed_tlv=false` (lenient default) → accept.
    /// `fail_on_malformed_tlv=true` → reject, but with a malformed-TLV error.
    #[tokio::test]
    async fn test_haproxy_v2_malformed_tlv_without_crc_is_accepted_by_default() {
        // 12-byte addresses + a truncated TLV (length=99 but only 1 byte
        // available afterwards). No CRC32C TLV.
        let mut header = Vec::from(v2::PROTOCOL_PREFIX);
        header.push(0x21);
        header.push(0x11);
        header.extend([0x00, 0x10]); // payload length = 16 (12 + 4 truncated TLV bytes)
        header.extend([192, 0, 2, 1]);
        header.extend([198, 51, 100, 1]);
        header.extend([0x30, 0x39]);
        header.extend([0x01, 0xBB]);
        // TLV: kind=0x04 (NoOp), length=99, but only 1 byte of value follows.
        header.extend([0x04, 0x00, 0x63, 0xAA]);

        // Default strictness accepts (CRC verification is not tricked into
        // returning "invalid" by a malformed TLV that isn't a CRC TLV).
        let proxy_svc = HaProxyService::new(service_fn(echo));
        let request = ServiceInput::new(std::io::Cursor::new(header.clone()));
        proxy_svc.serve(request).await.expect("default accepts");

        // Opting into strict TLV parsing rejects the same input.
        let strict_svc = HaProxyService::new(service_fn(echo)).with_strictness(HaProxyStrictness {
            fail_on_malformed_tlv: true,
            ..HaProxyStrictness::default()
        });
        let request = ServiceInput::new(std::io::Cursor::new(header));
        strict_svc.serve(request).await.unwrap_err();
    }
}
