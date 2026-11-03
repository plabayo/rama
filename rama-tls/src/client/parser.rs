//! Perma-forked from
//! tls-parser @ 65a2fe0b86f09235515337c501c8a512db1c6dba
//!
//! src and attribution: <https://github.com/rusticata/tls-parser>

use super::hello::{ECHClientHello, ECHClientHelloOuter, HpkeSymmetricCipherSuite};
use super::{ClientHello, ClientHelloExtension};
use crate::{CipherSuite, ExtensionId, enums::CompressionAlgorithm};
use nom::{
    IResult, Parser,
    bytes::streaming::take,
    combinator::{all_consuming, complete, cond, map, map_opt, map_parser, verify},
    error::{ErrorKind, make_error},
    multi::{length_data, many0},
    number::streaming::{be_u8, be_u16},
};
use rama_core::error::BoxErrorExt as _;
use rama_core::error::{BoxError, ErrorExt as _};
use rama_net::{
    address::{Domain, Host},
    tls::ApplicationProtocol,
};
use rama_utils::octets::kib;
use std::{borrow::Cow, str};

/// Parse a [`ClientHello`] from the raw "wire" bytes.
///
/// This function is not infallible, it can return an error if the input is not a valid
/// TLS ClientHello message or if there is unexpected trailing data.
pub fn parse_client_hello(i: &[u8]) -> Result<ClientHello, BoxError> {
    match parse_client_hello_inner(i) {
        Err(err) => Err(
            BoxError::from_static_str("parse client hello handshake message")
                .context_debug_field("err", err.to_owned()),
        ),
        Ok((i, hello)) => {
            if !i.is_empty() {
                return Err(BoxError::from_static_str("trailing ClientHello body bytes"));
            }
            Ok(hello)
        }
    }
}

/// Default maximum ClientHello handshake bytes for live inspection, including its header.
pub const DEFAULT_CLIENT_HELLO_MAX_SIZE: usize = kib(256);

// TLS's unsigned 24-bit handshake body length plus its four-byte header (RFC 8446 section 4).
const MAX_CLIENT_HELLO_MESSAGE_SIZE: usize = 0x00ff_ffff + 4;

/// A ClientHello header cannot describe an inspectable message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientHelloMessageError {
    /// The handshake type is not ClientHello, or its body is empty.
    Invalid,
    /// The header or declared message exceeds the caller's byte budget.
    TooLarge,
}

impl std::fmt::Display for ClientHelloMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "invalid ClientHello handshake header",
            Self::TooLarge => "ClientHello exceeds the message byte budget",
        })
    }
}

impl std::error::Error for ClientHelloMessageError {}

/// Inspect a contiguous TLS handshake header without allocating or needing its body.
///
/// Returns the total message size, including the four-byte header, or `None` if
/// the header is incomplete. TLS records and QUIC CRYPTO assembly both use this
/// check after making their first handshake bytes contiguous. The caller supplies
/// its byte budget and decides how to retain or replay transport data.
pub fn client_hello_message_size(
    prefix: &[u8],
    max_size: usize,
) -> Result<Option<usize>, ClientHelloMessageError> {
    if max_size < 4 {
        return Err(ClientHelloMessageError::TooLarge);
    }
    // TLS HandshakeType client_hello is 1; its length is an unsigned 24-bit
    // body length following the type byte (RFC 8446 section 4).
    if prefix.first().is_some_and(|kind| *kind != 1) {
        return Err(ClientHelloMessageError::Invalid);
    }
    let Some(header) = prefix.get(..4) else {
        return Ok(None);
    };
    let size = 4
        + ((usize::from(header[1]) << 16) | (usize::from(header[2]) << 8) | usize::from(header[3]));
    if size == 4 {
        return Err(ClientHelloMessageError::Invalid);
    }
    if size > max_size {
        return Err(ClientHelloMessageError::TooLarge);
    }
    Ok(Some(size))
}

/// Bounds for reassembling the first record-framed ClientHello.
///
/// Defaults allow 256 KiB (including the four-byte handshake header) across
/// 256 records. Memory grows with received bytes, never a peer's declaration.
/// Plaintext record payloads must still be nonempty and at most 16 KiB.
/// These limits do not apply to bare ClientHello bodies or QUIC messages.
#[derive(Debug, Clone, Copy)]
pub struct ClientHelloReassemblyConfig {
    max_handshake_size: usize,
    max_records: usize,
    require_matching_record_version: bool,
}

impl Default for ClientHelloReassemblyConfig {
    fn default() -> Self {
        Self {
            max_handshake_size: DEFAULT_CLIENT_HELLO_MAX_SIZE,
            max_records: 256,
            require_matching_record_version: false,
        }
    }
}

impl ClientHelloReassemblyConfig {
    rama_utils::macros::generate_set_and_with! {
        /// Set the maximum handshake bytes, including its four-byte header.
        /// Defaults to 256 KiB. Values below four reject every hello; values
        /// above the TLS 24-bit length plus four have no additional effect.
        pub fn max_handshake_size(mut self, size: usize) -> Self {
            self.max_handshake_size = size;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the maximum records contributing to the first handshake.
        /// Defaults to 256. Zero rejects every hello.
        pub fn max_records(mut self, count: usize) -> Self {
            self.max_records = count;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Require every record's legacy version to equal the first one's.
        /// Defaults to false for interoperability: TLS 1.3 ignores this field
        /// (RFC 8446 §5.1). Every record must still use a recognized TLS version.
        pub fn require_matching_record_version(mut self, required: bool) -> Self {
            self.require_matching_record_version = required;
            self
        }
    }

    pub(crate) fn max_wire_size(self) -> usize {
        let size = self.max_handshake_size.min(MAX_CLIENT_HELLO_MESSAGE_SIZE);
        // Each nonempty record contributes at least one handshake byte. Allow
        // the rest of the final record, which can contain another message.
        size + self.max_records.min(size) * 5 + MAX_PLAINTEXT_RECORD_SIZE
    }
}

const MAX_PLAINTEXT_RECORD_SIZE: usize = kib(16);

/// Parse exactly one ClientHello from TLS records using default reassembly bounds.
///
/// Unlike the prefix parser, this rejects trailing bytes, including another
/// handshake in the final record. Record headers may split the handshake at
/// any byte, including within its four-byte header.
pub fn parse_client_hello_handshake(i: &[u8]) -> Result<ClientHello, BoxError> {
    parse_client_hello_handshake_with_config(i, ClientHelloReassemblyConfig::default())
}

/// Parse exactly one record-framed ClientHello with explicit reassembly bounds.
pub fn parse_client_hello_handshake_with_config(
    i: &[u8],
    config: ClientHelloReassemblyConfig,
) -> Result<ClientHello, BoxError> {
    match parse_client_hello_handshake_prefix_inner(i, config) {
        Err(err) => Err(
            BoxError::from_static_str("parse client hello handshake message")
                .context_debug_field("err", err.to_owned()),
        ),
        Ok((i, hello)) => {
            if !i.is_empty() {
                return Err(BoxError::from_static_str(
                    "trailing ClientHello handshake bytes",
                ));
            }
            Ok(hello)
        }
    }
}

/// Outcome of incrementally classifying a (possibly partial) TLS ClientHello
/// handshake, for fail-fast protocol peeking.
///
/// It lets a peeker distinguish "keep reading" ([`Incomplete`]) from "this can
/// never be a ClientHello, stop now" ([`Invalid`]) — a distinction the plain
/// `Result` returned by [`parse_client_hello_handshake`] collapses (it maps
/// both to an error).
///
/// [`Incomplete`]: ClientHelloHandshakePrefix::Incomplete
/// [`Invalid`]: ClientHelloHandshakePrefix::Invalid
#[derive(Debug)]
pub enum ClientHelloHandshakePrefix {
    /// A complete, valid ClientHello handshake was parsed from the prefix.
    Complete(ClientHello),
    /// The prefix is a valid start of a ClientHello handshake but more bytes
    /// are needed to finish — keep peeking.
    Incomplete,
    /// The prefix cannot be a valid ClientHello handshake regardless of what
    /// bytes follow — stop peeking.
    Invalid,
}

/// Incrementally classify a (possibly partial) TLS ClientHello handshake.
///
/// This is the fail-fast counterpart of [`parse_client_hello_handshake`]: the
/// underlying streaming parser reports `Incomplete` when the bytes so far are a
/// valid prefix that simply needs more data, and a hard parse error when they
/// can never form a valid ClientHello. This surfaces that distinction as
/// [`ClientHelloHandshakePrefix`] so a peeker only keeps waiting while the
/// prefix remains possibly-valid, and rejects immediately otherwise.
pub fn parse_client_hello_handshake_prefix(i: &[u8]) -> ClientHelloHandshakePrefix {
    parse_client_hello_handshake_prefix_with_config(i, ClientHelloReassemblyConfig::default())
}

/// Classify a record-framed ClientHello using explicit reassembly bounds.
///
/// A partial record is incomplete even if its available payload contains the
/// entire hello. Once its containing record is complete, subsequent handshake
/// messages and records are ignored. Limit violations are invalid immediately.
pub fn parse_client_hello_handshake_prefix_with_config(
    i: &[u8],
    config: ClientHelloReassemblyConfig,
) -> ClientHelloHandshakePrefix {
    match parse_client_hello_handshake_prefix_inner(i, config) {
        Ok((_, hello)) => ClientHelloHandshakePrefix::Complete(hello),
        Err(nom::Err::Incomplete(_)) => ClientHelloHandshakePrefix::Incomplete,
        Err(nom::Err::Error(_) | nom::Err::Failure(_)) => ClientHelloHandshakePrefix::Invalid,
    }
}

fn parse_client_hello_handshake_prefix_inner(
    i: &[u8],
    config: ClientHelloReassemblyConfig,
) -> IResult<&[u8], ClientHello> {
    let (rest, message) = reassemble_client_hello(i, config)?;
    // Complete-parse the exact body so missing extensions cannot be mistaken
    // for an extension-less hello.
    let hello = complete(all_consuming(parse_client_hello_inner))
        .parse(&message[4..])
        .map_err(|err| err.map(|err| make_error(i, err.code)))?
        .1;
    Ok((rest, hello))
}

/// Scan record framing without copying partial handshakes. Only assemble once
/// all required bytes have arrived; the common single-record case is borrowed.
/// Repeated prefix calls inspect at most `max_records` headers and four handshake
/// header bytes, rather than copying the growing body on every TCP read.
fn reassemble_client_hello(
    input: &[u8],
    config: ClientHelloReassemblyConfig,
) -> IResult<&[u8], Cow<'_, [u8]>> {
    let mut i = input;
    let mut header = [0u8; 4];
    let mut header_len = 0;
    let mut expected = None;
    let mut first_version = None;
    let mut records = 0;
    let mut handshake_bytes = 0;
    loop {
        let invalid = || nom::Err::Error(make_error(i, ErrorKind::Verify));
        if config.max_handshake_size < 4 || records >= config.max_records {
            return Err(invalid());
        }
        // Validate available header bytes before asking for more input.
        if i.first().is_some_and(|b| *b != 0x16)
            || i.get(1).is_some_and(|b| *b != 0x03)
            || i.get(2).is_some_and(|b| !matches!(b, 0x00..=0x04))
        {
            return Err(invalid());
        }
        if i.len() < 5 {
            return Err(nom::Err::Incomplete(nom::Needed::Unknown));
        }
        let version = [i[1], i[2]];
        if config.require_matching_record_version
            && first_version.is_some_and(|first| first != version)
        {
            return Err(invalid());
        }
        first_version.get_or_insert(version);
        let record_len = usize::from(u16::from_be_bytes([i[3], i[4]]));
        if record_len == 0 || record_len > MAX_PLAINTEXT_RECORD_SIZE {
            return Err(invalid());
        }
        records += 1;
        let payload = &i[5..];
        let available = &payload[..payload.len().min(record_len)];
        if header_len < 4 {
            let n = (4 - header_len).min(available.len());
            header[header_len..header_len + n].copy_from_slice(&available[..n]);
            header_len += n;
            expected = client_hello_message_size(&header[..header_len], config.max_handshake_size)
                .map_err(|_error| invalid())?;
        }
        if available.len() < record_len {
            return Err(nom::Err::Incomplete(nom::Needed::Unknown));
        }
        if let Some(size) = expected.filter(|size| *size <= handshake_bytes + record_len) {
            let used = size - handshake_bytes;
            let message = if records == 1 {
                Cow::Borrowed(&payload[..used])
            } else {
                // The first pass proved these bytes exist and fit the limits.
                // This allocation follows received data, not a declaration.
                let mut message = Vec::with_capacity(size);
                let mut rest = input;
                while message.len() < size {
                    let len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
                    let n = len.min(size - message.len());
                    message.extend_from_slice(&rest[5..5 + n]);
                    rest = &rest[5 + len..];
                }
                Cow::Owned(message)
            };
            return Ok((&payload[used..], message));
        }
        handshake_bytes += record_len;
        i = &payload[record_len..];
    }
}

/// Incrementally classify a (possibly partial) bare TLS ClientHello handshake message: the
/// handshake header and body with no TLS record layer in front, as QUIC carries in its CRYPTO
/// stream (RFC 9001 §4.1).
///
/// The record-framed counterpart is [`parse_client_hello_handshake_prefix`]; this one skips the
/// record header a QUIC CRYPTO stream never has. Same incompleteness contract: `Incomplete`
/// while the buffered bytes are a valid but unfinished prefix, `Invalid` when they can never
/// complete.
pub fn parse_client_hello_message_prefix(i: &[u8]) -> ClientHelloHandshakePrefix {
    match parse_client_hello_message_prefix_inner(i) {
        Ok((_, hello)) => ClientHelloHandshakePrefix::Complete(hello),
        Err(nom::Err::Incomplete(_)) => ClientHelloHandshakePrefix::Incomplete,
        Err(nom::Err::Error(_) | nom::Err::Failure(_)) => ClientHelloHandshakePrefix::Invalid,
    }
}

fn parse_client_hello_message_prefix_inner(i: &[u8]) -> IResult<&[u8], ClientHello> {
    let size = client_hello_message_size(i, MAX_CLIENT_HELLO_MESSAGE_SIZE)
        .map_err(|_error| nom::Err::Error(make_error(i, ErrorKind::Verify)))?
        .ok_or(nom::Err::Incomplete(nom::Needed::Unknown))?;
    let (i, _) = take(4usize).parse(i)?;
    let hs_len = size - 4;

    // Bound the body by the handshake length so a short buffer is `Incomplete` rather than a
    // falsely-completed extension-less hello.
    let (rest, body) = take(hs_len).parse(i)?;
    let (_, hello) = complete(all_consuming(parse_client_hello_inner)).parse(body)?;
    Ok((rest, hello))
}

/// Parse a [`ClientHello`] from the raw incoming "wire" client handshake bytes to find the SNI Host value.
///
/// Same as [`extract_sni_from_client_hello_record`] but handles the full handshake bytes, meaning
/// the client hello record itself and the handshake header bytes in front of it.
pub fn extract_sni_from_client_hello_handshake(i: &[u8]) -> Result<Option<Domain>, BoxError> {
    extract_sni_from_client_hello_handshake_with_config(i, ClientHelloReassemblyConfig::default())
}

/// Extract SNI from reassembled TLS records with explicit bounds.
///
/// Like the body-only extractor, this validates SNI but skips other extension
/// contents. It is not a substitute for validating the entire ClientHello.
pub fn extract_sni_from_client_hello_handshake_with_config(
    i: &[u8],
    config: ClientHelloReassemblyConfig,
) -> Result<Option<Domain>, BoxError> {
    let (_, message) = reassemble_client_hello(i, config).map_err(|err| {
        BoxError::from_static_str("reassemble client hello handshake to find SNI")
            .context_debug_field("err", err.to_owned())
    })?;
    extract_sni_from_client_hello_record(&message[4..])
}

/// Parse a [`ClientHello`] from the raw "wire" bytes to find the SNI Host value.
///
/// This function is optimised to find the SNI value and nothing else.
/// Use [`parse_client_hello`] in case you need other content in the client hello,
/// or the client hello as a whole.
///
/// This validates the encountered SNI payload and stops once it finds a host name.
/// Other extensions are skipped, so a successful lookup does not establish a complete
/// ClientHello observation. It returns `None` when no SNI host name is present.
pub fn extract_sni_from_client_hello_record(i: &[u8]) -> Result<Option<Domain>, BoxError> {
    parse_client_hello_record_sni_inner(i)
        .map(|(_, domain)| domain)
        .map_err(|err| {
            BoxError::from_static_str("parse client hello record message to find SNI")
                .context_debug_field("err", err.to_owned())
        })
}

fn parse_client_hello_record_sni_inner(i: &[u8]) -> IResult<&[u8], Option<Domain>> {
    // skip version and random
    let (i, _) = take(34usize)(i)?;

    // skip sid
    let (i, sidlen) = verify(be_u8, |&n| n <= 32).parse(i)?;
    let (i, _) = cond(sidlen > 0, take(sidlen as usize)).parse(i)?;

    // skip ciphers
    let (i, ciphers_len) = be_u16(i)?;
    let (i, _) = take(ciphers_len)(i)?;

    // skip compression algos
    let (i, comp_len) = be_u8(i)?;
    let (i, _) = take(comp_len)(i)?;

    // Search for the SNI extension. Same incompleteness contract as
    // `parse_client_hello_inner`: an empty tail means "no extensions
    // block" (no SNI), but a *declared-yet-truncated* extensions
    // section must surface as `Incomplete` (via streaming `be_u16` /
    // `take`) so an incremental peeker keeps reading instead of
    // silently concluding "no SNI" from a half-buffered hello.
    if i.is_empty() {
        return Ok((&[], None));
    }
    let (after_len, ext_len) = be_u16(i)?;
    let (_, mut ext_payload) = take(ext_len as usize).parse(after_len)?;
    while !ext_payload.is_empty() {
        let (next, domain) = parse_tls_client_hello_extension_sni_host_or_skip(ext_payload)?;
        if let Some(domain) = domain {
            return Ok((next, Some(domain)));
        }
        ext_payload = next;
    }

    // no SNI found...
    Ok((&[], None))
}

fn parse_client_hello_inner(i: &[u8]) -> IResult<&[u8], ClientHello> {
    let (i, version) = be_u16(i)?;
    let (i, _random) = take(32usize)(i)?;
    let (i, sidlen) = verify(be_u8, |&n| n <= 32).parse(i)?;
    let (i, _sid) = cond(sidlen > 0, take(sidlen as usize)).parse(i)?;
    let (i, ciphers_len) = be_u16(i)?;
    let (i, cipher_suites) = parse_cipher_suites(i, ciphers_len as usize)?;
    let (i, comp_len) = be_u8(i)?;
    let (i, compression_algorithms) = parse_compressions_algs(i, comp_len as usize)?;

    // Extensions section.
    //
    // If `i` is empty here, the ClientHello legitimately carries no
    // extensions block (a TLS 1.0/1.1-era hello) — return an empty
    // list. Otherwise the 2-byte length AND the full declared payload
    // MUST be present; we parse them with the *streaming* `be_u16` /
    // `take` so a short buffer surfaces as `Incomplete` and propagates
    // via `?`. The previous `opt(complete(length_data(...)))` masked
    // BOTH "no section" and "section declared but truncated" as
    // `None`, which silently dropped SNI / ALPN / supported_versions
    // from a half-buffered hello and made the MITM mirror a bare
    // default ClientHello that upstreams reject. An incremental peeker
    // must keep reading on truncation, not accept a stripped hello.
    let (i, extensions) = if i.is_empty() {
        (i, Vec::new())
    } else {
        let (after_len, ext_len) = be_u16(i)?;
        let (after_ext, mut ext_payload) = take(ext_len as usize).parse(after_len)?;
        let mut extensions = vec![];
        while !ext_payload.is_empty() {
            let (next, ch_ext) = parse_tls_client_hello_extension(ext_payload)?;
            extensions.push(ch_ext);
            ext_payload = next;
        }
        (after_ext, extensions)
    };

    Ok((
        i,
        ClientHello {
            protocol_version: version.into(),
            cipher_suites,
            compression_algorithms,
            extensions,
        },
    ))
}

fn parse_cipher_suites(i: &[u8], len: usize) -> IResult<&[u8], Vec<CipherSuite>> {
    if len == 0 {
        return Ok((i, Vec::new()));
    }
    if len % 2 == 1 || len > i.len() {
        return Err(nom::Err::Error(make_error(i, ErrorKind::LengthValue)));
    }
    let v = (i[..len])
        .chunks(2)
        .map(|chunk| CipherSuite::from(((chunk[0] as u16) << 8) | chunk[1] as u16))
        .collect();
    Ok((&i[len..], v))
}

fn parse_compressions_algs(i: &[u8], len: usize) -> IResult<&[u8], Vec<CompressionAlgorithm>> {
    if len == 0 {
        return Ok((i, Vec::new()));
    }
    if len > i.len() {
        return Err(nom::Err::Error(make_error(i, ErrorKind::LengthValue)));
    }
    let v = (i[..len])
        .iter()
        .map(|&it| CompressionAlgorithm::from(it))
        .collect();
    Ok((&i[len..], v))
}

fn parse_tls_client_hello_extension_sni_host_or_skip(i: &[u8]) -> IResult<&[u8], Option<Domain>> {
    let (i, ext_type) = be_u16(i)?;
    let id = ExtensionId::from(ext_type);
    let (i, ext_data) = length_data(be_u16).parse(i)?;

    if id == ExtensionId::SERVER_NAME {
        let (_, name) = all_consuming(parse_tls_extension_sni).parse(ext_data)?;
        Ok((i, name))
    } else {
        Ok((i, None))
    }
}

fn parse_tls_client_hello_extension(i: &[u8]) -> IResult<&[u8], ClientHelloExtension> {
    let (i, ext_type) = be_u16(i)?;
    let id = ExtensionId::from(ext_type);
    let (i, ext_data) = length_data(be_u16).parse(i)?;

    let (remaining, ext) = match id {
        ExtensionId::SERVER_NAME => parse_tls_extension_sni_content(ext_data),
        ExtensionId::SUPPORTED_GROUPS => parse_tls_extension_elliptic_curves_content(ext_data),
        ExtensionId::EC_POINT_FORMATS => parse_tls_extension_ec_point_formats_content(ext_data),
        ExtensionId::SIGNATURE_ALGORITHMS => {
            parse_tls_extension_signature_algorithms_content(ext_data)
        }
        ExtensionId::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => {
            parse_tls_extension_alpn_content(ext_data)
        }
        ExtensionId::SUPPORTED_VERSIONS => parse_tls_extension_supported_versions_content(ext_data),
        ExtensionId::COMPRESS_CERTIFICATE => {
            parse_tls_extension_certificate_compression_content(ext_data)
        }
        ExtensionId::DELEGATED_CREDENTIAL => parse_tls_extension_delegated_credentials(ext_data),
        ExtensionId::RECORD_SIZE_LIMIT => {
            let (i, v) = be_u16(ext_data)?;
            Ok((i, ClientHelloExtension::RecordSizeLimit(v)))
        }
        ExtensionId::SERVER_PADDING_REQUEST => {
            let (i, bytes) = be_u16(ext_data)?;
            Ok((i, ClientHelloExtension::ServerPaddingRequest(bytes)))
        }
        ExtensionId::ENCRYPTED_CLIENT_HELLO => {
            let (i, ech) = parse_ech_client_hello(ext_data)?;
            Ok((i, ClientHelloExtension::EncryptedClientHello(ech)))
        }
        ExtensionId::APPLICATION_SETTINGS => {
            parse_tls_extension_application_settings_content(ext_data, true)
        }
        ExtensionId::OLD_APPLICATION_SETTINGS => {
            parse_tls_extension_application_settings_content(ext_data, false)
        }
        _ => Ok((
            &[][..],
            ClientHelloExtension::Opaque {
                id,
                data: ext_data.to_vec(),
            },
        )),
    }?;
    if !remaining.is_empty() {
        return Err(nom::Err::Error(make_error(remaining, ErrorKind::Eof)));
    }
    Ok((i, ext))
}

// struct {
//     ServerName server_name_list<1..2^16-1>
// } ServerNameList;
fn parse_tls_extension_sni_content(i: &[u8]) -> IResult<&[u8], ClientHelloExtension> {
    let (i, domain) = parse_tls_extension_sni(i)?;
    Ok((i, ClientHelloExtension::ServerName(domain)))
}

// struct {
//     ServerName server_name_list<1..2^16-1>
// } ServerNameList;
fn parse_tls_extension_sni(i: &[u8]) -> IResult<&[u8], Option<Domain>> {
    let (i, list_len) = be_u16(i)?;
    let (i, mut v) = map_parser(
        take(list_len),
        all_consuming(many0(complete(parse_tls_extension_sni_hostname))),
    )
    .parse(i)?;
    if v.len() != 1 {
        return Err(nom::Err::Error(nom::error::Error::new(
            i,
            ErrorKind::TooLarge,
        )));
    }
    Ok((i, v.pop()))
}

// struct {
//     NameType name_type;
//     select (name_type) {
//         case host_name: HostName;
//     } name;
// } ServerName;
//
// enum {
//     host_name(0), (255)
// } NameType;
//
// opaque HostName<1..2^16-1>;
fn parse_tls_extension_sni_hostname(i: &[u8]) -> IResult<&[u8], Domain> {
    let (i, nt) = be_u8(i)?;
    if nt != 0 {
        return Err(nom::Err::Error(nom::error::Error::new(i, ErrorKind::IsNot)));
    }
    let (i, v) = length_data(be_u16).parse(i)?;
    let host: Host = str::from_utf8(v)
        .map_err(|_e| nom::Err::Error(nom::error::Error::new(i, ErrorKind::Not)))?
        .parse()
        .map_err(|_e| nom::Err::Error(nom::error::Error::new(i, ErrorKind::Not)))?;

    // TLS SNI carries a DNS-shaped name (RFC 6066 §3). Anything that
    // can promote to a Domain is accepted — including pct-encoded
    // reg-names — via `try_into_domain`. IP literals and
    // non-promotable bytes (sub-delim, IPvFuture) are rejected.
    match host.try_into_domain() {
        Ok(domain) => Ok((i, domain)),
        Err(_) => Err(nom::Err::Error(nom::error::Error::new(i, ErrorKind::Not))),
    }
}

// defined in rfc8422
fn parse_tls_extension_elliptic_curves_content(i: &[u8]) -> IResult<&[u8], ClientHelloExtension> {
    map_parser(
        length_data(be_u16),
        map(parse_u16_type, ClientHelloExtension::SupportedGroups),
    )
    .parse(i)
}

fn parse_tls_extension_ec_point_formats_content(i: &[u8]) -> IResult<&[u8], ClientHelloExtension> {
    map_parser(
        length_data(be_u8),
        map(parse_u8_type, ClientHelloExtension::ECPointFormats),
    )
    .parse(i)
}

// ClientHello carries a length-prefixed vector, never the ServerHello scalar.
fn parse_tls_extension_supported_versions_content(
    i: &[u8],
) -> IResult<&[u8], ClientHelloExtension> {
    map_parser(
        length_data(verify(be_u8, |length| {
            *length >= 2 && length.is_multiple_of(2)
        })),
        map(parse_u16_type, ClientHelloExtension::SupportedVersions),
    )
    .parse(i)
}

/// Parse 'Signature Algorithms' extension (rfc8446, TLS 1.3 only)
fn parse_tls_extension_signature_algorithms_content(
    i: &[u8],
) -> IResult<&[u8], ClientHelloExtension> {
    map_parser(
        length_data(be_u16),
        map(parse_u16_type, ClientHelloExtension::SignatureAlgorithms),
    )
    .parse(i)
}

// Parse 'Delegated credentials' extensions (rfc9345)
fn parse_tls_extension_delegated_credentials(i: &[u8]) -> IResult<&[u8], ClientHelloExtension> {
    map_parser(
        length_data(be_u16),
        map(parse_u16_type, ClientHelloExtension::DelegatedCredentials),
    )
    .parse(i)
}

/// Defined in [RFC7301]
fn parse_tls_extension_alpn_content(i: &[u8]) -> IResult<&[u8], ClientHelloExtension> {
    map_parser(
        length_data(be_u16),
        map(
            parse_protocol_name_list,
            ClientHelloExtension::ApplicationLayerProtocolNegotiation,
        ),
    )
    .parse(i)
}

fn parse_tls_extension_certificate_compression_content(
    i: &[u8],
) -> IResult<&[u8], ClientHelloExtension> {
    map_parser(
        length_data(be_u8),
        map(parse_u16_type, ClientHelloExtension::CertificateCompression),
    )
    .parse(i)
}

fn parse_protocol_name_list(mut i: &[u8]) -> IResult<&[u8], Vec<ApplicationProtocol>> {
    // The loop consumes `i` until it is empty, so `i` at the end of the loop
    // is the actual (empty) residual — return it verbatim. The original
    // version hard-coded `Ok((&[], v))`, which masked any future bug in the
    // loop's accounting and was inconsistent with the rest of the parser
    // (other helpers surface the unconsumed tail).
    let mut v = vec![];
    while !i.is_empty() {
        let (n, alpn) = map_parser(length_data(be_u8), parse_protocol_name).parse(i)?;
        v.push(alpn);
        i = n;
    }
    Ok((i, v))
}

fn parse_protocol_name(i: &[u8]) -> IResult<&[u8], ApplicationProtocol> {
    let alpn = ApplicationProtocol::from(i);
    Ok((&[], alpn))
}

fn parse_tls_extension_application_settings_content(
    i: &[u8],
    new_codepoint: bool,
) -> IResult<&[u8], ClientHelloExtension> {
    let (n, alps) = map_parser(length_data(be_u16), parse_protocol_name_list).parse(i)?;

    let application_settings = ClientHelloExtension::ApplicationSettings {
        protocols: alps,
        new_codepoint,
    };

    Ok((n, application_settings))
}

fn parse_u8_type<T: From<u8>>(i: &[u8]) -> IResult<&[u8], Vec<T>> {
    let v = i.iter().map(|i| T::from(*i)).collect();
    Ok((&[], v))
}

fn parse_u16_type<T: From<u16>>(i: &[u8]) -> IResult<&[u8], Vec<T>> {
    let len = i.len();
    if len == 0 {
        return Ok((i, Vec::new()));
    }
    if len % 2 == 1 || len > i.len() {
        return Err(nom::Err::Error(make_error(i, ErrorKind::LengthValue)));
    }
    let v = (i[..len])
        .chunks(2)
        .map(|chunk| T::from(((chunk[0] as u16) << 8) | chunk[1] as u16))
        .collect();
    Ok((&i[len..], v))
}

fn parse_ech_client_hello(input: &[u8]) -> IResult<&[u8], ECHClientHello> {
    let (input, is_outer) = map_opt(be_u8, |v| match v {
        0 => Some(true),
        1 => Some(false),
        _ => None,
    })
    .parse(input)?;

    match is_outer {
        true => {
            let (input, (kdf_id, aead_id, config_id)) = (be_u16, be_u16, be_u8).parse(input)?;
            let (input, enc) = length_data(be_u16).parse(input)?;
            let (input, payload) = length_data(be_u16).parse(input)?;

            Ok((
                input,
                ECHClientHello::Outer(ECHClientHelloOuter {
                    cipher_suite: HpkeSymmetricCipherSuite {
                        aead_id: aead_id.into(),
                        kdf_id: kdf_id.into(),
                    },
                    config_id,
                    enc: enc.to_vec(),
                    payload: payload.to_vec(),
                }),
            ))
        }
        false => Ok((input, ECHClientHello::Inner)),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn shared_header_validation_is_incremental_and_bounded() {
        use super::{
            ClientHelloMessageError, MAX_CLIENT_HELLO_MESSAGE_SIZE, client_hello_message_size,
        };
        for size in [
            5usize,
            rama_utils::octets::kib(256),
            MAX_CLIENT_HELLO_MESSAGE_SIZE,
        ] {
            let body = u32::try_from(size - 4).unwrap().to_be_bytes();
            let header = [1, body[1], body[2], body[3]];
            for prefix in 0..4 {
                assert_eq!(client_hello_message_size(&header[..prefix], size), Ok(None));
            }
            assert_eq!(client_hello_message_size(&header, size), Ok(Some(size)));
            assert_eq!(
                client_hello_message_size(&header, size - 1),
                Err(ClientHelloMessageError::TooLarge)
            );
        }
        assert_eq!(
            client_hello_message_size(&[2], usize::MAX),
            Err(ClientHelloMessageError::Invalid)
        );
        assert_eq!(
            client_hello_message_size(&[1, 0, 0, 0], usize::MAX),
            Err(ClientHelloMessageError::Invalid)
        );
        assert_eq!(
            client_hello_message_size(&[], 3),
            Err(ClientHelloMessageError::TooLarge)
        );
    }

    use super::*;
    use crate::{
        CertificateCompressionAlgorithm, ECPointFormat, ExtensionId, ProtocolVersion,
        SignatureScheme, SupportedGroup,
    };
    use rama_net::address::Domain;
    use std::assert_matches;

    use crate::client::test_support::{fragments, hello, record};

    #[test]
    fn record_fragmentation_preserves_hello_and_fingerprints_at_every_split() {
        use crate::fingerprint::{Ja3, Ja4};
        let message = hello(0);
        let expected = parse_client_hello_handshake(&record(&message)).unwrap();
        let expected_json = serde_json::to_value(&expected).unwrap();
        for split in 1..message.len() {
            let mut wire = record(&message[..split]);
            wire.extend(record(&message[split..]));
            for end in 0..wire.len() {
                assert_matches!(
                    parse_client_hello_handshake_prefix(&wire[..end]),
                    ClientHelloHandshakePrefix::Incomplete
                );
            }
            let actual = parse_client_hello_handshake(&wire).unwrap();
            assert_eq!(serde_json::to_value(&actual).unwrap(), expected_json);
            assert_eq!(
                extract_sni_from_client_hello_handshake(&wire).unwrap(),
                expected.ext_server_name().cloned()
            );
            assert_eq!(
                Ja3::compute_from_client_hello(&actual).unwrap().to_string(),
                Ja3::compute_from_client_hello(&expected)
                    .unwrap()
                    .to_string()
            );
            assert_eq!(
                Ja4::compute_from_client_hello(&actual).unwrap().to_string(),
                Ja4::compute_from_client_hello(&expected)
                    .unwrap()
                    .to_string()
            );
        }
        parse_client_hello_handshake(&fragments(&message, 1)).unwrap();
        assert_matches!(
            parse_client_hello_message_prefix(&message),
            ClientHelloHandshakePrefix::Complete(_)
        );
    }

    #[test]
    fn reassembly_limits_are_configurable_and_reject_declarations_early() {
        let message = hello(400);
        let wire = fragments(&message, 1);
        assert_matches!(
            parse_client_hello_handshake_prefix(&wire),
            ClientHelloHandshakePrefix::Invalid
        );
        let config = ClientHelloReassemblyConfig {
            max_handshake_size: message.len(),
            max_records: message.len(),
            ..Default::default()
        };
        parse_client_hello_handshake_with_config(&wire, config).unwrap();
        assert_eq!(
            extract_sni_from_client_hello_handshake_with_config(&wire, config)
                .unwrap()
                .unwrap()
                .as_str(),
            "x.com"
        );
        for config in [
            ClientHelloReassemblyConfig {
                max_handshake_size: message.len() - 1,
                ..config
            },
            ClientHelloReassemblyConfig {
                max_records: message.len() - 1,
                ..config
            },
            ClientHelloReassemblyConfig {
                max_records: 0,
                ..config
            },
            ClientHelloReassemblyConfig {
                max_handshake_size: 0,
                ..config
            },
        ] {
            assert_matches!(
                parse_client_hello_handshake_prefix_with_config(&wire, config),
                ClientHelloHandshakePrefix::Invalid
            );
        }
        // The over-cap handshake declaration is rejected before its body arrives.
        let declared = [0x16, 3, 1, 0x40, 0, 1, 4, 0, 0];
        assert_matches!(
            parse_client_hello_handshake_prefix(&declared),
            ClientHelloHandshakePrefix::Invalid
        );
        // The record-count budget cannot be extended by waiting for more input.
        assert_matches!(
            parse_client_hello_handshake_prefix_with_config(
                &record(&message[..1]),
                ClientHelloReassemblyConfig {
                    max_records: 1,
                    ..config
                }
            ),
            ClientHelloHandshakePrefix::Invalid
        );
        let enormous = ClientHelloReassemblyConfig {
            max_handshake_size: usize::MAX,
            max_records: usize::MAX,
            ..config
        };
        assert!(enormous.max_wire_size() < rama_utils::octets::mib(128));
    }

    #[test]
    fn malformed_records_and_optional_version_consistency() {
        let message = hello(0);
        for header in [
            vec![0x16, 3, 1, 0, 0],    // empty handshake record
            vec![0x16, 3, 1, 0x40, 1], // oversized plaintext record
            vec![0x17],
            vec![0x16, 2],
            vec![0x16, 3, 5],
        ] {
            let mut wire = record(&message[..2]);
            wire.extend_from_slice(&header);
            assert_matches!(
                parse_client_hello_handshake_prefix(&wire),
                ClientHelloHandshakePrefix::Invalid
            );
        }
        let mut wire = record(&message[..2]);
        let mut second = record(&message[2..]);
        second[2] = 3;
        wire.extend(second);
        parse_client_hello_handshake(&wire).unwrap();
        assert_matches!(
            parse_client_hello_handshake_prefix_with_config(
                &wire,
                ClientHelloReassemblyConfig {
                    require_matching_record_version: true,
                    ..Default::default()
                }
            ),
            ClientHelloHandshakePrefix::Invalid
        );
    }

    #[test]
    fn first_message_boundary_and_complete_record_are_respected() {
        let message = hello(0);
        let mut payload = message.clone();
        payload.extend_from_slice(&[2, 0, 0, 0]);
        let wire = record(&payload);
        assert_matches!(
            parse_client_hello_handshake_prefix(&wire[..wire.len() - 1]),
            ClientHelloHandshakePrefix::Incomplete
        );
        assert_matches!(
            parse_client_hello_handshake_prefix(&wire),
            ClientHelloHandshakePrefix::Complete(_)
        );
        parse_client_hello_handshake(&wire).unwrap_err();
        let mut wire = fragments(&message, 3);
        wire.extend_from_slice(&[0x17, 3]); // a later partial record is irrelevant
        assert_matches!(
            parse_client_hello_handshake_prefix(&wire),
            ClientHelloHandshakePrefix::Complete(_)
        );
        parse_client_hello_handshake(&wire).unwrap_err();
        // A record cannot borrow handshake bytes from beyond its declared end.
        let mut wire = record(&message);
        wire[3..5].copy_from_slice(&2u16.to_be_bytes());
        assert_matches!(
            parse_client_hello_handshake_prefix(&wire),
            ClientHelloHandshakePrefix::Invalid
        );
    }

    #[test]
    fn large_hello_crosses_record_boundaries_under_default_limits() {
        let message = hello(60_000);
        let wire = fragments(&message, kib(16));
        let parsed = parse_client_hello_handshake(&wire).unwrap();
        assert_eq!(parsed.ext_server_name().unwrap().as_str(), "x.com");
        assert_eq!(parsed.ext_alpn().unwrap(), &[ApplicationProtocol::HTTP_2]);
    }

    fn body_with_extension(id: u16, value: &[u8]) -> Vec<u8> {
        let mut body = ch_record_body_prefix();
        body.extend_from_slice(&u16::try_from(value.len() + 4).unwrap().to_be_bytes());
        body.extend_from_slice(&id.to_be_bytes());
        body.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
        body.extend_from_slice(value);
        body
    }

    #[test]
    fn server_padding_request_requires_its_complete_u16_body() {
        for bytes in [0u16, 32, 16_384, u16::MAX] {
            let hello = parse_client_hello(&body_with_extension(
                ExtensionId::SERVER_PADDING_REQUEST.into(),
                &bytes.to_be_bytes(),
            ))
            .unwrap();
            assert!(matches!(
                hello.extensions(),
                [ClientHelloExtension::ServerPaddingRequest(actual)] if *actual == bytes
            ));
        }
        for body in [vec![], vec![0], vec![0, 1, 2]] {
            parse_client_hello(&body_with_extension(
                ExtensionId::SERVER_PADDING_REQUEST.into(),
                &body,
            ))
            .unwrap_err();
        }
    }

    #[test]
    fn typed_client_hello_extensions_reject_discarded_trailing_bytes() {
        let cases: &[(u16, &[u8])] = &[
            (0, b"\0\x08\0\0\x05x.com"),
            (10, &[0, 2, 0, 29]),
            (11, &[1, 0]),
            (13, &[0, 2, 8, 4]),
            (16, &[0, 3, 2, b'h', b'2']),
            (27, &[2, 0, 1]),
            (28, &[0x40, 0]),
            (34, &[0, 2, 8, 4]),
            (43, &[2, 3, 4]),
            (17513, &[0, 3, 2, b'h', b'2']),
            (17613, &[0, 3, 2, b'h', b'2']),
            (65037, &[1]),
        ];
        for &(id, value) in cases {
            let body = body_with_extension(id, value);
            assert_eq!(parse_client_hello(&body).unwrap().extensions().len(), 1);
            let mut trailing = value.to_vec();
            trailing.push(0xff);
            let body = body_with_extension(id, &trailing);
            assert!(parse_client_hello(&body).is_err(), "extension {id}");
            let framed = wrap_client_hello_handshake(&body);
            assert!(
                matches!(
                    parse_client_hello_handshake_prefix(&framed),
                    ClientHelloHandshakePrefix::Invalid
                ),
                "extension {id}"
            );
            assert!(
                matches!(
                    parse_client_hello_message_prefix(&framed[5..]),
                    ClientHelloHandshakePrefix::Invalid
                ),
                "extension {id}"
            );
        }
        let mut body = body_with_extension(0xbeef, &[1, 2]);
        let extension = [0, 43, 0, 3, 2, 3, 4];
        let offset = ch_record_body_prefix().len();
        body[offset..offset + 2].copy_from_slice(&13u16.to_be_bytes());
        body.extend_from_slice(&extension);
        assert_eq!(parse_client_hello(&body).unwrap().extensions().len(), 2);
    }

    #[test]
    fn client_supported_versions_uses_its_declared_vector_length() {
        for value in [&[3, 4][..], &[0], &[1, 3], &[4, 3, 4], &[2, 3, 4, 3, 3]] {
            assert!(
                parse_client_hello(&body_with_extension(43, value)).is_err(),
                "versions {value:?}"
            );
        }
    }

    #[test]
    fn sni_names_do_not_discard_unknown_or_truncated_nested_entries() {
        for value in [
            &[][..],
            &[0, 0],
            &[0, 3, 1, 0, 0],
            b"\0\x09\0\0\x05x.com\xff",
        ] {
            let body = body_with_extension(0, value);
            assert!(parse_client_hello(&body).is_err(), "SNI {value:?}");
            assert!(
                extract_sni_from_client_hello_record(&body).is_err(),
                "SNI peek {value:?}"
            );
        }
    }

    #[test]
    fn complete_hello_bodies_and_prefixes_do_not_discard_internal_trailers() {
        let mut body = ch_record_body_prefix();
        body.extend_from_slice(&[0, 0]);
        parse_client_hello(&body).unwrap();
        let framed = wrap_client_hello_handshake(&body);
        parse_client_hello_handshake(&framed).unwrap();
        let mut followed = framed;
        followed.push(0xff);
        parse_client_hello_handshake(&followed).unwrap_err();
        assert!(matches!(
            parse_client_hello_handshake_prefix(&followed),
            ClientHelloHandshakePrefix::Complete(_)
        ));
        assert!(matches!(
            parse_client_hello_message_prefix(&followed[5..]),
            ClientHelloHandshakePrefix::Complete(_)
        ));
        body.push(0xff);
        parse_client_hello(&body).unwrap_err();
        let framed = wrap_client_hello_handshake(&body);
        parse_client_hello_handshake(&framed).unwrap_err();
        assert!(matches!(
            parse_client_hello_handshake_prefix(&framed),
            ClientHelloHandshakePrefix::Invalid
        ));
        assert!(matches!(
            parse_client_hello_message_prefix(&framed[5..]),
            ClientHelloHandshakePrefix::Invalid
        ));
    }

    #[test]
    fn test_parse_tls_extension_sni_hostname() {
        let test_cases = [
            ("", None),
            ("\x00", None),
            ("\x00\x00\x05x.com", Some(Domain::from_static("x.com"))),
            (
                "\x00\x00\x10fp.ramaproxy.org",
                Some(Domain::from_static("fp.ramaproxy.org")),
            ),
            ("\x00\x00\x11fp.ramaproxy.org", None),
            ("\x01\x00\x10fp.ramaproxy.org", None),
            ("\x00\x00\x09127.0.0.1", None),
            ("\x00\x00\x276670:2e72:616d:6170:726f:7879:2e6f:7267", None),
        ];
        for (input, expected_output) in test_cases {
            let result = parse_tls_extension_sni_hostname(input.as_bytes());
            match expected_output {
                Some(domain) => assert_eq!(domain, result.unwrap().1),
                None => {
                    result.unwrap_err();
                }
            }
        }
    }

    #[test]
    fn test_parse_client_hello_zero_bytes_failure() {
        parse_client_hello(&[]).unwrap_err();
    }

    /// ClientHello record body (no TLS record / handshake header) up to
    /// and including the compression-methods field, with one TLS 1.3
    /// cipher and the null compression method. Callers append whatever
    /// extensions-section bytes they want to exercise.
    fn ch_record_body_prefix() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x03, 0x03]); // legacy_version = TLS 1.2
        v.extend_from_slice(&[0u8; 32]); // random
        v.push(0x00); // session_id length = 0
        v.extend_from_slice(&[0x00, 0x02]); // cipher_suites length = 2
        v.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        v.extend_from_slice(&[0x01, 0x00]); // compression: len 1, method null
        v
    }

    /// Wrap a ClientHello record body in the handshake header (ClientHello +
    /// 3-byte length) and TLS record header (handshake, TLS 1.0, 2-byte length).
    fn wrap_client_hello_handshake(body: &[u8]) -> Vec<u8> {
        let mut hs = Vec::new();
        hs.push(0x01);
        let blen = body.len();
        hs.extend_from_slice(&[
            ((blen >> 16) & 0xff) as u8,
            ((blen >> 8) & 0xff) as u8,
            (blen & 0xff) as u8,
        ]);
        hs.extend_from_slice(body);

        let mut rec = Vec::new();
        rec.extend_from_slice(&[0x16, 0x03, 0x01]);
        let hlen = hs.len();
        rec.extend_from_slice(&[((hlen >> 8) & 0xff) as u8, (hlen & 0xff) as u8]);
        rec.extend_from_slice(&hs);
        rec
    }

    /// Fail-fast prefix classifier: every strict prefix of a valid ClientHello
    /// handshake must be `Incomplete` — never a premature `Complete` (the
    /// compression-boundary `i.is_empty()` trap that would drop the extensions)
    /// and never `Invalid` — and the full record must be `Complete` with its
    /// extensions intact.
    #[test]
    fn client_hello_handshake_prefix_is_incomplete_until_complete() {
        let mut body = ch_record_body_prefix();
        body.extend_from_slice(&[0x00, 0x04]); // extensions total length = 4
        body.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]); // extended_master_secret, empty
        let record = wrap_client_hello_handshake(&body);

        for len in 1..record.len() {
            match parse_client_hello_handshake_prefix(&record[..len]) {
                ClientHelloHandshakePrefix::Incomplete => {}
                other => panic!("prefix of len {len} must be Incomplete, got {other:?}"),
            }
        }

        match parse_client_hello_handshake_prefix(&record) {
            ClientHelloHandshakePrefix::Complete(hello) => {
                assert_eq!(hello.extensions().len(), 1);
            }
            other => panic!("full record must be Complete, got {other:?}"),
        }
    }

    /// The classifier rejects (rather than waits on) a valid TLS record header
    /// wrapping a non-ClientHello handshake, and non-handshake records.
    #[test]
    fn client_hello_handshake_prefix_rejects_non_client_hello() {
        // record header (handshake, TLS 1.2, len 6) + handshake type 0x02.
        let non_ch = [
            0x16, 0x03, 0x03, 0x00, 0x06, 0x02, 0x00, 0x00, 0x02, 0xaa, 0xbb,
        ];
        assert_matches!(
            parse_client_hello_handshake_prefix(&non_ch),
            ClientHelloHandshakePrefix::Invalid,
        );

        // alert record (content type 0x15), never a handshake.
        let non_handshake = [0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00];
        assert_matches!(
            parse_client_hello_handshake_prefix(&non_handshake),
            ClientHelloHandshakePrefix::Invalid,
        );
    }

    /// A hello with no extensions section at all (legacy TLS 1.0/1.1
    /// shape) must still parse — with an empty extensions list.
    #[test]
    fn parse_client_hello_without_extensions_section() {
        let body = ch_record_body_prefix();
        let ch = parse_client_hello(&body).expect("legacy extensionless CH must parse");
        assert!(ch.extensions().is_empty());
        assert_eq!(ch.cipher_suites(), &[CipherSuite::TLS13_AES_128_GCM_SHA256]);
    }

    /// A hello whose extensions section is fully present parses with the
    /// extensions populated.
    #[test]
    fn parse_client_hello_with_complete_extensions() {
        let mut body = ch_record_body_prefix();
        body.extend_from_slice(&[0x00, 0x04]); // extensions total length = 4
        body.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]); // extended_master_secret, empty
        let ch = parse_client_hello(&body).expect("complete CH must parse");
        assert_eq!(ch.extensions().len(), 1);
    }

    /// Regression: a hello whose extensions section is *declared* but
    /// *truncated* in the buffer must NOT parse as an extension-less
    /// hello. Before the fix `opt(complete(length_data(...)))` swallowed
    /// the incompleteness and returned a CH with zero extensions —
    /// which made the MITM mirror a bare default ClientHello (no SNI /
    /// ALPN / supported_versions) that SNI-routed upstreams reject. The
    /// parse must instead fail so an incremental peeker keeps reading.
    #[test]
    fn parse_client_hello_truncated_extensions_section_is_error() {
        let mut body = ch_record_body_prefix();
        body.extend_from_slice(&[0x00, 0x0a]); // declares 10 extension bytes
        body.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]); // but only 4 present
        parse_client_hello(&body)
            .expect_err("truncated extensions must not parse as extension-less");
    }

    /// Same truncation contract through the full handshake-level parser
    /// (the path `PeekTlsClientHelloService` / the MITM actually use):
    /// a complete record parses with extensions; a truncated one errors.
    #[test]
    fn parse_client_hello_handshake_truncated_extensions_is_error() {
        // Build the CH body with a complete 1-extension section.
        let mut body = ch_record_body_prefix();
        body.extend_from_slice(&[0x00, 0x04]);
        body.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);

        let wrap_handshake = |body: &[u8]| -> Vec<u8> {
            let mut hs = Vec::new();
            // Handshake header: ClientHello (0x01) + 3-byte length.
            hs.push(0x01);
            let blen = body.len();
            hs.extend_from_slice(&[
                ((blen >> 16) & 0xff) as u8,
                ((blen >> 8) & 0xff) as u8,
                (blen & 0xff) as u8,
            ]);
            hs.extend_from_slice(body);
            // TLS record header: handshake (0x16) + version + 2-byte length.
            let mut rec = Vec::new();
            rec.extend_from_slice(&[0x16, 0x03, 0x01]);
            let hlen = hs.len();
            rec.extend_from_slice(&[((hlen >> 8) & 0xff) as u8, (hlen & 0xff) as u8]);
            rec.extend_from_slice(&hs);
            rec
        };

        let complete_record = wrap_handshake(&body);
        let ch =
            parse_client_hello_handshake(&complete_record).expect("complete record must parse");
        assert_eq!(ch.extensions().len(), 1);

        // Now lop off the last 2 bytes of the *body's* extension payload
        // so the declared extensions length outruns the buffer.
        let truncated_record = &complete_record[..complete_record.len() - 2];
        parse_client_hello_handshake(truncated_record)
            .expect_err("truncated handshake-level CH must not parse as extension-less");
    }

    #[test]
    fn test_parse_client_hello_pcap_dump_apple_itunes_bytes_success() {
        let client_hello = parse_client_hello(&[
            0x03, 0x03, 0x74, 0xbd, 0x2a, 0x45, 0x51, 0x29, 0x95, 0x42, 0x61, 0x17, 0xab, 0x20,
            0x8f, 0xf2, 0x30, 0xea, 0x72, 0x0f, 0x2e, 0xcd, 0x73, 0xff, 0xcb, 0xbc, 0x89, 0x10,
            0x46, 0xc8, 0xb7, 0x3c, 0x31, 0xf0, 0x20, 0x25, 0xea, 0x68, 0xb2, 0x13, 0x62, 0xf7,
            0x4b, 0x0f, 0x82, 0x57, 0xf6, 0xe9, 0x41, 0xc5, 0x28, 0x74, 0xa9, 0xf4, 0x80, 0x73,
            0x90, 0x4f, 0x85, 0xe7, 0xa7, 0xaa, 0x84, 0x37, 0xe8, 0xdf, 0x97, 0x00, 0x2a, 0x7a,
            0x7a, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2c, 0xc0, 0x2b, 0xcc, 0xa9, 0xc0,
            0x30, 0xc0, 0x2f, 0xcc, 0xa8, 0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x14, 0xc0, 0x13, 0x00,
            0x9d, 0x00, 0x9c, 0x00, 0x35, 0x00, 0x2f, 0xc0, 0x08, 0xc0, 0x12, 0x00, 0x0a, 0x01,
            0x00, 0x01, 0x89, 0x8a, 0x8a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x18, 0x00,
            0x00, 0x15, 0x69, 0x6e, 0x69, 0x74, 0x2e, 0x69, 0x74, 0x75, 0x6e, 0x65, 0x73, 0x2e,
            0x61, 0x70, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x17, 0x00, 0x00, 0xff,
            0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x0c, 0x00, 0x0a, 0x3a, 0x3a, 0x00, 0x1d,
            0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x10,
            0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31,
            0x2e, 0x31, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
            0x18, 0x00, 0x16, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x02, 0x03, 0x08,
            0x05, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01, 0x00, 0x12, 0x00,
            0x00, 0x00, 0x33, 0x00, 0x2b, 0x00, 0x29, 0x3a, 0x3a, 0x00, 0x01, 0x00, 0x00, 0x1d,
            0x00, 0x20, 0x49, 0xee, 0x60, 0xa1, 0x29, 0xc0, 0x44, 0x44, 0xc3, 0x02, 0x8a, 0x25,
            0x8c, 0x86, 0x64, 0xc3, 0x3a, 0xc0, 0xec, 0xbb, 0x6c, 0xe7, 0x93, 0xda, 0x51, 0xca,
            0xef, 0x59, 0xc9, 0xee, 0x41, 0x31, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x2b,
            0x00, 0x0b, 0x0a, 0xda, 0xda, 0x03, 0x04, 0x03, 0x03, 0x03, 0x02, 0x03, 0x01, 0x00,
            0x1b, 0x00, 0x03, 0x02, 0x00, 0x01, 0xda, 0xda, 0x00, 0x01, 0x00, 0x00, 0x15, 0x00,
            0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ])
        .expect("to parse");
        assert_eq!(
            client_hello.cipher_suites(),
            &[
                CipherSuite::from(0x7a7a),
                CipherSuite::TLS13_AES_128_GCM_SHA256,
                CipherSuite::TLS13_AES_256_GCM_SHA384,
                CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
                CipherSuite::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
                CipherSuite::TLS_RSA_WITH_3DES_EDE_CBC_SHA,
            ]
        );
        assert_eq!(client_hello.extensions().len(), 16);

        assert_eq_opaque_extension(
            &client_hello.extensions()[0],
            ExtensionId::from(0x8a8a),
            &[],
        );
        assert_eq_server_name_extension(
            &client_hello.extensions()[1],
            Some(&Domain::from_static("init.itunes.apple.com")),
        );
        assert_eq_opaque_extension(
            &client_hello.extensions()[2],
            ExtensionId::EXTENDED_MASTER_SECRET,
            &[],
        );
        assert_eq_opaque_extension(
            &client_hello.extensions()[3],
            ExtensionId::RENEGOTIATION_INFO,
            &[0x00],
        );
        assert_eq_supported_groups_extension(
            &client_hello.extensions()[4],
            &[
                SupportedGroup::from(0x3a3a),
                SupportedGroup::X25519,
                SupportedGroup::SECP256R1,
                SupportedGroup::SECP384R1,
                SupportedGroup::SECP521R1,
            ],
        );
        assert_eq_ec_point_formats_extension(
            &client_hello.extensions()[5],
            &[ECPointFormat::Uncompressed],
        );
        assert_eq_alpn_extension(
            &client_hello.extensions()[6],
            &[ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11],
        );
        assert_eq_opaque_extension(
            &client_hello.extensions()[7],
            ExtensionId::STATUS_REQUEST,
            &[0x01, 0x00, 0x00, 0x00, 0x00],
        );
        assert_eq_signature_algorithms_extension(
            &client_hello.extensions()[8],
            &[
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ECDSA_SHA1_Legacy,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::RSA_PKCS1_SHA1,
            ],
        );
        assert_eq_opaque_extension(
            &client_hello.extensions()[9],
            ExtensionId::SIGNED_CERTIFICATE_TIMESTAMP,
            &[],
        );
        assert_eq_opaque_extension(
            &client_hello.extensions()[10],
            ExtensionId::KEY_SHARE,
            &[
                0x00, 0x29, 0x3a, 0x3a, 0x00, 0x01, 0x00, 0x00, 0x1d, 0x00, 0x20, 0x49, 0xee, 0x60,
                0xa1, 0x29, 0xc0, 0x44, 0x44, 0xc3, 0x02, 0x8a, 0x25, 0x8c, 0x86, 0x64, 0xc3, 0x3a,
                0xc0, 0xec, 0xbb, 0x6c, 0xe7, 0x93, 0xda, 0x51, 0xca, 0xef, 0x59, 0xc9, 0xee, 0x41,
                0x31,
            ],
        );
        assert_eq_opaque_extension(
            &client_hello.extensions()[11],
            ExtensionId::PSK_KEY_EXCHANGE_MODES,
            &[0x01, 0x01],
        );
        assert_eq_supported_versions_extension(
            &client_hello.extensions()[12],
            &[
                ProtocolVersion::from(0xdada),
                ProtocolVersion::TLSv1_3,
                ProtocolVersion::TLSv1_2,
                ProtocolVersion::TLSv1_1,
                ProtocolVersion::TLSv1_0,
            ],
        );
        assert_eq_supported_certificate_compression_extension(
            &client_hello.extensions()[13],
            &[CertificateCompressionAlgorithm::Zlib],
        );
        assert_eq_opaque_extension(
            &client_hello.extensions()[14],
            ExtensionId::from(0xdada), // GREASE
            &[0x00],
        );
        assert_eq_opaque_extension(
            &client_hello.extensions()[15],
            ExtensionId::from(0x0015), // padding
            &[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00,
            ],
        );
    }

    fn assert_eq_opaque_extension(
        ext: &ClientHelloExtension,
        expected_id: ExtensionId,
        expected_data: &[u8],
    ) {
        match ext {
            ClientHelloExtension::Opaque { id, data } => {
                assert_eq!(*id, expected_id);
                assert_eq!(data, expected_data);
            }
            other => {
                panic!("unexpected extension: {other:?}");
            }
        }
    }

    fn assert_eq_server_name_extension(
        ext: &ClientHelloExtension,
        expected_domain: Option<&Domain>,
    ) {
        match ext {
            ClientHelloExtension::ServerName(domain) => {
                assert_eq!(domain.as_ref(), expected_domain);
            }
            other => {
                panic!("unexpected extension: {other:?}");
            }
        }
    }

    fn assert_eq_supported_groups_extension(
        ext: &ClientHelloExtension,
        expected_groups: &[SupportedGroup],
    ) {
        match ext {
            ClientHelloExtension::SupportedGroups(groups) => {
                assert_eq!(groups, expected_groups);
            }
            other => {
                panic!("unexpected extension: {other:?}");
            }
        }
    }

    fn assert_eq_ec_point_formats_extension(
        ext: &ClientHelloExtension,
        expected_ec_point_formats: &[ECPointFormat],
    ) {
        match ext {
            ClientHelloExtension::ECPointFormats(points) => {
                assert_eq!(points, expected_ec_point_formats);
            }
            other => {
                panic!("unexpected extension: {other:?}");
            }
        }
    }

    fn assert_eq_alpn_extension(
        ext: &ClientHelloExtension,
        expected_alpn_list: &[ApplicationProtocol],
    ) {
        match ext {
            ClientHelloExtension::ApplicationLayerProtocolNegotiation(alpn_list) => {
                assert_eq!(alpn_list, expected_alpn_list);
            }
            other => {
                panic!("unexpected extension: {other:?}");
            }
        }
    }

    fn assert_eq_signature_algorithms_extension(
        ext: &ClientHelloExtension,
        expected_signature_algorithms: &[SignatureScheme],
    ) {
        match ext {
            ClientHelloExtension::SignatureAlgorithms(algorithms) => {
                assert_eq!(algorithms, expected_signature_algorithms);
            }
            other => {
                panic!("unexpected extension: {other:?}");
            }
        }
    }

    fn assert_eq_supported_versions_extension(
        ext: &ClientHelloExtension,
        expected_version_list: &[ProtocolVersion],
    ) {
        match ext {
            ClientHelloExtension::SupportedVersions(version_list) => {
                assert_eq!(version_list, expected_version_list);
            }
            other => {
                panic!("unexpected extension: {other:?}");
            }
        }
    }

    fn assert_eq_supported_certificate_compression_extension(
        ext: &ClientHelloExtension,
        expected_certificate_compression: &[CertificateCompressionAlgorithm],
    ) {
        match ext {
            ClientHelloExtension::CertificateCompression(algorithms) => {
                assert_eq!(algorithms, expected_certificate_compression);
            }
            other => {
                panic!("unexpected extension: {other:?}");
            }
        }
    }

    #[test]
    fn test_extract_sni_from_client_hello_handshake() {
        #[expect(clippy::single_element_loop)]
        for (content, expected_sni) in [(
            &[
                0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03, 0x02, 0x15, 0xfd,
                0xe2, 0x92, 0xc0, 0x46, 0x9f, 0x92, 0xbe, 0xd7, 0xe9, 0x1a, 0x3c, 0x50, 0x5e, 0x55,
                0x49, 0x17, 0xa6, 0xf8, 0xa5, 0xca, 0xa4, 0x6d, 0x60, 0xcc, 0xea, 0xf7, 0x25, 0xf0,
                0x6e, 0x20, 0x41, 0x20, 0x18, 0x66, 0x5c, 0xae, 0x08, 0xb0, 0x10, 0x96, 0x3c, 0xad,
                0xb4, 0x13, 0xe1, 0x92, 0xce, 0x96, 0xad, 0x9d, 0x45, 0x05, 0xb7, 0xa6, 0x4c, 0x01,
                0x71, 0x08, 0x74, 0x0d, 0x1f, 0x35, 0x00, 0x2a, 0x3a, 0x3a, 0x13, 0x01, 0x13, 0x02,
                0x13, 0x03, 0xc0, 0x2c, 0xc0, 0x2b, 0xcc, 0xa9, 0xc0, 0x30, 0xc0, 0x2f, 0xcc, 0xa8,
                0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x14, 0xc0, 0x13, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x35,
                0x00, 0x2f, 0xc0, 0x08, 0xc0, 0x12, 0x00, 0x0a, 0x01, 0x00, 0x01, 0x89, 0xda, 0xda,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x12, 0x00, 0x00, 0x0f, 0x6f, 0x6e, 0x65,
                0x2e, 0x6f, 0x6e, 0x65, 0x2e, 0x6f, 0x6e, 0x65, 0x2e, 0x6f, 0x6e, 0x65, 0x00, 0x17,
                0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x0c, 0x00, 0x0a, 0xfa,
                0xfa, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x02, 0x01,
                0x00, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x16,
                0x00, 0x14, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x08, 0x05,
                0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01, 0x00, 0x12, 0x00, 0x00, 0x00, 0x33,
                0x00, 0x2b, 0x00, 0x29, 0xfa, 0xfa, 0x00, 0x01, 0x00, 0x00, 0x1d, 0x00, 0x20, 0x7c,
                0xe1, 0xc6, 0xc2, 0x01, 0x69, 0x42, 0xba, 0x2b, 0xec, 0x07, 0x2f, 0x04, 0xbd, 0xb6,
                0x2a, 0x7e, 0x04, 0x6b, 0x96, 0x98, 0x51, 0x4e, 0x80, 0xb3, 0x2a, 0x4c, 0x4f, 0x1f,
                0x39, 0x82, 0x2b, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x2b, 0x00, 0x0b, 0x0a,
                0x6a, 0x6a, 0x03, 0x04, 0x03, 0x03, 0x03, 0x02, 0x03, 0x01, 0x00, 0x1b, 0x00, 0x03,
                0x02, 0x00, 0x01, 0x3a, 0x3a, 0x00, 0x01, 0x00, 0x00, 0x15, 0x00, 0xd3, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            Domain::from_static("one.one.one.one"),
        )] {
            let domain = extract_sni_from_client_hello_handshake(content).unwrap();
            assert_eq!(Some(expected_sni), domain);
        }
    }

    #[test]
    fn test_extract_sni_from_client_hello_record() {
        #[expect(clippy::single_element_loop)]
        for (content, expected_sni) in [(
            &[
                0x03, 0x03, 0x74, 0xbd, 0x2a, 0x45, 0x51, 0x29, 0x95, 0x42, 0x61, 0x17, 0xab, 0x20,
                0x8f, 0xf2, 0x30, 0xea, 0x72, 0x0f, 0x2e, 0xcd, 0x73, 0xff, 0xcb, 0xbc, 0x89, 0x10,
                0x46, 0xc8, 0xb7, 0x3c, 0x31, 0xf0, 0x20, 0x25, 0xea, 0x68, 0xb2, 0x13, 0x62, 0xf7,
                0x4b, 0x0f, 0x82, 0x57, 0xf6, 0xe9, 0x41, 0xc5, 0x28, 0x74, 0xa9, 0xf4, 0x80, 0x73,
                0x90, 0x4f, 0x85, 0xe7, 0xa7, 0xaa, 0x84, 0x37, 0xe8, 0xdf, 0x97, 0x00, 0x2a, 0x7a,
                0x7a, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2c, 0xc0, 0x2b, 0xcc, 0xa9, 0xc0,
                0x30, 0xc0, 0x2f, 0xcc, 0xa8, 0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x14, 0xc0, 0x13, 0x00,
                0x9d, 0x00, 0x9c, 0x00, 0x35, 0x00, 0x2f, 0xc0, 0x08, 0xc0, 0x12, 0x00, 0x0a, 0x01,
                0x00, 0x01, 0x89, 0x8a, 0x8a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x18, 0x00,
                0x00, 0x15, 0x69, 0x6e, 0x69, 0x74, 0x2e, 0x69, 0x74, 0x75, 0x6e, 0x65, 0x73, 0x2e,
                0x61, 0x70, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x17, 0x00, 0x00, 0xff,
                0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x0c, 0x00, 0x0a, 0x3a, 0x3a, 0x00, 0x1d,
                0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x10,
                0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31,
                0x2e, 0x31, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
                0x18, 0x00, 0x16, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x02, 0x03, 0x08,
                0x05, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01, 0x00, 0x12, 0x00,
                0x00, 0x00, 0x33, 0x00, 0x2b, 0x00, 0x29, 0x3a, 0x3a, 0x00, 0x01, 0x00, 0x00, 0x1d,
                0x00, 0x20, 0x49, 0xee, 0x60, 0xa1, 0x29, 0xc0, 0x44, 0x44, 0xc3, 0x02, 0x8a, 0x25,
                0x8c, 0x86, 0x64, 0xc3, 0x3a, 0xc0, 0xec, 0xbb, 0x6c, 0xe7, 0x93, 0xda, 0x51, 0xca,
                0xef, 0x59, 0xc9, 0xee, 0x41, 0x31, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x2b,
                0x00, 0x0b, 0x0a, 0xda, 0xda, 0x03, 0x04, 0x03, 0x03, 0x03, 0x02, 0x03, 0x01, 0x00,
                0x1b, 0x00, 0x03, 0x02, 0x00, 0x01, 0xda, 0xda, 0x00, 0x01, 0x00, 0x00, 0x15, 0x00,
                0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
            Domain::from_static("init.itunes.apple.com"),
        )] {
            let domain = extract_sni_from_client_hello_record(content).unwrap();
            assert_eq!(Some(expected_sni), domain);
        }
    }

    #[test]
    fn parse_alps_from_client_hello() {
        #[expect(clippy::single_element_loop)]
        for (content, expected_alps) in [(
            &[
                0x3, 0x3, 0x16, 0xbc, 0xa5, 0xcd, 0xa6, 0xa, 0x97, 0x8f, 0xde, 0x13, 0x7f, 0x5e,
                0x84, 0x1b, 0x3f, 0x27, 0x4c, 0x1b, 0xc7, 0x5d, 0x31, 0xf1, 0xb7, 0x67, 0x6a, 0xb3,
                0xc9, 0x11, 0xa2, 0x96, 0x6, 0x58, 0x20, 0x68, 0x1e, 0x6c, 0x75, 0x5, 0xa1, 0x3b,
                0x62, 0x29, 0xc8, 0x29, 0x57, 0xe8, 0x45, 0x97, 0x95, 0x24, 0x6f, 0xc3, 0xba, 0x6c,
                0xd5, 0x46, 0xca, 0xff, 0x77, 0x4b, 0x25, 0xfd, 0x2b, 0x69, 0xa9, 0x0, 0x20, 0x8a,
                0x8a, 0x13, 0x1, 0x13, 0x2, 0x13, 0x3, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0,
                0x30, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x13, 0xc0, 0x14, 0x0, 0x9c, 0x0, 0x9d, 0x0,
                0x2f, 0x0, 0x35, 0x1, 0x0, 0x6, 0x69, 0x4a, 0x4a, 0x0, 0x0, 0x0, 0x2d, 0x0, 0x2,
                0x1, 0x1, 0x0, 0xd, 0x0, 0x12, 0x0, 0x10, 0x4, 0x3, 0x8, 0x4, 0x4, 0x1, 0x5, 0x3,
                0x8, 0x5, 0x5, 0x1, 0x8, 0x6, 0x6, 0x1, 0x0, 0x17, 0x0, 0x0, 0x0, 0x1b, 0x0, 0x3,
                0x2, 0x0, 0x2, 0x0, 0xb, 0x0, 0x2, 0x1, 0x0, 0x0, 0x5, 0x0, 0x5, 0x1, 0x0, 0x0,
                0x0, 0x0, 0x0, 0xa, 0x0, 0xc, 0x0, 0xa, 0x2a, 0x2a, 0x11, 0xec, 0x0, 0x1d, 0x0,
                0x17, 0x0, 0x18, 0xfe, 0xd, 0x0, 0xda, 0x0, 0x0, 0x1, 0x0, 0x1, 0x43, 0x0, 0x20,
                0xee, 0xaa, 0x32, 0x96, 0x85, 0x85, 0x5b, 0xfd, 0xd4, 0xc8, 0x60, 0xb0, 0xd1, 0xfd,
                0x20, 0x6b, 0x59, 0x60, 0x48, 0xa2, 0xff, 0x5c, 0x97, 0xae, 0x61, 0x4e, 0x34, 0xb2,
                0xe8, 0x28, 0x98, 0x7f, 0x0, 0xb0, 0x58, 0x18, 0x34, 0x1e, 0x5c, 0x9f, 0xe6, 0x1c,
                0x45, 0x5e, 0x7d, 0x22, 0xe4, 0x89, 0x36, 0xef, 0xdd, 0x77, 0xbe, 0xdd, 0xff, 0x2f,
                0x5e, 0x86, 0xed, 0x23, 0xaa, 0xf9, 0xec, 0x3b, 0x1, 0xee, 0xe8, 0xbf, 0x89, 0xe,
                0x39, 0xf2, 0x2f, 0x45, 0xb6, 0x70, 0x2c, 0x6a, 0x9f, 0xe, 0x10, 0xa, 0x9a, 0xe7,
                0x1a, 0xa8, 0xa4, 0xeb, 0x46, 0x3, 0x7b, 0x82, 0xa2, 0xf4, 0x1a, 0x83, 0x6a, 0x67,
                0x29, 0x30, 0x8e, 0x9c, 0x28, 0x46, 0xcd, 0xa1, 0x66, 0x7f, 0x3e, 0x6a, 0xe2, 0x53,
                0x2d, 0x17, 0xda, 0xab, 0x73, 0xe, 0xe, 0xec, 0x6, 0xbc, 0x19, 0x17, 0x91, 0x45,
                0x82, 0x95, 0xfa, 0x9d, 0x5c, 0x4c, 0xb, 0xdb, 0x7, 0xa2, 0x8d, 0xd4, 0x6, 0x21,
                0x8b, 0x1d, 0x64, 0x63, 0x3, 0xc0, 0x7d, 0x42, 0x29, 0x84, 0x0, 0xbb, 0xa2, 0x6f,
                0xf6, 0x3a, 0x54, 0x5c, 0xb8, 0xda, 0x44, 0x63, 0xa9, 0x54, 0x1a, 0x63, 0xde, 0xd9,
                0x93, 0x77, 0x88, 0x91, 0xc3, 0x21, 0xdc, 0x36, 0xc2, 0xbc, 0x4e, 0xbe, 0x3a, 0x2,
                0x37, 0x65, 0xa3, 0x67, 0x10, 0x3d, 0xbf, 0x91, 0xbe, 0x61, 0x51, 0x16, 0xac, 0xdd,
                0xb9, 0x50, 0xfa, 0x21, 0x65, 0x7a, 0x4f, 0x76, 0x2d, 0x35, 0xa, 0xf2, 0x7c, 0x19,
                0x0, 0x10, 0x0, 0xe, 0x0, 0xc, 0x2, 0x68, 0x32, 0x8, 0x68, 0x74, 0x74, 0x70, 0x2f,
                0x31, 0x2e, 0x31, 0x0, 0x12, 0x0, 0x0, 0x0, 0x0, 0x0, 0x12, 0x0, 0x10, 0x0, 0x0,
                0xd, 0x77, 0x69, 0x6b, 0x69, 0x70, 0x65, 0x64, 0x69, 0x61, 0x2e, 0x6f, 0x72, 0x67,
                0xff, 0x1, 0x0, 0x1, 0x0, 0x44, 0xcd, 0x0, 0x5, 0x0, 0x3, 0x2, 0x68, 0x32, 0x0,
                0x33, 0x4, 0xef, 0x4, 0xed, 0x2a, 0x2a, 0x0, 0x1, 0x0, 0x11, 0xec, 0x4, 0xc0, 0x5e,
                0xa8, 0x36, 0x55, 0x26, 0xa9, 0x33, 0x2c, 0x4b, 0x51, 0x20, 0xa9, 0x9b, 0x27, 0x8a,
                0x5a, 0x55, 0x28, 0xc, 0xea, 0x1, 0x8d, 0x96, 0x2f, 0x8, 0x1c, 0x95, 0xd, 0x51,
                0x1, 0x2, 0x96, 0x9, 0xde, 0x78, 0x26, 0xc8, 0x92, 0x4a, 0x46, 0xa4, 0x5e, 0xf5,
                0xcb, 0x49, 0xb9, 0xf0, 0x2c, 0x50, 0x57, 0x3e, 0xe6, 0x97, 0x87, 0x19, 0xf3, 0xac,
                0xfb, 0x7b, 0x87, 0xdb, 0x20, 0x47, 0x58, 0x2c, 0x62, 0x45, 0x98, 0xc1, 0xf8, 0xd4,
                0x1, 0x3d, 0xcb, 0x93, 0x90, 0x22, 0x24, 0xf9, 0x9, 0x8a, 0x49, 0x66, 0x69, 0x3a,
                0x32, 0x19, 0xb7, 0x13, 0x1a, 0xd9, 0xc2, 0xad, 0xd7, 0x18, 0xcf, 0xf6, 0xc7, 0x99,
                0x23, 0xc8, 0x85, 0x41, 0xc6, 0x8e, 0xcb, 0xcc, 0xc2, 0x17, 0x2c, 0xb8, 0xb2, 0xb1,
                0xc9, 0xb6, 0x26, 0x60, 0xa9, 0xf0, 0x2d, 0x3b, 0x6a, 0x2d, 0xc5, 0x46, 0x61, 0xcb,
                0x18, 0xbb, 0x85, 0xe0, 0x47, 0x3e, 0xe7, 0x53, 0xca, 0xba, 0x14, 0x10, 0x6, 0xa2,
                0xc3, 0xd5, 0x40, 0x87, 0x44, 0x48, 0xf8, 0x1, 0x2b, 0xf2, 0x10, 0x3e, 0x85, 0x78,
                0x17, 0xbf, 0xa5, 0x88, 0xe9, 0xf2, 0x86, 0x4a, 0x80, 0x2, 0x40, 0x28, 0x9b, 0x3,
                0x49, 0x15, 0x80, 0x61, 0x9a, 0x8d, 0x76, 0xb7, 0x1c, 0x77, 0x4, 0x6d, 0x45, 0xb3,
                0x96, 0xe1, 0x7, 0x50, 0xb8, 0x34, 0xe, 0xda, 0xf, 0x6b, 0xb5, 0xaf, 0xdb, 0x6,
                0x2f, 0xa0, 0xc5, 0xb1, 0xcb, 0xcc, 0x54, 0x61, 0xc, 0x95, 0x23, 0x4a, 0x17, 0x1b,
                0x59, 0x26, 0x18, 0xb1, 0x78, 0x4, 0xc5, 0x61, 0xd8, 0x47, 0x68, 0xae, 0xf1, 0x24,
                0x98, 0x84, 0x53, 0x80, 0x62, 0x8c, 0xb6, 0x72, 0xa9, 0xd, 0xe4, 0x7f, 0xb9, 0xc3,
                0x31, 0x79, 0x9c, 0xa0, 0xfa, 0xa1, 0x17, 0xe5, 0x52, 0xa5, 0xa6, 0x35, 0x6f, 0x4d,
                0xb3, 0x79, 0xd4, 0x6c, 0x69, 0xb3, 0xb5, 0xa1, 0xa8, 0xcc, 0xb6, 0x70, 0xe9, 0x48,
                0x11, 0xe0, 0x67, 0xde, 0xfc, 0x61, 0x6, 0x92, 0x9c, 0xa6, 0x2b, 0x75, 0xc7, 0x14,
                0x73, 0xcf, 0x68, 0x31, 0x51, 0x2, 0xc, 0xda, 0x64, 0xb7, 0x74, 0xc3, 0x90, 0x4,
                0x14, 0xc2, 0xf1, 0x72, 0x79, 0xf5, 0x47, 0x93, 0x8f, 0xf1, 0x2e, 0xc0, 0xbc, 0x5,
                0x5d, 0xa7, 0x7d, 0x4, 0x5b, 0x8c, 0xf, 0xe9, 0x1, 0x21, 0x12, 0x17, 0x80, 0xdb,
                0x84, 0x73, 0xe5, 0xcb, 0x74, 0x4a, 0x83, 0xb5, 0xeb, 0x77, 0x5b, 0x8a, 0xb5, 0x10,
                0x3b, 0xd, 0x7f, 0xc1, 0x42, 0xbf, 0x33, 0xe, 0xb2, 0x67, 0xc2, 0xd9, 0x3b, 0x1e,
                0x83, 0x8b, 0xc6, 0x19, 0xc4, 0xbb, 0x1c, 0x53, 0x3c, 0x23, 0x26, 0x5, 0x14, 0xdb,
                0x83, 0xf3, 0x20, 0x89, 0x91, 0x1c, 0x94, 0x23, 0x8b, 0x7a, 0xf8, 0x9a, 0x4e, 0x5f,
                0xda, 0xc, 0xd6, 0x46, 0x56, 0x11, 0x70, 0x6b, 0x40, 0xd8, 0xaa, 0xc8, 0x7c, 0xa0,
                0x22, 0x85, 0xcf, 0xc, 0x4c, 0x22, 0x6f, 0x68, 0x68, 0x35, 0x57, 0x99, 0x32, 0x82,
                0xa7, 0xe4, 0x8c, 0x1e, 0xc1, 0x57, 0xac, 0xc7, 0xaa, 0xc7, 0x9b, 0x77, 0x7e, 0x7d,
                0x96, 0xb3, 0x6c, 0xd5, 0x9c, 0x32, 0x67, 0xc8, 0xcd, 0x38, 0x21, 0x34, 0xd4, 0xcb,
                0xd4, 0xc8, 0xb9, 0x30, 0xf7, 0xe, 0x3f, 0xf0, 0xa1, 0xe5, 0xd8, 0x5, 0x57, 0x49,
                0xa6, 0xc0, 0xca, 0x63, 0x37, 0x85, 0x60, 0x8d, 0x74, 0xc9, 0x89, 0x93, 0x61, 0xc3,
                0x27, 0x48, 0x3f, 0x63, 0x20, 0x37, 0x54, 0x4f, 0x5c, 0x24, 0x74, 0x18, 0xb9, 0x43,
                0xef, 0xf2, 0x68, 0xc, 0xb1, 0xa5, 0xad, 0x5a, 0x84, 0x27, 0xa2, 0x8f, 0x31, 0xf8,
                0xa5, 0x45, 0xb6, 0x40, 0x21, 0x25, 0x7b, 0x16, 0xe7, 0x6d, 0x2e, 0x63, 0x9a, 0xf4,
                0x18, 0x2f, 0x70, 0x66, 0x18, 0xc6, 0x22, 0x41, 0x18, 0xb3, 0x1a, 0x22, 0x83, 0xa2,
                0x32, 0xaa, 0x1e, 0x81, 0xf4, 0x8c, 0x4e, 0xd4, 0x95, 0x2f, 0x23, 0xb6, 0x8d, 0x75,
                0x89, 0x3d, 0x9a, 0xc0, 0xe, 0x2b, 0x61, 0x6, 0xb0, 0x91, 0x4b, 0x46, 0x9d, 0x12,
                0x3c, 0x20, 0xd7, 0xb9, 0x1, 0x1c, 0x4b, 0x60, 0xda, 0xe2, 0xa, 0xdc, 0xe6, 0x62,
                0x42, 0x15, 0x82, 0xd2, 0x14, 0x16, 0xe5, 0x12, 0x9a, 0x20, 0x90, 0x23, 0xa4, 0x47,
                0xb6, 0x5f, 0xd4, 0x4, 0x23, 0x80, 0x48, 0xa2, 0xc7, 0xc9, 0x3f, 0x67, 0xc6, 0xe2,
                0x77, 0x2a, 0x71, 0xbc, 0x7b, 0xbd, 0xb8, 0x7e, 0xc9, 0x73, 0xd, 0x69, 0x88, 0x12,
                0x92, 0x44, 0x46, 0x4c, 0x3, 0x33, 0xa1, 0xd3, 0x81, 0xfe, 0xa6, 0x7b, 0xd2, 0x69,
                0x45, 0xa1, 0x67, 0x5a, 0x30, 0x35, 0xa1, 0x50, 0x7a, 0x40, 0x4, 0x10, 0x59, 0x83,
                0xc8, 0xbb, 0x7e, 0x55, 0x78, 0x1, 0xfb, 0x57, 0xe9, 0xd3, 0x63, 0x7, 0x4b, 0xcb,
                0xa2, 0xf7, 0x5c, 0xed, 0xd7, 0x29, 0x53, 0x16, 0xc6, 0x67, 0xf7, 0x4c, 0x4b, 0xf7,
                0x86, 0x24, 0x29, 0xa3, 0x8d, 0x3, 0x43, 0x55, 0xe9, 0x1, 0x6f, 0x17, 0x1b, 0x2f,
                0xec, 0x2f, 0x5a, 0xd1, 0x96, 0x86, 0xd2, 0xb8, 0x93, 0xe1, 0x25, 0x12, 0xf8, 0xb6,
                0xa7, 0xf1, 0xbb, 0xf4, 0x17, 0x46, 0xa, 0x10, 0xa1, 0xba, 0x80, 0x70, 0xd5, 0xa0,
                0x70, 0xfa, 0xd2, 0xbe, 0x56, 0x1a, 0x40, 0x17, 0x38, 0x2c, 0x3e, 0x70, 0x9f, 0xcc,
                0x62, 0xc6, 0x49, 0xb9, 0x25, 0x2c, 0x2b, 0x9a, 0x4f, 0x57, 0xb4, 0x1e, 0xd5, 0x3d,
                0xf9, 0x91, 0xa, 0x7b, 0xe8, 0x84, 0xd4, 0x6, 0x8d, 0x16, 0x44, 0xb0, 0x89, 0x82,
                0x14, 0xed, 0x13, 0x80, 0xcf, 0xf7, 0x40, 0x44, 0x6a, 0x68, 0xca, 0xfb, 0x80, 0x96,
                0x44, 0xa7, 0xd1, 0x26, 0xa4, 0x67, 0xc, 0x19, 0x31, 0x8, 0xb5, 0x9f, 0x32, 0x53,
                0x91, 0xd9, 0x39, 0xcf, 0xa3, 0x1c, 0x1a, 0xb0, 0x12, 0xe9, 0x9c, 0xa0, 0x25, 0x98,
                0x19, 0x36, 0x9c, 0x6e, 0x39, 0x3, 0xa7, 0x3e, 0x38, 0xc2, 0xa9, 0xba, 0x7, 0x70,
                0xb3, 0xcf, 0xab, 0x88, 0x59, 0x2b, 0x83, 0xbe, 0x97, 0xc7, 0xb8, 0x36, 0x5, 0xc9,
                0xdb, 0x88, 0x99, 0x25, 0x61, 0x72, 0x77, 0xd2, 0x3b, 0xe3, 0x95, 0x1f, 0x38, 0xa2,
                0x7f, 0xc5, 0x4a, 0xa0, 0x1a, 0x29, 0x68, 0x53, 0x5b, 0xc, 0xf2, 0x8a, 0xb4, 0xf5,
                0x12, 0xb6, 0x30, 0xb, 0x6, 0xcd, 0xe3, 0x41, 0x88, 0x57, 0x8b, 0x53, 0xc5, 0x8e,
                0xe8, 0xa5, 0x19, 0xb5, 0x26, 0x4a, 0xab, 0x97, 0x2, 0x7f, 0x73, 0x6c, 0x8c, 0x10,
                0x7e, 0x11, 0x41, 0x62, 0x85, 0xe4, 0xc4, 0xf, 0x70, 0x14, 0xcf, 0x1c, 0x4f, 0xec,
                0xe1, 0xc1, 0x5d, 0xd8, 0x94, 0x1b, 0x90, 0x32, 0xde, 0x6c, 0x70, 0xa5, 0x75, 0x33,
                0x2b, 0xb7, 0x72, 0xc5, 0x49, 0x52, 0xe3, 0xe9, 0x63, 0xc7, 0xe1, 0xb1, 0x9b, 0xb8,
                0x1d, 0xe6, 0x41, 0x75, 0xf3, 0x11, 0xa, 0x9e, 0xb3, 0x15, 0x73, 0x73, 0x61, 0xb3,
                0x11, 0x88, 0xf8, 0xa9, 0x74, 0x25, 0x0, 0xa4, 0xf5, 0xb5, 0x16, 0xbf, 0xbc, 0x4c,
                0xfd, 0x36, 0xb7, 0x1c, 0x60, 0x93, 0xbb, 0x75, 0x79, 0xde, 0x25, 0x18, 0x15, 0x4b,
                0x5d, 0x2, 0xb2, 0x6c, 0x31, 0x87, 0x17, 0xd4, 0xb0, 0x70, 0xcf, 0xb2, 0xb8, 0x24,
                0xb0, 0x2f, 0x4, 0x8b, 0xd, 0xa5, 0xf9, 0x59, 0x3e, 0xf8, 0x8f, 0x3b, 0x56, 0x95,
                0x26, 0x84, 0x2, 0xcb, 0x13, 0xab, 0x8f, 0xb, 0x97, 0xef, 0x49, 0xc, 0xb, 0x9,
                0x48, 0x32, 0xea, 0xaa, 0xff, 0x93, 0x5e, 0x7e, 0x32, 0x21, 0x62, 0x2, 0xc5, 0xc8,
                0x6b, 0xa3, 0xfc, 0x9c, 0x3a, 0x8, 0x4c, 0x83, 0xdb, 0x14, 0xa1, 0xb1, 0x6, 0x82,
                0xbb, 0xa9, 0x65, 0xe0, 0x60, 0x34, 0x11, 0x25, 0xce, 0xdd, 0xc6, 0x49, 0x7d, 0x6a,
                0x83, 0x4d, 0x4, 0x5c, 0xbf, 0xd9, 0xcb, 0x21, 0xd2, 0x7f, 0xb2, 0x6c, 0x92, 0xda,
                0x4c, 0x42, 0xaa, 0xd2, 0x75, 0x65, 0xf9, 0x19, 0xb5, 0xc1, 0xab, 0xd2, 0xb4, 0x61,
                0x6f, 0x5c, 0x36, 0x6, 0xb8, 0x38, 0xc8, 0xcb, 0x40, 0x1c, 0x53, 0x1, 0x83, 0x26,
                0x42, 0x1, 0x59, 0x5d, 0x59, 0x46, 0x9b, 0x90, 0x54, 0xcd, 0x2, 0x19, 0x8d, 0xab,
                0x30, 0x5f, 0x11, 0xd1, 0xa1, 0x4d, 0x59, 0x67, 0xeb, 0x5c, 0x99, 0x79, 0x34, 0x5c,
                0x20, 0x94, 0x4e, 0xba, 0x87, 0x75, 0xe4, 0x89, 0xce, 0xbd, 0xdc, 0x2b, 0x1a, 0xbc,
                0xa7, 0x36, 0x9b, 0xb8, 0x3, 0xd5, 0xb2, 0xbd, 0x58, 0x6, 0xc6, 0x5b, 0xa9, 0xdc,
                0x55, 0x81, 0xf0, 0x58, 0x7f, 0x96, 0xa5, 0x9e, 0xcd, 0x82, 0x4a, 0x6d, 0x5a, 0x69,
                0x8c, 0x2b, 0x49, 0x16, 0x27, 0x51, 0xa9, 0x7e, 0xf8, 0x8a, 0xf1, 0x94, 0xd8, 0x4f,
                0x66, 0x4b, 0xfd, 0x54, 0x47, 0xb8, 0x14, 0x5, 0xeb, 0x9b, 0xe5, 0x9e, 0x48, 0xc6,
                0xef, 0x5f, 0x38, 0xe1, 0x98, 0x2d, 0xa8, 0xb3, 0x97, 0xe2, 0x24, 0x7, 0xdc, 0x2f,
                0xf8, 0x5c, 0x7f, 0x8, 0x9a, 0x41, 0x4b, 0x67, 0xa8, 0x76, 0xb8, 0x14, 0xba, 0x3a,
                0x62, 0xf9, 0x35, 0x8, 0x43, 0xdd, 0x81, 0x35, 0xa2, 0x6, 0x70, 0x0, 0x1d, 0x0,
                0x20, 0xd3, 0x86, 0xf6, 0xe7, 0x26, 0x27, 0x50, 0xc3, 0x4c, 0xba, 0xb5, 0x9c, 0xff,
                0x86, 0xd1, 0x35, 0xd0, 0xb3, 0x97, 0xb5, 0x99, 0xf4, 0xbb, 0x86, 0xb2, 0x8, 0x21,
                0x27, 0xf2, 0x56, 0x88, 0x2, 0x0, 0x23, 0x0, 0x0, 0x0, 0x2b, 0x0, 0x7, 0x6, 0xda,
                0xda, 0x3, 0x4, 0x3, 0x3, 0xaa, 0xaa, 0x0, 0x1, 0x0,
            ],
            ClientHelloExtension::ApplicationSettings {
                protocols: vec![ApplicationProtocol::HTTP_2],
                new_codepoint: true,
            },
        )] {
            let client_hello = parse_client_hello(content).unwrap();
            let found_alps = client_hello
                .extensions()
                .iter()
                .find(|ext| {
                    ext.id() == ExtensionId::APPLICATION_SETTINGS
                        || ext.id() == ExtensionId::OLD_APPLICATION_SETTINGS
                })
                .unwrap();
            match (found_alps, expected_alps) {
                (
                    ClientHelloExtension::ApplicationSettings {
                        protocols: found_alps,
                        new_codepoint: found_new_codepoint,
                    },
                    ClientHelloExtension::ApplicationSettings {
                        protocols: expected_alps,
                        new_codepoint: expected_new_codepoint,
                    },
                ) => {
                    assert_eq!(expected_alps, *found_alps);
                    assert_eq!(expected_new_codepoint, *found_new_codepoint);
                }
                (found, expected) => panic!("unexpected ext {found:?}; expected: {expected:?}"),
            }
        }
    }
}
