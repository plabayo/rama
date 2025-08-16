//! Sec-WebSocket-Extensions header value types.
//!
//! More information:
//! <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Sec-WebSocket-Extensions>

use std::{fmt, str::FromStr, sync::Arc};

use rama_core::telemetry::tracing;
use rama_error::{ErrorExt, OpaqueError};
use rama_http_types::{HeaderName, HeaderValue};

use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader, util::csv};

/// The `Sec-Websocket-Extensions` header, containing one or multiple [`Extension`]s.
///
/// Read more about it in the [`Extension`] docs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecWebsocketExtensions(Vec<Extension>);

impl SecWebsocketExtensions {
    /// Create a new [`SecWebsocketExtensions`] headers value.
    pub fn new(extension: impl Into<Extension>) -> Self {
        Self(vec![extension.into()])
    }

    #[inline]
    /// Create a new [`SecWebsocketExtensions`] with [`Extension::PerMessageDeflate`],
    /// using the default [`PerMessageDeflateConfig`].
    #[must_use]
    pub fn per_message_deflate() -> Self {
        Self::per_message_deflate_with_config(Default::default())
    }

    #[inline]
    /// Create a new [`SecWebsocketExtensions`] with [`Extension::PerMessageDeflate`],
    /// using the provided [`PerMessageDeflateConfig`].
    #[must_use]
    pub fn per_message_deflate_with_config(config: PerMessageDeflateConfig) -> Self {
        Self::new(Extension::PerMessageDeflate(config))
    }
}

impl SecWebsocketExtensions {
    rama_utils::macros::generate_set_and_with! {
        /// Add an extra extension to the [`SecWebsocketExtensions`] header.
        pub fn extra_extension(mut self, ext: impl Into<Extension>) -> Self {
            self.0.push(ext.into());
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Add multiple extra extensions to the [`SecWebsocketExtensions`] header.
        pub fn extra_extensions(mut self, ext_it: impl IntoIterator<Item = impl Into<Extension>>) -> Self {
            self.0.extend(ext_it.into_iter().map(Into::into));
            self
        }
    }
}

impl SecWebsocketExtensions {
    #[must_use]
    /// Return a reference to the first [`Extension`]
    pub fn first(&self) -> &Extension {
        // assumption is that vec is never empty, due
        // to how we construct it!
        &self.0[0]
    }

    #[must_use]
    pub fn into_first(self) -> Extension {
        // assumption is that vec is never empty, due
        // to how we construct it!
        self.into_iter().next().unwrap()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Extension> {
        self.0.iter()
    }
}

impl IntoIterator for SecWebsocketExtensions {
    type Item = Extension;
    type IntoIter = std::vec::IntoIter<Extension>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<Item: Into<Extension>> FromIterator<Item> for SecWebsocketExtensions {
    fn from_iter<T: IntoIterator<Item = Item>>(iter: T) -> Self {
        let mut vec: Vec<_> = iter.into_iter().map(Into::into).collect();
        if vec.is_empty() {
            vec.push(Extension::Empty);
        }
        Self(vec)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// WebSocket extensions as specified in [RFC6455: section 9].
///
/// [RFC6455: section 9]: https://www.rfc-editor.org/rfc/rfc6455#section-9
pub enum Extension {
    /// Per-Message Compression Extensions (PMCE)
    /// as defined in [RFC7692]
    /// using the DEFLATE ([RFC1951]) algorithm.
    ///
    /// See details in the [`PerMessageDeflateConfig`] docs.
    ///
    /// [RFC7692]: https://www.rfc-editor.org/rfc/rfc7692.html
    /// [RFC1951]: https://www.rfc-editor.org/rfc/rfc1951.html
    PerMessageDeflate(PerMessageDeflateConfig),

    /// Empty Extension value
    Empty,

    /// An extension unknown to this library.
    ///
    /// Up to the user to parse and handle it appropriately, if at all.
    Unknown(Arc<str>),
}

impl Extension {
    #[must_use]
    /// Consume this instance into a [`SecWebsocketExtensions`]
    /// with a single extension value.
    pub fn into_header(self) -> SecWebsocketExtensions {
        SecWebsocketExtensions::new(self)
    }
}

impl From<Extension> for SecWebsocketExtensions {
    fn from(value: Extension) -> Self {
        Self::new(value)
    }
}

impl From<PerMessageDeflateConfig> for Extension {
    fn from(value: PerMessageDeflateConfig) -> Self {
        Self::PerMessageDeflate(value)
    }
}

impl From<PerMessageDeflateIdentifier> for Extension {
    fn from(value: PerMessageDeflateIdentifier) -> Self {
        Self::PerMessageDeflate(PerMessageDeflateConfig::from(value))
    }
}

rama_utils::macros::enums::enum_builder! {
    /// Possible identifiers used for PerMessageDeflate
    #[derive(Default)]
    @String
    pub enum PerMessageDeflateIdentifier {
        #[default]
        /// Standard identifier
        PerMessageDeflate => "permessage-deflate",
        /// Deprecated Identifier
        PerFrameDeflate => "perframe-deflate",
        /// Deprecated Identifier still used by WebKit (e.g. iOS)
        XWebKitDeflateFrame => "x-webkit-deflate-frame",
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PerMessageDeflateConfig {
    /// Identifier used (or to be used).
    ///
    /// When serializing the default one is to be used
    /// if none is specified.
    pub identifier: PerMessageDeflateIdentifier,

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

impl From<PerMessageDeflateIdentifier> for PerMessageDeflateConfig {
    fn from(identifier: PerMessageDeflateIdentifier) -> Self {
        Self {
            identifier,
            ..Default::default()
        }
    }
}

impl FromStr for Extension {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split(';').map(|s| s.trim());
        let identifier = parts
            .next()
            .ok_or_else(|| OpaqueError::from_display("empty WebSocket Extension is invalid"))?;
        if let Some(identifier) = PerMessageDeflateIdentifier::strict_parse(identifier) {
            let mut config = PerMessageDeflateConfig {
                identifier,
                ..Default::default()
            };
            for part in parts {
                if part.eq_ignore_ascii_case("server_no_context_takeover") {
                    if std::mem::replace(&mut config.server_no_context_takeover, true) {
                        return Err(OpaqueError::from_display(
                            "duplicate extension param: server_no_context_takeover",
                        ));
                    }
                } else if part.eq_ignore_ascii_case("client_no_context_takeover") {
                    if std::mem::replace(&mut config.client_no_context_takeover, true) {
                        return Err(OpaqueError::from_display(
                            "duplicate extension param: client_no_context_takeover",
                        ));
                    }
                } else if part.eq_ignore_ascii_case("server_max_window_bits") {
                    if config.server_max_window_bits.replace(0).is_some() {
                        return Err(OpaqueError::from_display(
                            "duplicate extension param: server_max_window_bits",
                        ));
                    }
                } else if part.eq_ignore_ascii_case("client_max_window_bits") {
                    if config.client_max_window_bits.replace(0).is_some() {
                        return Err(OpaqueError::from_display(
                            "duplicate extension param: client_max_window_bits",
                        ));
                    }
                } else if let Some((k, v)) = part.split_once('=') {
                    let k = k.trim();

                    // The value may be quoted (RFC7692)
                    let v = v.trim();
                    let v = v
                        .strip_prefix('"')
                        .and_then(|v| v.strip_suffix('"'))
                        .unwrap_or(v);
                    let v = v.trim();

                    if k.eq_ignore_ascii_case("server_max_window_bits") {
                        match v.trim().parse::<u8>() {
                            Ok(v) => {
                                if !(8..=15).contains(&v) {
                                    tracing::debug!(
                                        "fail per-message-deflate config value for server max windows bits: {v} not in [8,15] range"
                                    );
                                    return Err(OpaqueError::from_display(
                                        "invalid server max windows bits (OOB)",
                                    ));
                                }
                                if config.server_max_window_bits.replace(v).is_some() {
                                    return Err(OpaqueError::from_display(
                                        "duplicate extension param: server_max_window_bits",
                                    ));
                                }
                            }
                            Err(err) => {
                                tracing::debug!(
                                    "fail per-message-deflate config with invalid value for server max windows bits: {k} = {v}; err = {err}"
                                );
                                return Err(err.context("invalid per-message-deflate config value for server max windows bits"));
                            }
                        }
                    } else if k.eq_ignore_ascii_case("client_max_window_bits") {
                        match v.trim().parse::<u8>() {
                            Ok(v) => {
                                if !(8..=15).contains(&v) {
                                    tracing::debug!(
                                        "fail per-message-deflate config value for client max windows bits: {v} not in [8,15] range"
                                    );
                                    return Err(OpaqueError::from_display(
                                        "invalid client max windows bits (OOB)",
                                    ));
                                }
                                if config.client_max_window_bits.replace(v).is_some() {
                                    return Err(OpaqueError::from_display(
                                        "duplicate extension param: client_max_window_bits",
                                    ));
                                }
                            }
                            Err(err) => {
                                tracing::debug!(
                                    "fail per-message-deflate config with invalid value for client max windows bits: {k} = {v}; err = {err}"
                                );
                                return Err(err.context("invalid per-message-deflate config value for client max windows bits"));
                            }
                        }
                    } else {
                        tracing::debug!(
                            "fail per-message-deflate config with unknown permessage-deflate config parameter: {k} = {v}"
                        );
                        return Err(OpaqueError::from_display(
                            "unexpected value not expected for given key",
                        ));
                    }
                } else {
                    tracing::debug!(
                        "received unknown permessage-deflate config parameter part: {part}"
                    );
                    return Err(OpaqueError::from_display(
                        "unexpected key not expected for permessage-deflate config",
                    ));
                }
            }
            Ok(Self::PerMessageDeflate(config))
        } else {
            tracing::trace!(
                "received unknown extension with identifier: {identifier} (full: {s}); store as unkown"
            );
            Ok(Self::Unknown(s.into()))
        }
    }
}

impl fmt::Display for Extension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PerMessageDeflate(config) => {
                write!(f, "{}", config.identifier)?;
                if config.server_no_context_takeover {
                    write!(f, "; server_no_context_takeover")?
                }
                if let Some(log) = config.server_max_window_bits {
                    if log == 0 {
                        write!(f, "; server_max_window_bits")?
                    } else {
                        write!(f, "; server_max_window_bits={log}")?
                    }
                }
                if config.client_no_context_takeover {
                    write!(f, "; client_no_context_takeover")?
                }
                if let Some(log) = config.client_max_window_bits {
                    if log == 0 {
                        write!(f, "; client_max_window_bits")?
                    } else {
                        write!(f, "; client_max_window_bits={log}")?
                    }
                }
                Ok(())
            }
            Self::Empty => Ok(()), // nothing to do
            Self::Unknown(v) => write!(f, "{v}"),
        }
    }
}

impl TypedHeader for SecWebsocketExtensions {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::SEC_WEBSOCKET_EXTENSIONS
    }
}

impl HeaderDecode for SecWebsocketExtensions {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        let result: Result<Vec<_>, _> = values
            .flat_map(|value| {
                value.to_str().into_iter().flat_map(|string| {
                    string.split(',').filter_map(|x| match x.trim() {
                        "" => None,
                        y => match y.parse::<Extension>() {
                            Ok(ext) => Some(Ok(ext)),
                            Err(err) => {
                                tracing::debug!("fail extension '{y}' due to error: {err}");
                                Some(Err(Error::invalid()))
                            }
                        },
                    })
                })
            })
            .collect();
        let mut v = result?;
        if v.is_empty() {
            v.push(Extension::Empty);
        }
        Ok(Self(v))
    }
}

impl HeaderEncode for SecWebsocketExtensions {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        struct Format<F>(F);
        impl<F> fmt::Display for Format<F>
        where
            F: Fn(&mut fmt::Formatter<'_>) -> fmt::Result,
        {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                (self.0)(f)
            }
        }
        let s = format!(
            "{}",
            Format(|f: &mut fmt::Formatter<'_>| { csv::fmt_comma_delimited(&mut *f, self.iter()) })
        );
        values.extend(Some(HeaderValue::try_from(s).unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{test_decode, test_encode};
    use super::{
        Extension, PerMessageDeflateConfig, PerMessageDeflateIdentifier, SecWebsocketExtensions,
    };

    #[test]
    fn decode_sec_websocket_extensions() {
        for (name, input, expected_output) in [
            // Basic Valid Cases
            (
                "single extension",
                vec!["permessage-deflate"],
                Some(SecWebsocketExtensions::per_message_deflate()),
            ),
            (
                "valueless client_max_window_bits",
                vec!["permessage-deflate; client_max_window_bits"],
                Some(SecWebsocketExtensions::per_message_deflate_with_config(
                    PerMessageDeflateConfig {
                        client_max_window_bits: Some(0), // Assuming 0 is the sentinel for a valueless parameter
                        ..Default::default()
                    },
                )),
            ),
            (
                "x-webkit-deflate-frame identifier",
                vec!["x-webkit-deflate-frame"],
                Some(SecWebsocketExtensions::per_message_deflate_with_config(
                    PerMessageDeflateConfig {
                        identifier: super::PerMessageDeflateIdentifier::XWebKitDeflateFrame,
                        ..Default::default()
                    },
                )),
            ),
            // Multiple Parameters in a Single Header
            (
                "client and server no context takeover",
                vec!["permessage-deflate; client_no_context_takeover; server_no_context_takeover"],
                Some(SecWebsocketExtensions::per_message_deflate_with_config(
                    PerMessageDeflateConfig {
                        client_no_context_takeover: true,
                        server_no_context_takeover: true,
                        ..Default::default()
                    },
                )),
            ),
            (
                "valued client and server max window bits",
                vec!["permessage-deflate; client_max_window_bits=10; server_max_window_bits=11"],
                Some(SecWebsocketExtensions::per_message_deflate_with_config(
                    PerMessageDeflateConfig {
                        client_max_window_bits: Some(10),
                        server_max_window_bits: Some(11),
                        ..Default::default()
                    },
                )),
            ),
            (
                "all parameters mixed",
                vec![
                    "permessage-deflate; server_no_context_takeover; client_max_window_bits=12; client_no_context_takeover",
                ],
                Some(SecWebsocketExtensions::per_message_deflate_with_config(
                    PerMessageDeflateConfig {
                        server_no_context_takeover: true,
                        client_no_context_takeover: true,
                        client_max_window_bits: Some(12),
                        ..Default::default()
                    },
                )),
            ),
            // Multiple Header Values
            (
                "multiple headers, duplicates allowed",
                vec![
                    "permessage-deflate; client_no_context_takeover",
                    "x-webkit-deflate-frame",
                ],
                Some(
                    SecWebsocketExtensions::per_message_deflate_with_config(
                        PerMessageDeflateConfig {
                            client_no_context_takeover: true,
                            ..Default::default()
                        },
                    )
                    .with_extra_extension(Extension::PerMessageDeflate(
                        PerMessageDeflateConfig {
                            identifier: PerMessageDeflateIdentifier::XWebKitDeflateFrame,
                            ..Default::default()
                        },
                    )),
                ),
            ),
            (
                "multiple headers, preserve unknown extensions",
                vec![
                    "unknown-extension, another-one",
                    "permessage-deflate; server_max_window_bits=14",
                ],
                Some(
                    SecWebsocketExtensions::new(Extension::Unknown("unknown-extension".into()))
                        .with_extra_extension(Extension::Unknown("another-one".into()))
                        .with_extra_extension(Extension::PerMessageDeflate(
                            PerMessageDeflateConfig {
                                server_max_window_bits: Some(14),
                                ..Default::default()
                            },
                        )),
                ),
            ),
            // quoted value
            (
                "multiple headers, preserve unknown extensions",
                vec![
                    "unknown-extension, another-one",
                    "permessage-deflate; server_max_window_bits=\"14\"",
                ],
                Some(
                    SecWebsocketExtensions::new(Extension::Unknown("unknown-extension".into()))
                        .with_extra_extension(Extension::Unknown("another-one".into()))
                        .with_extra_extension(Extension::PerMessageDeflate(
                            PerMessageDeflateConfig {
                                server_max_window_bits: Some(14),
                                ..Default::default()
                            },
                        )),
                ),
            ),
            // Robustness: Whitespace and Case-Insensitivity
            (
                "leading/trailing whitespace",
                vec!["  permessage-deflate ; client_no_context_takeover  "],
                Some(SecWebsocketExtensions::per_message_deflate_with_config(
                    PerMessageDeflateConfig {
                        client_no_context_takeover: true,
                        ..Default::default()
                    },
                )),
            ),
            (
                "case-insensitive name and params",
                vec!["PerMessage-Deflate; Client_No_Context_Takeover; SERVER_MAX_WINDOW_BITS=8"],
                Some(SecWebsocketExtensions::per_message_deflate_with_config(
                    PerMessageDeflateConfig {
                        client_no_context_takeover: true,
                        server_max_window_bits: Some(8),
                        ..Default::default()
                    },
                )),
            ),
            // invalid duplicate extension parameters
            (
                "invalid duplicate client_max_window_bits",
                vec!["permessage-deflate; client_max_window_bits=15; client_max_window_bits=14"],
                None,
            ),
            (
                "invalid duplicate server_max_window_bits",
                vec!["permessage-deflate; server_max_window_bits=15; server_max_window_bits=14"],
                None,
            ),
            (
                "invalid duplicate client_max_window_bits w/o value",
                vec!["permessage-deflate; client_max_window_bits=15; client_max_window_bits"],
                None,
            ),
            (
                "invalid duplicate server_max_window_bits w/o value",
                vec!["permessage-deflate; server_max_window_bits=15; server_max_window_bits"],
                None,
            ),
            (
                "invalid duplicate server_no_context_takeover",
                vec![
                    "permessage-deflate; server_no_context_takeover; client_no_context_takeover; server_no_context_takeover",
                ],
                None,
            ),
            (
                "invalid duplicate client_no_context_takeover",
                vec![
                    "permessage-deflate; client_no_context_takeover; server_no_context_takeover; client_no_context_takeover",
                ],
                None,
            ),
            // weird edge cases: handled gracefully
            (
                "empty header",
                vec![""],
                Some(SecWebsocketExtensions::new(Extension::Empty)),
            ),
            (
                "whitespace only header",
                vec!["   "],
                Some(SecWebsocketExtensions::new(Extension::Empty)),
            ),
            (
                "unknown extension",
                vec!["super-zip"],
                Some(SecWebsocketExtensions::new(Extension::Unknown(
                    "super-zip".into(),
                ))),
            ),
            // edge cases invalid
            (
                "windows bits OOB: client: underflow",
                vec!["permessage-deflate; client_max_window_bits=7"],
                None,
            ),
            (
                "windows bits OOB: client: overflow",
                vec!["permessage-deflate; client_max_window_bits=16"],
                None,
            ),
            (
                "windows bits OOB: server: underflow",
                vec!["permessage-deflate; server_max_window_bits=7"],
                None,
            ),
            (
                "windows bits OOB: server: overflow",
                vec!["permessage-deflate; server_max_window_bits=16"],
                None,
            ),
            (
                "invalid parameter format",
                vec!["permessage-deflate; client_max_window_bits_15"],
                None,
            ),
            (
                "invalid parameter value",
                vec!["permessage-deflate; client_max_window_bits=abc"],
                None,
            ),
            (
                "parameter with empty value",
                vec!["permessage-deflate; client_max_window_bits="],
                None,
            ),
            // handled, but only due to a side effect, not something sensible
            (
                "malformed header with comma",
                vec!["permessage-deflate, client_max_window_bits"],
                Some(
                    SecWebsocketExtensions::per_message_deflate()
                        .with_extra_extension(Extension::Unknown("client_max_window_bits".into())),
                ),
            ),
            (
                "multiple conflicting headers",
                vec![
                    "permessage-deflate; client_max_window_bits=10",
                    "permessage-deflate; client_max_window_bits=11",
                ],
                Some(
                    SecWebsocketExtensions::per_message_deflate_with_config(
                        PerMessageDeflateConfig {
                            client_max_window_bits: Some(10),
                            ..Default::default()
                        },
                    )
                    .with_extra_extension(Extension::PerMessageDeflate(
                        PerMessageDeflateConfig {
                            client_max_window_bits: Some(11),
                            ..Default::default()
                        },
                    )),
                ),
            ),
        ] {
            assert_eq!(
                test_decode::<SecWebsocketExtensions>(&input),
                expected_output,
                "Failed test case: {name}",
            );
        }
    }

    #[test]
    fn encode_sec_websocket_extensions_extended() {
        for (name, input, expected_output) in [
            // Basic Cases
            (
                "default permessage-deflate",
                SecWebsocketExtensions::per_message_deflate(),
                "permessage-deflate",
            ),
            (
                "valueless client_max_window_bits (chromium style)",
                SecWebsocketExtensions::per_message_deflate_with_config(PerMessageDeflateConfig {
                    client_max_window_bits: Some(0), // Assuming 0 is the sentinel for a valueless parameter
                    ..Default::default()
                }),
                "permessage-deflate; client_max_window_bits",
            ),
            (
                "x-webkit-deflate-frame identifier (safari style)",
                SecWebsocketExtensions::per_message_deflate_with_config(PerMessageDeflateConfig {
                    identifier: PerMessageDeflateIdentifier::XWebKitDeflateFrame,
                    ..Default::default()
                }),
                "x-webkit-deflate-frame",
            ),
            // Boolean Flag Parameters
            (
                "client_no_context_takeover enabled",
                SecWebsocketExtensions::per_message_deflate_with_config(PerMessageDeflateConfig {
                    client_no_context_takeover: true,
                    ..Default::default()
                }),
                "permessage-deflate; client_no_context_takeover",
            ),
            (
                "server_no_context_takeover enabled",
                SecWebsocketExtensions::per_message_deflate_with_config(PerMessageDeflateConfig {
                    server_no_context_takeover: true,
                    ..Default::default()
                }),
                "permessage-deflate; server_no_context_takeover",
            ),
            (
                "both no_context_takeover flags enabled",
                SecWebsocketExtensions::per_message_deflate_with_config(PerMessageDeflateConfig {
                    client_no_context_takeover: true,
                    server_no_context_takeover: true,
                    ..Default::default()
                }),
                // The order might vary, so be prepared to accept other valid serializations
                // e.g., "permessage-deflate; server_no_context_takeover; client_no_context_takeover"
                "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
            ),
            // Valued Parameters
            (
                "specific client_max_window_bits",
                SecWebsocketExtensions::per_message_deflate_with_config(PerMessageDeflateConfig {
                    client_max_window_bits: Some(12),
                    ..Default::default()
                }),
                "permessage-deflate; client_max_window_bits=12",
            ),
            (
                "specific server_max_window_bits",
                SecWebsocketExtensions::per_message_deflate_with_config(PerMessageDeflateConfig {
                    server_max_window_bits: Some(10),
                    ..Default::default()
                }),
                "permessage-deflate; server_max_window_bits=10",
            ),
            // Complex Combinations
            (
                "all parameters configured",
                SecWebsocketExtensions::per_message_deflate_with_config(PerMessageDeflateConfig {
                    client_no_context_takeover: true,
                    server_no_context_takeover: true,
                    client_max_window_bits: Some(15),
                    server_max_window_bits: Some(15),
                    ..Default::default()
                }),
                // Again, the exact order of parameters might differ
                "permessage-deflate; server_no_context_takeover; server_max_window_bits=15; client_no_context_takeover; client_max_window_bits=15",
            ),
            (
                "mixed valued and boolean parameters",
                SecWebsocketExtensions::per_message_deflate_with_config(PerMessageDeflateConfig {
                    client_no_context_takeover: true,
                    server_max_window_bits: Some(11),
                    ..Default::default()
                }),
                "permessage-deflate; server_max_window_bits=11; client_no_context_takeover",
            ),
            (
                "webkit identifier with parameters",
                SecWebsocketExtensions::per_message_deflate_with_config(PerMessageDeflateConfig {
                    identifier: PerMessageDeflateIdentifier::XWebKitDeflateFrame,
                    client_max_window_bits: Some(10),
                    client_no_context_takeover: true,
                    ..Default::default()
                }),
                "x-webkit-deflate-frame; client_no_context_takeover; client_max_window_bits=10",
            ),
        ] {
            let headers = test_encode(input);
            assert_eq!(
                headers["sec-websocket-extensions"], expected_output,
                "Failed test case: {name}",
            );
        }
    }
}
