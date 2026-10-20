//! Legacy fields retain only facts that the overwrite schema actually recorded.
//! Each non-null field contributes a conventional weight of one with unknown
//! original history. Fields from separate requests are never joined together.

use crate::UserAgent;
use rama_core::telemetry::tracing;
use rama_http::Version;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

#[cfg(feature = "tls")]
use crate::profile::capture::tls::{TlsCapture, TlsCaptureLimits, TlsCaptureTransport};
use crate::profile::{
    capture::{
        completeness::ProfileCaptureCompleteness,
        headers::HeaderCapturePolicy,
        http2::{H2Capture, H2CaptureLimits},
        joint::{CaptureLevel, CapturedSlot, CapturedSlotKind, JointCapture, JointCaptureLimits},
        observation::{PreparedProfileCapture, ProfileCapture},
        pseudo_headers::PseudoHeaderCapture,
        runtime::RuntimeProfileCapture,
    },
    format::{
        canonical::{
            CanonicalDomain, CanonicalReader, CanonicalValue, CanonicalWriter, ProfileDataError,
            ValueId,
        },
        input::UserAgentProfileInput,
    },
    model::identity::{ConnectionContext, ProfileKey},
};

mod joint;

mod headers;
pub use headers::{LegacyHeaderCapture, LegacyHttpProtocol};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum LegacyField {
    H1Settings,
    H1Navigate,
    H1Fetch,
    H1Xhr,
    H1Form,
    H1Ws,
    H2Settings,
    H2Navigate,
    H2Fetch,
    H2Xhr,
    H2Form,
    H2Ws,
    TcpTls,
    WsTlsAlpn,
    JsWebApis,
    SourceInfo,
}

impl LegacyField {
    pub fn name(self) -> &'static str {
        match self {
            Self::H1Settings => "h1_settings",
            Self::H1Navigate => "h1_headers_navigate",
            Self::H1Fetch => "h1_headers_fetch",
            Self::H1Xhr => "h1_headers_xhr",
            Self::H1Form => "h1_headers_form",
            Self::H1Ws => "h1_headers_ws",
            Self::H2Settings => "h2_settings",
            Self::H2Navigate => "h2_headers_navigate",
            Self::H2Fetch => "h2_headers_fetch",
            Self::H2Xhr => "h2_headers_xhr",
            Self::H2Form => "h2_headers_form",
            Self::H2Ws => "h2_headers_ws",
            Self::TcpTls => "tls_client_hello",
            Self::WsTlsAlpn => "tls_ws_client_config_overwrites",
            Self::JsWebApis => "js_web_apis",
            Self::SourceInfo => "source_info",
        }
    }

    pub fn tag(self) -> u8 {
        match self {
            Self::H1Settings => 0,
            Self::H1Navigate => 1,
            Self::H1Fetch => 2,
            Self::H1Xhr => 3,
            Self::H1Form => 4,
            Self::H1Ws => 5,
            Self::H2Settings => 6,
            Self::H2Navigate => 7,
            Self::H2Fetch => 8,
            Self::H2Xhr => 9,
            Self::H2Form => 10,
            Self::H2Ws => 11,
            Self::TcpTls => 12,
            Self::WsTlsAlpn => 13,
            Self::JsWebApis => 14,
            Self::SourceInfo => 15,
        }
    }

    pub fn from_tag(tag: u8) -> Result<Self, ProfileDataError> {
        match tag {
            0 => Ok(Self::H1Settings),
            1 => Ok(Self::H1Navigate),
            2 => Ok(Self::H1Fetch),
            3 => Ok(Self::H1Xhr),
            4 => Ok(Self::H1Form),
            5 => Ok(Self::H1Ws),
            6 => Ok(Self::H2Settings),
            7 => Ok(Self::H2Navigate),
            8 => Ok(Self::H2Fetch),
            9 => Ok(Self::H2Xhr),
            10 => Ok(Self::H2Form),
            11 => Ok(Self::H2Ws),
            12 => Ok(Self::TcpTls),
            13 => Ok(Self::WsTlsAlpn),
            14 => Ok(Self::JsWebApis),
            15 => Ok(Self::SourceInfo),
            _ => Err(ProfileDataError::Invalid("legacy field")),
        }
    }

    pub fn protocol(self) -> Option<LegacyHttpProtocol> {
        match self {
            Self::H1Settings
            | Self::H1Navigate
            | Self::H1Fetch
            | Self::H1Xhr
            | Self::H1Form
            | Self::H1Ws => Some(LegacyHttpProtocol::Http1),
            Self::H2Settings
            | Self::H2Navigate
            | Self::H2Fetch
            | Self::H2Xhr
            | Self::H2Form
            | Self::H2Ws => Some(LegacyHttpProtocol::Http2),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub enum LegacyFieldValue {
    H1Settings {
        title_case_headers: bool,
    },
    Headers(LegacyHeaderCapture),
    H2Settings {
        pseudo: Option<PseudoHeaderCapture>,
        early: Option<H2Capture>,
    },
    #[cfg(feature = "tls")]
    TcpTls(TlsCapture),
    WsTlsAlpn(Option<Box<[Box<[u8]>]>>),
    Runtime(Box<RuntimeProfileCapture>),
}

#[derive(Debug, Clone, Serialize)]
pub struct LegacyFieldCapture {
    pub field: LegacyField,
    pub value: LegacyFieldValue,
}

fn nested(
    reader: &mut CanonicalReader<'_>,
    maximum: usize,
) -> Result<CanonicalValue, ProfileDataError> {
    let bytes = reader.bytes(maximum)?;
    Ok(CanonicalValue {
        id: ValueId(Sha256::digest(bytes).into()),
        bytes: bytes.into(),
    })
}

fn boolean(reader: &mut CanonicalReader<'_>) -> Result<bool, ProfileDataError> {
    match reader.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ProfileDataError::Invalid("legacy boolean")),
    }
}

impl LegacyFieldCapture {
    pub fn canonical(&self, maximum: usize) -> Result<CanonicalValue, ProfileDataError> {
        let mut writer = CanonicalWriter::new(CanonicalDomain::LegacyField, maximum)?;
        writer.u8(self.field.tag())?;
        match (&self.field, &self.value) {
            (LegacyField::H1Settings, LegacyFieldValue::H1Settings { title_case_headers }) => {
                writer.u8(u8::from(*title_case_headers))?
            }
            (
                LegacyField::H1Navigate
                | LegacyField::H1Fetch
                | LegacyField::H1Xhr
                | LegacyField::H1Form
                | LegacyField::H1Ws
                | LegacyField::H2Navigate
                | LegacyField::H2Fetch
                | LegacyField::H2Xhr
                | LegacyField::H2Form
                | LegacyField::H2Ws,
                LegacyFieldValue::Headers(headers),
            ) => {
                if self.field.protocol() != Some(headers.protocol) {
                    return Err(ProfileDataError::Invalid("legacy header protocol"));
                }
                if headers
                    .fields
                    .iter()
                    .any(|field| field.representation.is_some())
                {
                    return Err(ProfileDataError::Invalid("legacy QPACK representation"));
                }
                writer.bytes(&headers.canonical(maximum)?.bytes)?;
            }
            (LegacyField::H2Settings, LegacyFieldValue::H2Settings { pseudo, early }) => {
                writer.u8(u8::from(pseudo.is_some()))?;
                if let Some(pseudo) = pseudo {
                    if pseudo.version != Version::HTTP_2 {
                        return Err(ProfileDataError::Invalid("legacy pseudo-header protocol"));
                    }
                    writer.bytes(&pseudo.canonical(maximum)?.bytes)?;
                }
                writer.u8(u8::from(early.is_some()))?;
                if let Some(early) = early {
                    writer.bytes(
                        &early
                            .canonical(H2CaptureLimits {
                                bytes: maximum,
                                ..H2CaptureLimits::default()
                            })?
                            .bytes,
                    )?;
                }
            }
            #[cfg(feature = "tls")]
            (LegacyField::TcpTls, LegacyFieldValue::TcpTls(tls)) => {
                if !matches!(tls.transport, TlsCaptureTransport::Tcp) {
                    return Err(ProfileDataError::Invalid("legacy TLS transport"));
                }
                writer.bytes(
                    &tls.canonical(TlsCaptureLimits {
                        bytes: maximum,
                        ..TlsCaptureLimits::default()
                    })?
                    .bytes,
                )?;
            }
            (LegacyField::WsTlsAlpn, LegacyFieldValue::WsTlsAlpn(protocols)) => {
                writer.u8(u8::from(protocols.is_some()))?;
                if let Some(protocols) = protocols {
                    if protocols.len() > 64 {
                        return Err(ProfileDataError::Invalid("legacy ALPN count"));
                    }
                    writer.u64(protocols.len() as u64)?;
                    for protocol in protocols {
                        if protocol.is_empty() || protocol.len() > 255 {
                            return Err(ProfileDataError::Invalid("legacy ALPN length"));
                        }
                        writer.bytes(protocol)?;
                    }
                }
            }
            (
                LegacyField::JsWebApis | LegacyField::SourceInfo,
                LegacyFieldValue::Runtime(runtime),
            ) => {
                let source = runtime.runtime.source_info.is_some();
                let js = runtime
                    .runtime
                    .js_info
                    .as_ref()
                    .is_some_and(|value| value.web_apis.is_some());
                if (self.field == LegacyField::SourceInfo
                    && (!source || runtime.runtime.js_info.is_some()))
                    || (self.field == LegacyField::JsWebApis && (source || !js))
                {
                    return Err(ProfileDataError::Invalid("legacy runtime field"));
                }
                writer.bytes(&runtime.canonical(maximum)?.bytes)?;
            }
            _ => return Err(ProfileDataError::Invalid("legacy field payload")),
        }
        Ok(writer.finish())
    }

    /// Legacy fields have no reliable population or cross-field correlation.
    /// A coarse field bucket bounds revisions without promoting generated rules.
    pub fn structural(&self, maximum: usize) -> Result<CanonicalValue, ProfileDataError> {
        self.canonical(maximum)?;
        let mut writer = CanonicalWriter::new(CanonicalDomain::LegacyFieldStructure, maximum)?;
        writer.u8(self.field.tag())?;
        Ok(writer.finish())
    }

    pub(in crate::profile) fn validate_structure(
        value: &CanonicalValue,
        maximum: usize,
    ) -> Result<(), ProfileDataError> {
        value.verify(CanonicalDomain::LegacyFieldStructure, maximum)?;
        let mut reader = CanonicalReader::new(&value.bytes, CanonicalDomain::LegacyFieldStructure)?;
        LegacyField::from_tag(reader.u8()?)?;
        reader.finish()
    }

    pub fn from_canonical(
        value: &CanonicalValue,
        maximum: usize,
    ) -> Result<Self, ProfileDataError> {
        value.verify(CanonicalDomain::LegacyField, maximum)?;
        let mut reader = CanonicalReader::new(&value.bytes, CanonicalDomain::LegacyField)?;
        let field = LegacyField::from_tag(reader.u8()?)?;
        let payload = match field {
            LegacyField::H1Settings => LegacyFieldValue::H1Settings {
                title_case_headers: boolean(&mut reader)?,
            },
            LegacyField::H1Navigate
            | LegacyField::H1Fetch
            | LegacyField::H1Xhr
            | LegacyField::H1Form
            | LegacyField::H1Ws
            | LegacyField::H2Navigate
            | LegacyField::H2Fetch
            | LegacyField::H2Xhr
            | LegacyField::H2Form
            | LegacyField::H2Ws => LegacyFieldValue::Headers(LegacyHeaderCapture::from_canonical(
                &nested(&mut reader, maximum)?,
                maximum,
            )?),
            LegacyField::H2Settings => {
                let pseudo = if boolean(&mut reader)? {
                    Some(PseudoHeaderCapture::from_canonical(
                        &nested(&mut reader, maximum)?,
                        maximum,
                    )?)
                } else {
                    None
                };
                let early = if boolean(&mut reader)? {
                    Some(H2Capture::from_canonical(
                        &nested(&mut reader, maximum)?,
                        H2CaptureLimits {
                            bytes: maximum,
                            ..H2CaptureLimits::default()
                        },
                    )?)
                } else {
                    None
                };
                LegacyFieldValue::H2Settings { pseudo, early }
            }
            LegacyField::TcpTls => {
                #[cfg(feature = "tls")]
                {
                    LegacyFieldValue::TcpTls(TlsCapture::from_canonical(
                        &nested(&mut reader, maximum)?,
                        TlsCaptureLimits {
                            bytes: maximum,
                            ..TlsCaptureLimits::default()
                        },
                    )?)
                }
                #[cfg(not(feature = "tls"))]
                {
                    return Err(ProfileDataError::Unsupported("legacy TLS field"));
                }
            }
            LegacyField::WsTlsAlpn => {
                let protocols = if boolean(&mut reader)? {
                    let count = reader.count(64)?;
                    let mut protocols = Vec::new();
                    for _ in 0..count {
                        protocols.push(reader.bytes(255)?.into());
                    }
                    Some(protocols.into())
                } else {
                    None
                };
                LegacyFieldValue::WsTlsAlpn(protocols)
            }
            LegacyField::JsWebApis | LegacyField::SourceInfo => {
                LegacyFieldValue::Runtime(Box::new(RuntimeProfileCapture::from_canonical(
                    &nested(&mut reader, maximum)?,
                    maximum,
                )?))
            }
        };
        reader.finish()?;
        let capture = Self {
            field,
            value: payload,
        };
        if capture.canonical(maximum)?.bytes != value.bytes {
            return Err(ProfileDataError::Invalid("noncanonical legacy field"));
        }
        Ok(capture)
    }

    /// Prepare independent legacy fields as one atomic storage batch. No joint
    /// tuple or request method is inferred from an overwrite-schema row.
    pub fn prepare_row(
        row: &UserAgentProfileInput,
        authorized: bool,
        limits: JointCaptureLimits,
    ) -> Result<Option<PreparedProfileCapture>, ProfileDataError> {
        let fields = Self::capture_row(row, limits.value_bytes)?;
        if fields.is_empty() {
            return Ok(None);
        }
        let key = ProfileKey::from_user_agent(&UserAgent::new(row.uastr.clone()));
        let profile = key.canonical(limits.value_bytes)?;
        let mut remaining = limits
            .bytes
            .checked_sub(profile.bytes.len())
            .ok_or(ProfileDataError::LimitExceeded("legacy row bytes"))?;
        let mut buckets = Vec::new();
        for field in fields {
            let capture = ProfileCapture {
                profile: key.clone(),
                flow: None,
                connection: ConnectionContext::default(),
                joint: JointCapture {
                    completeness: ProfileCaptureCompleteness::Complete,
                    level: CaptureLevel::Legacy,
                    slots: vec![CapturedSlot {
                        kind: CapturedSlotKind::LegacyField,
                        value: field.canonical(limits.value_bytes)?,
                    }]
                    .into(),
                },
            };
            let prepared = capture.prepare(authorized, limits)?;
            for bucket in prepared.buckets {
                for size in [
                    bucket.scope.bytes.len(),
                    bucket.structure.bytes.len(),
                    bucket.value.bytes.len(),
                ] {
                    remaining = remaining
                        .checked_sub(size)
                        .ok_or(ProfileDataError::LimitExceeded("legacy row bytes"))?;
                }
                buckets.push(bucket);
            }
        }
        Ok(Some(PreparedProfileCapture {
            profile,
            flow: None,
            buckets: buckets.into(),
        }))
    }

    pub fn capture_row(
        row: &UserAgentProfileInput,
        maximum: usize,
    ) -> Result<Box<[Self]>, ProfileDataError> {
        Self::capture_fields(row, maximum, &mut |_field, error| Err(error))
    }

    /// Like [`Self::capture_row`], but skips fields that cannot be captured.
    pub fn capture_row_lenient(
        row: &UserAgentProfileInput,
        maximum: usize,
    ) -> Result<Box<[Self]>, ProfileDataError> {
        Self::capture_fields(row, maximum, &mut |field, error| {
            tracing::debug!(
                user_agent = %row.uastr,
                field = field.name(),
                "skip legacy profile field: {error}"
            );
            Ok(())
        })
    }

    fn capture_fields(
        row: &UserAgentProfileInput,
        maximum: usize,
        rejected: &mut dyn FnMut(LegacyField, ProfileDataError) -> Result<(), ProfileDataError>,
    ) -> Result<Box<[Self]>, ProfileDataError> {
        let mut output = Vec::new();
        let mut keep = |rejected: &mut dyn FnMut(
            LegacyField,
            ProfileDataError,
        ) -> Result<(), ProfileDataError>,
                        field: LegacyField,
                        value: Result<LegacyFieldValue, ProfileDataError>|
         -> Result<bool, ProfileDataError> {
            match value.and_then(|value| {
                let capture = Self { field, value };
                capture.canonical(maximum)?;
                Ok(capture)
            }) {
                Ok(capture) => {
                    output.push(capture);
                    Ok(true)
                }
                Err(error) => rejected(field, error).map(|()| false),
            }
        };
        if let Some(settings) = &row.h1_settings {
            keep(
                rejected,
                LegacyField::H1Settings,
                Ok(LegacyFieldValue::H1Settings {
                    title_case_headers: settings.title_case_headers,
                }),
            )?;
        }
        let policy = HeaderCapturePolicy {
            bytes: maximum,
            ..HeaderCapturePolicy::default()
        };
        for (field, headers) in [
            (LegacyField::H1Navigate, row.h1_headers_navigate.as_ref()),
            (LegacyField::H1Fetch, row.h1_headers_fetch.as_ref()),
            (LegacyField::H1Xhr, row.h1_headers_xhr.as_ref()),
            (LegacyField::H1Form, row.h1_headers_form.as_ref()),
            (LegacyField::H1Ws, row.h1_headers_ws.as_ref()),
            (LegacyField::H2Navigate, row.h2_headers_navigate.as_ref()),
            (LegacyField::H2Fetch, row.h2_headers_fetch.as_ref()),
            (LegacyField::H2Xhr, row.h2_headers_xhr.as_ref()),
            (LegacyField::H2Form, row.h2_headers_form.as_ref()),
            (LegacyField::H2Ws, row.h2_headers_ws.as_ref()),
        ] {
            if let Some(headers) = headers {
                keep(
                    rejected,
                    field,
                    field
                        .protocol()
                        .ok_or(ProfileDataError::Invalid("legacy header field"))
                        .and_then(|protocol| {
                            LegacyHeaderCapture::capture(protocol, headers, &policy)
                        })
                        .map(LegacyFieldValue::Headers),
                )?;
            }
        }
        if let Some(settings) = &row.h2_settings {
            let pseudo = settings
                .http_pseudo_headers
                .as_ref()
                .map(|order| {
                    PseudoHeaderCapture::capture(
                        ProfileCaptureCompleteness::Complete,
                        Version::HTTP_2,
                        order,
                        None,
                        maximum,
                    )
                })
                .transpose();
            // Unusable early frames drop only themselves; the pseudo-header order stays.
            let early = match settings
                .early_frames
                .as_ref()
                .map(|early| {
                    H2Capture::capture(
                        early,
                        H2CaptureLimits {
                            bytes: maximum,
                            ..H2CaptureLimits::default()
                        },
                    )
                })
                .transpose()
            {
                Ok(early) => early,
                Err(error) => {
                    rejected(LegacyField::H2Settings, error)?;
                    None
                }
            };
            let value = pseudo.map(|pseudo| LegacyFieldValue::H2Settings { pseudo, early });
            keep(rejected, LegacyField::H2Settings, value)?;
        }
        #[cfg(feature = "tls")]
        {
            let mut base = false;
            if let Some(hello) = &row.tls_client_hello {
                base = keep(
                    rejected,
                    LegacyField::TcpTls,
                    TlsCapture::capture(
                        ProfileCaptureCompleteness::Complete,
                        TlsCaptureTransport::Tcp,
                        hello,
                        TlsCaptureLimits {
                            bytes: maximum,
                            ..TlsCaptureLimits::default()
                        },
                    )
                    .map(LegacyFieldValue::TcpTls),
                )?;
            }
            if let Some(overwrites) = &row.tls_ws_client_config_overwrites {
                // The overwrite only applies on top of a kept TLS hello.
                keep(
                    rejected,
                    LegacyField::WsTlsAlpn,
                    if base {
                        Ok(LegacyFieldValue::WsTlsAlpn(overwrites.alpn.as_ref().map(
                            |protocols| {
                                protocols
                                    .iter()
                                    .map(|protocol| protocol.as_bytes().into())
                                    .collect()
                            },
                        )))
                    } else {
                        Err(ProfileDataError::Incomplete("legacy websocket TLS base"))
                    },
                )?;
            }
        }
        if let Some(js) = &row.js_web_apis {
            keep(
                rejected,
                LegacyField::JsWebApis,
                RuntimeProfileCapture::capture_report(None, Some(js), maximum)
                    .map(|runtime| LegacyFieldValue::Runtime(Box::new(runtime))),
            )?;
        }
        if let Some(source) = &row.source_info {
            keep(
                rejected,
                LegacyField::SourceInfo,
                RuntimeProfileCapture::capture_report(Some(source), None, maximum)
                    .map(|runtime| LegacyFieldValue::Runtime(Box::new(runtime))),
            )?;
        }
        output.sort_unstable_by_key(|field| field.field.tag());
        Ok(output.into())
    }
}

#[cfg(test)]
mod tests;
