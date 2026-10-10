use rama_http::{HeaderMap, Version};
use serde::Serialize;

use super::super::{
    CanonicalDomain, CanonicalValue, HeaderCapture, HeaderCapturePolicy, HeaderOccurrence,
    ProfileCaptureCompleteness, ProfileDataError, canonical::CanonicalReader,
    capture::decode_fields,
};

/// The old fingerprint schema distinguished HTTP/1 from HTTP/2 but did not
/// retain the HTTP/1 minor version or the request method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum LegacyHttpProtocol {
    Http1,
    Http2,
}

impl LegacyHttpProtocol {
    fn tag(self) -> u8 {
        match self {
            Self::Http1 => 0,
            Self::Http2 => 1,
        }
    }

    /// HTTP/1.0 and HTTP/1.1 share these header ownership/framing rules. This
    /// value selects validation only; it is absent from the retained legacy value.
    fn validation_version(self) -> Version {
        match self {
            Self::Http1 => Version::HTTP_11,
            Self::Http2 => Version::HTTP_2,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LegacyHeaderCapture {
    pub protocol: LegacyHttpProtocol,
    pub fields: Box<[HeaderOccurrence]>,
}

impl LegacyHeaderCapture {
    pub fn capture(
        protocol: LegacyHttpProtocol,
        headers: &HeaderMap,
        policy: &HeaderCapturePolicy,
    ) -> Result<Self, ProfileDataError> {
        let captured = policy.capture(
            ProfileCaptureCompleteness::Complete,
            protocol.validation_version(),
            headers,
            None,
        )?;
        Ok(Self {
            protocol,
            fields: captured.fields,
        })
    }

    pub fn canonical(&self, maximum: usize) -> Result<CanonicalValue, ProfileDataError> {
        self.header().canonical_with_domain(
            CanonicalDomain::LegacyHeaders,
            self.protocol.tag(),
            &Self::policy(maximum),
        )
    }

    pub fn from_canonical(
        value: &CanonicalValue,
        maximum: usize,
    ) -> Result<Self, ProfileDataError> {
        value.verify(CanonicalDomain::LegacyHeaders, maximum)?;
        let mut reader = CanonicalReader::new(&value.bytes, CanonicalDomain::LegacyHeaders)?;
        let protocol = match reader.u8()? {
            0 => LegacyHttpProtocol::Http1,
            1 => LegacyHttpProtocol::Http2,
            _ => return Err(ProfileDataError::Invalid("legacy HTTP protocol")),
        };
        ProfileCaptureCompleteness::from_tag(reader.u8()?)?
            .require_complete("legacy header field")?;
        let fields = decode_fields(&mut reader, &Self::policy(maximum))?;
        reader.finish()?;
        let capture = Self { protocol, fields };
        if capture
            .fields
            .iter()
            .any(|field| field.representation.is_some())
        {
            return Err(ProfileDataError::Invalid("legacy QPACK representation"));
        }
        if capture.canonical(maximum)?.bytes != value.bytes {
            return Err(ProfileDataError::Invalid("noncanonical legacy headers"));
        }
        Ok(capture)
    }

    fn header(&self) -> HeaderCapture {
        HeaderCapture {
            version: self.protocol.validation_version(),
            completeness: ProfileCaptureCompleteness::Complete,
            fields: self.fields.clone(),
        }
    }

    fn policy(bytes: usize) -> HeaderCapturePolicy {
        HeaderCapturePolicy {
            bytes,
            ..HeaderCapturePolicy::default()
        }
    }
}
