//! Decode retained captures once, preserving protocol-specific resource limits.
//!
//! Canonical identity bytes remain the persistence boundary. This module exposes
//! typed values for consumers that need fields, without an intermediate JSON tree.
//! Structural and legacy values retain their validated canonical representation.

use super::canonical::{CanonicalDomain, CanonicalValue, ProfileDataError};
#[cfg(feature = "tls")]
use crate::profile::capture::tls::{TlsCapture, TlsCaptureLimits};
use crate::profile::capture::{
    headers::{HeaderCapture, HeaderCapturePolicy},
    http2::{H2Capture, H2CaptureLimits},
    http3::{
        H3ClientSequenceCapture, H3SequenceCaptureLimits,
        bootstrap::{H3BootstrapCapture, H3BootstrapLimits},
    },
    joint::{JointCapture, JointCaptureLimits},
    order::{OrderCaptureLimits, OrderedProtocolCapture},
    pseudo_headers::PseudoHeaderCapture,
    quic::{QuicFlightCapture, QuicFlightCaptureLimits},
    runtime::RuntimeProfileCapture,
};

/// Bounds applied before and during decoding of one canonical value.
///
/// The byte ceiling applies to every domain. Component limits additionally bound
/// protocol-specific counts and represented lengths; they are not interchangeable
/// with the encoded byte length. Joint slots are validated by the joint decoder.
pub struct CaptureDecodeLimits {
    /// Maximum encoded bytes, including the canonical envelope.
    pub bytes: usize,
    /// Header occurrences, values and binding policy.
    pub headers: HeaderCapturePolicy,
    /// Ordered protocol fields and their encoded values.
    pub order: OrderCaptureLimits,
    /// HTTP/2 frames and settings.
    pub h2: H2CaptureLimits,
    /// HTTP/3 events, settings and QPACK instructions.
    pub h3: H3SequenceCaptureLimits,
    /// Initial request references and insertion associations.
    pub h3_bootstrap: H3BootstrapLimits,
    /// QUIC datagrams, packets, frame shapes and parameters.
    pub quic: QuicFlightCaptureLimits,
    /// Correlated component slots and their encoded values.
    pub joint: JointCaptureLimits,
    /// TLS elements and their encoded values.
    #[cfg(feature = "tls")]
    pub tls: TlsCaptureLimits,
}

impl Default for CaptureDecodeLimits {
    fn default() -> Self {
        Self {
            bytes: 65536,
            headers: HeaderCapturePolicy::default(),
            order: OrderCaptureLimits::default(),
            h2: H2CaptureLimits::default(),
            h3: H3SequenceCaptureLimits::default(),
            h3_bootstrap: H3BootstrapLimits::default(),
            quic: QuicFlightCaptureLimits::default(),
            joint: JointCaptureLimits::default(),
            #[cfg(feature = "tls")]
            tls: TlsCaptureLimits::default(),
        }
    }
}

/// A validated capture, or a validated domain without a field-level view.
///
/// Joint components retain their canonical values so consumers can choose their
/// presentation without losing slot kinds, ordering or correlation boundaries.
/// The canonical fallback borrows the original value instead of copying its bytes.
#[derive(Debug)]
pub enum DecodedCapture<'a> {
    Headers(HeaderCapture),
    Order(OrderedProtocolCapture),
    H2(H2Capture),
    H3(H3ClientSequenceCapture),
    H3Bootstrap(H3BootstrapCapture),
    PseudoHeaders(PseudoHeaderCapture),
    // Runtime metadata is substantially larger than the wire capture variants.
    Runtime(Box<RuntimeProfileCapture>),
    Quic(QuicFlightCapture),
    Joint(JointCapture),
    #[cfg(feature = "tls")]
    Tls(TlsCapture),
    Canonical {
        domain: CanonicalDomain,
        value: &'a CanonicalValue,
    },
}

impl<'a> DecodedCapture<'a> {
    /// Verify identity, envelope and payload semantics while decoding its fields.
    pub fn from_canonical(
        value: &'a CanonicalValue,
        limits: &CaptureDecodeLimits,
    ) -> Result<Self, ProfileDataError> {
        // The tag is only a dispatch hint. Every branch invokes a validating
        // decoder; a correct digest alone never establishes payload validity.
        let domain = value.domain_tag(limits.bytes)?;
        Ok(match domain {
            CanonicalDomain::Headers => {
                Self::Headers(HeaderCapture::from_canonical(value, &limits.headers)?)
            }
            CanonicalDomain::Order => {
                Self::Order(OrderedProtocolCapture::from_canonical(value, limits.order)?)
            }
            CanonicalDomain::H2 => Self::H2(H2Capture::from_canonical(value, limits.h2)?),
            CanonicalDomain::H3Bootstrap => Self::H3Bootstrap(H3BootstrapCapture::from_canonical(
                value,
                limits.h3_bootstrap,
            )?),
            CanonicalDomain::H3Sequence => {
                Self::H3(H3ClientSequenceCapture::from_canonical(value, limits.h3)?)
            }
            CanonicalDomain::PseudoHeaders => {
                Self::PseudoHeaders(PseudoHeaderCapture::from_canonical(value, limits.bytes)?)
            }
            CanonicalDomain::RuntimeMetadata => Self::Runtime(Box::new(
                RuntimeProfileCapture::from_canonical(value, limits.bytes)?,
            )),
            CanonicalDomain::QuicFlight => {
                Self::Quic(QuicFlightCapture::from_canonical(value, limits.quic)?)
            }
            CanonicalDomain::Joint => {
                Self::Joint(JointCapture::from_canonical(value, limits.joint)?)
            }
            #[cfg(feature = "tls")]
            CanonicalDomain::Tls => Self::Tls(TlsCapture::from_canonical(value, limits.tls)?),
            _ => {
                value.validate_content(domain, limits.bytes)?;
                Self::Canonical { domain, value }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{
        capture::{completeness::ProfileCaptureCompleteness, order::OrderNamespace},
        model::identity::ProfileKey,
    };
    use sha2::{Digest as _, Sha256};

    fn ordered_value() -> CanonicalValue {
        OrderedProtocolCapture::capture(
            ProfileCaptureCompleteness::Complete,
            OrderNamespace::Http3Setting,
            [(33, 17_u64.to_be_bytes())],
            OrderCaptureLimits::default(),
        )
        .unwrap()
        .canonical(OrderCaptureLimits::default())
        .unwrap()
    }

    #[test]
    fn typed_decode_enforces_identity_payload_and_component_limits() {
        let value = ordered_value();
        let mut limits = CaptureDecodeLimits::default();
        assert!(matches!(
            DecodedCapture::from_canonical(&value, &limits).unwrap(),
            DecodedCapture::Order(_)
        ));

        limits.bytes = value.bytes.len() - 1;
        DecodedCapture::from_canonical(&value, &limits).unwrap_err();
        limits = CaptureDecodeLimits::default();
        limits.order.elements = 0;
        DecodedCapture::from_canonical(&value, &limits).unwrap_err();
        limits = CaptureDecodeLimits::default();

        let mut corrupt = value.clone();
        corrupt.id.0[0] ^= 1;
        DecodedCapture::from_canonical(&corrupt, &limits).unwrap_err();

        // A valid digest does not make a truncated protocol payload valid.
        let mut corrupt = value;
        corrupt.bytes = corrupt.bytes[..corrupt.bytes.len() - 1].into();
        corrupt.id.0 = Sha256::digest(&corrupt.bytes).into();
        DecodedCapture::from_canonical(&corrupt, &limits).unwrap_err();
    }

    #[test]
    fn fallback_borrows_only_validated_canonical_values() {
        let value = ProfileKey::new("test-client").canonical(65536).unwrap();
        let limits = CaptureDecodeLimits::default();
        let DecodedCapture::Canonical {
            domain,
            value: borrowed,
        } = DecodedCapture::from_canonical(&value, &limits).unwrap()
        else {
            panic!("expected canonical fallback")
        };
        assert_eq!(domain, CanonicalDomain::Profile);
        assert!(std::ptr::eq(&value, borrowed));

        let mut corrupt = value;
        corrupt.bytes = corrupt.bytes[..corrupt.bytes.len() - 1].into();
        corrupt.id.0 = Sha256::digest(&corrupt.bytes).into();
        DecodedCapture::from_canonical(&corrupt, &limits).unwrap_err();
    }
}
