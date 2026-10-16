//! Readable retained captures for packet comparison and offline diagnostics.
//!
//! The archive loader validates and reanalyzes evidence. Serialized analysis is
//! never trusted as the source of captured fields. Decoding uses the same bounded
//! public capture APIs available to applications, while wire comparison remains
//! independent (for example, tshark in the browser integration tests).

use rama::{
    error::{BoxError, BoxErrorExt as _},
    ua::profile::{
        CanonicalDomain, CanonicalValue, H2Capture, H2CaptureLimits, H3ClientSequenceCapture,
        H3SequenceCaptureLimits, HeaderCapture, HeaderCapturePolicy, JointCapture,
        JointCaptureLimits, OrderCaptureLimits, OrderedProtocolCapture, ProfileArchiveLimits,
        PseudoHeaderCapture, QuicFlightCapture, QuicFlightCaptureLimits, RuntimeProfileCapture,
        TlsCapture, TlsCaptureLimits, load_profile_archive_snapshot,
    },
};
use serde_json::{Value, json};
use std::io::{self, Write};

/// Refuse an expanded diagnostic that exceeds the archive's output budget.
struct BoundedOutput {
    bytes: Vec<u8>,
    maximum: usize,
}

impl Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("profile inspection output limit exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn decode(value: &CanonicalValue, maximum: usize, nested: bool) -> Result<Value, BoxError> {
    let domain = value.validated_domain(maximum)?;
    Ok(match domain {
        CanonicalDomain::Headers => serde_json::to_value(HeaderCapture::from_canonical(
            value,
            &HeaderCapturePolicy::default(),
        )?)?,
        CanonicalDomain::PseudoHeaders => {
            serde_json::to_value(PseudoHeaderCapture::from_canonical(value, maximum)?)?
        }
        CanonicalDomain::Tls => serde_json::to_value(TlsCapture::from_canonical(
            value,
            TlsCaptureLimits::default(),
        )?)?,
        CanonicalDomain::H2 => serde_json::to_value(H2Capture::from_canonical(
            value,
            H2CaptureLimits::default(),
        )?)?,
        CanonicalDomain::Order => serde_json::to_value(OrderedProtocolCapture::from_canonical(
            value,
            OrderCaptureLimits::default(),
        )?)?,
        CanonicalDomain::RuntimeMetadata => {
            serde_json::to_value(RuntimeProfileCapture::from_canonical(value, maximum)?)?
        }
        CanonicalDomain::QuicFlight => serde_json::to_value(QuicFlightCapture::from_canonical(
            value,
            QuicFlightCaptureLimits::default(),
        )?)?,
        CanonicalDomain::H3Sequence => serde_json::to_value(
            H3ClientSequenceCapture::from_canonical(value, H3SequenceCaptureLimits::default())?,
        )?,
        CanonicalDomain::Joint => {
            if nested {
                return Err(BoxError::from_static_str("nested joint capture"));
            }
            let joint = JointCapture::from_canonical(value, JointCaptureLimits::default())?;
            let slots = joint
                .slots
                .iter()
                .map(|slot| {
                    Ok(json!({"kind": slot.kind, "capture": decode(&slot.value, maximum, true)?}))
                })
                .collect::<Result<Vec<_>, BoxError>>()?;
            json!({"completeness": joint.completeness, "level": joint.level, "slots": slots})
        }
        // Retain valid legacy/structural domains explicitly, without inventing a
        // decoded representation or silently omitting observations.
        _ => json!({"domain": domain, "canonical": value}),
    })
}

pub(super) fn archive_json(bytes: &[u8], authorized: bool) -> Result<Vec<u8>, BoxError> {
    let limits = ProfileArchiveLimits::default();
    let profiles = load_profile_archive_snapshot(bytes, authorized, limits)?;
    let mut output = BoundedOutput {
        bytes: Vec::new(),
        maximum: limits.bytes,
    };
    output.write_all(b"{\"format_version\":1,\"profiles\":[")?;
    for (index, profile) in profiles.iter().enumerate() {
        if index != 0 {
            output.write_all(b",")?;
        }
        let scopes = profile
            .analysis
            .scopes
            .iter()
            .map(|scope| {
                let variants = scope
                    .observations
                    .variants
                    .iter()
                    .map(|variant| {
                        Ok(json!({
                            "id": variant.value.id,
                            "weight": variant.weight,
                            "capture": decode(&variant.value, limits.bytes, false)?,
                        }))
                    })
                    .collect::<Result<Vec<_>, BoxError>>()?;
                Ok(json!({
                    "id": scope.id, "flow": scope.flow, "context": scope.context,
                    "domain": scope.observations.domain, "variants": variants,
                }))
            })
            .collect::<Result<Vec<_>, BoxError>>()?;
        serde_json::to_writer(
            &mut output,
            &json!({"key": profile.analysis.key, "scopes": scopes}),
        )?;
    }
    output.write_all(b"]}\n")?;
    Ok(output.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::{
        http::{HeaderName, Version},
        ua::profile::{
            HeaderOccurrence, HeaderValueSource, ProfileArchiveEntry, ProfileArchiveWriter,
            ProfileCaptureCompleteness, ProfileEvidence, ProfileKey,
        },
    };

    #[test]
    fn inspection_preserves_order_values_and_repeated_headers() {
        let capture = HeaderCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            version: Version::HTTP_2,
            fields: [b"first".as_slice(), b"second".as_slice()]
                .into_iter()
                .enumerate()
                .map(|(occurrence, value)| HeaderOccurrence {
                    name: HeaderName::from_static("accept"),
                    occurrence: occurrence as u32,
                    sensitive: false,
                    representation: None,
                    value: HeaderValueSource::Profile(value.into()),
                })
                .collect(),
        };
        let canonical = capture.canonical(&HeaderCapturePolicy::default()).unwrap();
        let decoded = decode(&canonical, 65536, false).unwrap();
        assert_eq!(decoded["fields"].as_array().unwrap().len(), 2);
        assert_eq!(decoded["fields"][0]["value"]["Profile"], json!(b"first"));
        assert_eq!(decoded["fields"][1]["value"]["Profile"], json!(b"second"));
        assert_eq!(decoded["fields"][1]["occurrence"], 1);
        let mut corrupt = canonical;
        corrupt.bytes[0] ^= 1;
        decode(&corrupt, 65536, false).unwrap_err();
    }

    #[test]
    fn inspection_reanalyzes_evidence_instead_of_trusting_saved_analysis() {
        let entry = ProfileArchiveEntry {
            evidence: ProfileEvidence {
                format_version: 1,
                profile: ProfileKey::new("real-client").canonical(16384).unwrap(),
                scopes: Box::default(),
            },
            sampler_seed: [3; 32],
        };
        let archive =
            ProfileArchiveWriter::new(Vec::new(), false, 100, 14, ProfileArchiveLimits::default())
                .unwrap()
                .write_profile(entry)
                .unwrap()
                .finish()
                .unwrap();
        let mut forged: Value = serde_json::from_slice(&archive).unwrap();
        forged["profiles"][0]["analysis"]["key"]["client"] = json!("forged-client");
        let inspected: Value = serde_json::from_slice(
            &archive_json(&serde_json::to_vec(&forged).unwrap(), false).unwrap(),
        )
        .unwrap();
        assert_eq!(inspected["profiles"][0]["key"]["client"], "real-client");
    }

    #[test]
    fn inspection_output_budget_rejects_overflow_without_partial_write() {
        let mut output = BoundedOutput {
            bytes: Vec::new(),
            maximum: 3,
        };
        output.write_all(b"abc").unwrap();
        output.write_all(b"d").unwrap_err();
        assert_eq!(output.bytes, b"abc");
    }
}
