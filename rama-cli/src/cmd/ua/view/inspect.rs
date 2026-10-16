//! Readable retained captures for packet comparison and offline diagnostics.
//!
//! The archive loader validates and reanalyzes evidence. Serialized analysis is
//! never trusted as the source of captured fields. Decoding uses the same bounded
//! public capture APIs available to applications, while wire comparison remains
//! independent (for example, tshark in the browser integration tests).

use rama::{
    error::BoxError,
    ua::profile::{
        analysis::{capture::AnalyzedCaptureVariant, profile::AnalyzedProfileScope},
        capture::joint::CapturedSlot,
        format::{
            archive::{
                CompiledProfileArchiveEntry, ProfileArchiveLimits, load_profile_archive_snapshot,
            },
            canonical::CanonicalValue,
            decoded::{CaptureDecodeLimits, DecodedCapture},
        },
    },
};
use serde::{
    Serialize, Serializer,
    ser::{Error as _, SerializeStruct as _},
};
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

/// Serialize mapped iterators without retaining an intermediate collection.
struct Sequence<I>(I);

impl<I> Serialize for Sequence<I>
where
    I: Clone + IntoIterator,
    I::Item: Serialize,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.clone())
    }
}

struct CaptureView<'a> {
    value: &'a CanonicalValue,
    maximum: usize,
    nested: bool,
}

impl Serialize for CaptureView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let limits = CaptureDecodeLimits {
            bytes: self.maximum,
            ..CaptureDecodeLimits::default()
        };
        let decoded =
            DecodedCapture::from_canonical(self.value, &limits).map_err(S::Error::custom)?;
        match decoded {
            DecodedCapture::Headers(value) => value.serialize(serializer),
            DecodedCapture::PseudoHeaders(value) => value.serialize(serializer),
            DecodedCapture::Tls(value) => value.serialize(serializer),
            DecodedCapture::H2(value) => value.serialize(serializer),
            DecodedCapture::Order(value) => value.serialize(serializer),
            DecodedCapture::Runtime(value) => value.serialize(serializer),
            DecodedCapture::Quic(value) => value.serialize(serializer),
            DecodedCapture::H3(value) => value.serialize(serializer),
            DecodedCapture::Joint(joint) => {
                if self.nested {
                    return Err(S::Error::custom("nested joint capture"));
                }
                let mut output = serializer.serialize_struct("JointCapture", 3)?;
                output.serialize_field("completeness", &joint.completeness)?;
                output.serialize_field("level", &joint.level)?;
                output.serialize_field(
                    "slots",
                    &Sequence(joint.slots.iter().map(|slot| SlotView {
                        slot,
                        maximum: self.maximum,
                    })),
                )?;
                output.end()
            }
            DecodedCapture::Canonical { domain, value } => {
                let mut output = serializer.serialize_struct("CanonicalCapture", 2)?;
                output.serialize_field("domain", &domain)?;
                output.serialize_field("canonical", value)?;
                output.end()
            }
        }
    }
}

struct SlotView<'a> {
    slot: &'a CapturedSlot,
    maximum: usize,
}

impl Serialize for SlotView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut output = serializer.serialize_struct("Slot", 2)?;
        output.serialize_field("kind", &self.slot.kind)?;
        output.serialize_field(
            "capture",
            &CaptureView {
                value: &self.slot.value,
                maximum: self.maximum,
                nested: true,
            },
        )?;
        output.end()
    }
}

struct VariantView<'a> {
    variant: &'a AnalyzedCaptureVariant,
    maximum: usize,
}

impl Serialize for VariantView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut output = serializer.serialize_struct("Variant", 3)?;
        output.serialize_field("id", &self.variant.value.id)?;
        output.serialize_field("weight", &self.variant.weight)?;
        output.serialize_field(
            "capture",
            &CaptureView {
                value: &self.variant.value,
                maximum: self.maximum,
                nested: false,
            },
        )?;
        output.end()
    }
}

struct ScopeView<'a> {
    scope: &'a AnalyzedProfileScope,
    maximum: usize,
}

impl Serialize for ScopeView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut output = serializer.serialize_struct("Scope", 5)?;
        output.serialize_field("id", &self.scope.id)?;
        output.serialize_field("flow", &self.scope.flow)?;
        output.serialize_field("context", &self.scope.context)?;
        output.serialize_field("domain", &self.scope.observations.domain)?;
        output.serialize_field(
            "variants",
            &Sequence(
                self.scope
                    .observations
                    .variants
                    .iter()
                    .map(|variant| VariantView {
                        variant,
                        maximum: self.maximum,
                    }),
            ),
        )?;
        output.end()
    }
}

struct ProfileView<'a> {
    profile: &'a CompiledProfileArchiveEntry,
    maximum: usize,
}

impl Serialize for ProfileView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut output = serializer.serialize_struct("Profile", 2)?;
        output.serialize_field("key", &self.profile.analysis.key)?;
        output.serialize_field(
            "scopes",
            &Sequence(self.profile.analysis.scopes.iter().map(|scope| ScopeView {
                scope,
                maximum: self.maximum,
            })),
        )?;
        output.end()
    }
}

#[derive(Serialize)]
struct ArchiveView<P> {
    format_version: u16,
    profiles: P,
}

pub(super) fn archive_json(bytes: &[u8], authorized: bool) -> Result<Vec<u8>, BoxError> {
    let limits = ProfileArchiveLimits::default();
    let profiles = load_profile_archive_snapshot(bytes, authorized, limits)?;
    let mut output = BoundedOutput {
        bytes: Vec::new(),
        maximum: limits.bytes,
    };
    let archive = ArchiveView {
        format_version: 1,
        profiles: Sequence(profiles.iter().map(|profile| ProfileView {
            profile,
            maximum: limits.bytes,
        })),
    };
    // Keep the final byte buffer private until every capture has validated and
    // serialized successfully. Stdout never receives a partial JSON document.
    serde_json::to_writer(&mut output, &archive)?;
    output.write_all(b"\n")?;
    Ok(output.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::{
        http::{HeaderName, Version},
        ua::profile::{
            capture::{
                completeness::ProfileCaptureCompleteness,
                headers::{
                    HeaderCapture, HeaderCapturePolicy, HeaderOccurrence, HeaderValueSource,
                },
            },
            evidence::ProfileEvidence,
            format::archive::{ProfileArchiveEntry, ProfileArchiveWriter},
            model::identity::ProfileKey,
        },
    };
    use serde_json::{Value, json};

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
        let decoded = serde_json::to_value(CaptureView {
            value: &canonical,
            maximum: 65536,
            nested: false,
        })
        .unwrap();
        assert_eq!(decoded["fields"].as_array().unwrap().len(), 2);
        assert_eq!(decoded["fields"][0]["value"]["Profile"], json!(b"first"));
        assert_eq!(decoded["fields"][1]["value"]["Profile"], json!(b"second"));
        assert_eq!(decoded["fields"][1]["occurrence"], 1);
        let mut corrupt = canonical;
        corrupt.bytes[0] ^= 1;
        serde_json::to_value(CaptureView {
            value: &corrupt,
            maximum: 65536,
            nested: false,
        })
        .unwrap_err();
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
    fn streamed_sequences_stop_visiting_values_at_the_output_budget() {
        let visited = std::cell::Cell::new(0);
        let sequence = Sequence((0..100).inspect(|_| {
            visited.set(visited.get() + 1);
        }));
        let mut output = BoundedOutput {
            bytes: Vec::new(),
            maximum: 3,
        };
        serde_json::to_writer(&mut output, &sequence).unwrap_err();
        assert!(visited.get() < 100);
        assert!(output.bytes.len() <= 3);
    }

    #[test]
    fn streamed_joint_preserves_slot_shape_and_canonical_fallback() {
        use rama::ua::profile::capture::joint::{
            CaptureLevel, CapturedSlot, CapturedSlotKind, JointCapture, JointCaptureLimits,
        };
        let capture = HeaderCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            version: Version::HTTP_2,
            fields: Box::default(),
        };
        let expected = serde_json::to_value(&capture).unwrap();
        let joint = JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Request,
            slots: vec![CapturedSlot {
                kind: CapturedSlotKind::Headers,
                value: capture.canonical(&HeaderCapturePolicy::default()).unwrap(),
            }]
            .into(),
        }
        .canonical(JointCaptureLimits::default())
        .unwrap();
        let actual = serde_json::to_value(CaptureView {
            value: &joint,
            maximum: 65536,
            nested: false,
        })
        .unwrap();
        assert_eq!(
            actual,
            json!({"completeness": "Complete", "level": "Request", "slots": [{"kind": "Headers", "capture": expected}]})
        );
        let value = ProfileKey::new("test-client").canonical(65536).unwrap();
        let actual = serde_json::to_value(CaptureView {
            value: &value,
            maximum: 65536,
            nested: false,
        })
        .unwrap();
        assert_eq!(actual["canonical"], serde_json::to_value(&value).unwrap());
        assert_eq!(actual["domain"], 2);
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
