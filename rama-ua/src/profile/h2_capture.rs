//! Bounded H2 settings and early frames, captured before semantic collapse.

use rama_http::proto::h2::frame::{
    DEFAULT_MAX_FRAME_SIZE, EarlyFrame, EarlyFrameCapture, MAX_MAX_FRAME_SIZE, Priority, Setting,
    SettingId, Settings, StreamDependency, StreamId, WindowUpdate,
};
use rama_utils::octets::kib;
use serde::Serialize;

use super::{
    CanonicalDomain, CanonicalValue, ProfileCaptureCompleteness, ProfileDataError,
    canonical::{CanonicalReader, CanonicalWriter},
};

#[derive(Debug, Clone, Copy)]
/// Resource limits for one retained H2 connection prefix.
pub struct H2CaptureLimits {
    pub frames: usize,
    pub settings: usize,
    pub bytes: usize,
}
impl Default for H2CaptureLimits {
    fn default() -> Self {
        Self {
            frames: 16,
            settings: 256,
            bytes: kib(16),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
/// One raw SETTINGS identifier/value pair in observed wire order.
pub struct H2CapturedSetting {
    pub id: u16,
    pub value: u32,
}

#[derive(Debug, Clone, Serialize)]
/// An H2 connection frame observed before the first request boundary.
pub enum H2CapturedFrame {
    Settings {
        ack: bool,
        entries: Box<[H2CapturedSetting]>,
    },
    WindowUpdate {
        stream: u32,
        increment: u32,
    },
    Priority {
        stream: u32,
        dependency: u32,
        weight: u8,
        exclusive: bool,
    },
}

impl H2CapturedFrame {
    /// SETTINGS acknowledgements reflect peer timing, not client identity.
    pub(crate) fn is_protocol_generated(&self) -> bool {
        matches!(self, Self::Settings { ack: true, .. })
    }
}

#[derive(Debug, Clone, Serialize)]
/// A complete bounded H2 client connection prefix.
pub struct H2Capture {
    pub completeness: ProfileCaptureCompleteness,
    pub frames: Box<[H2CapturedFrame]>,
}

fn invalid() -> ProfileDataError {
    ProfileDataError::Invalid("H2 early frame")
}

fn bounded() -> ProfileDataError {
    ProfileDataError::LimitExceeded("H2 early capture")
}

impl H2Capture {
    /// Record the supported early-frame prefix. Legacy frame arrays lack the
    /// completeness and raw SETTINGS evidence required by this conversion.
    pub fn capture(
        input: &EarlyFrameCapture,
        limits: H2CaptureLimits,
    ) -> Result<Self, ProfileDataError> {
        if !input.is_complete() {
            return Err(ProfileDataError::Incomplete("H2 early frames"));
        }
        if input.as_slice().len() > limits.frames {
            return Err(bounded());
        }
        // Check all budgets before cloning a single retained setting.
        let mut remaining = limits.settings;
        let mut bytes = 26usize;
        for frame in input.iter() {
            let length = match frame {
                EarlyFrame::Settings(settings) => {
                    let wire = settings
                        .observation
                        .as_ref()
                        .ok_or(ProfileDataError::Incomplete("H2 SETTINGS wire values"))?;
                    if !wire.complete {
                        return Err(ProfileDataError::Incomplete("H2 SETTINGS wire values"));
                    }
                    remaining = remaining
                        .checked_sub(wire.entries.len())
                        .ok_or_else(bounded)?;
                    wire.entries
                        .len()
                        .checked_mul(6)
                        .and_then(|length| length.checked_add(10))
                        .ok_or_else(bounded)?
                }
                EarlyFrame::WindowUpdate(_) => 9,
                EarlyFrame::Priority(_) => 11,
            };
            bytes = bytes.checked_add(length).ok_or_else(bounded)?;
            if bytes > limits.bytes {
                return Err(bounded());
            }
        }
        let frames = input
            .iter()
            .map(|frame| {
                Ok(match frame {
                    EarlyFrame::Settings(settings) => H2CapturedFrame::Settings {
                        ack: settings.flags.is_ack(),
                        entries: settings
                            .observation
                            .as_ref()
                            .ok_or(ProfileDataError::Incomplete("H2 SETTINGS wire values"))?
                            .entries
                            .iter()
                            .map(|entry| H2CapturedSetting {
                                id: entry.id.into(),
                                value: entry.value,
                            })
                            .collect(),
                    },
                    EarlyFrame::WindowUpdate(frame) => H2CapturedFrame::WindowUpdate {
                        stream: frame.stream_id.into(),
                        increment: frame.size_increment,
                    },
                    EarlyFrame::Priority(frame) => H2CapturedFrame::Priority {
                        stream: frame.stream_id.into(),
                        dependency: frame.dependency.dependency_id.into(),
                        weight: frame.dependency.weight,
                        exclusive: frame.dependency.is_exclusive,
                    },
                })
            })
            .collect::<Result<_, ProfileDataError>>()?;
        let capture = Self {
            completeness: ProfileCaptureCompleteness::Complete,
            frames,
        };
        capture.canonical(limits)?;
        Ok(capture)
    }

    /// Compile this bounded capture into the H2 client's early-frame replay input.
    pub fn replay_frames(
        &self,
        limits: H2CaptureLimits,
    ) -> Result<Vec<EarlyFrame>, ProfileDataError> {
        self.canonical(limits)?;
        self.frames
            .iter()
            .filter(|frame| !frame.is_protocol_generated())
            .map(|frame| {
                Ok(match frame {
                    H2CapturedFrame::Settings { ack: true, .. } => {
                        EarlyFrame::Settings(Settings::ack())
                    }
                    H2CapturedFrame::Settings {
                        ack: false,
                        entries,
                    } => EarlyFrame::Settings(
                        Settings::from_ordered_entries(
                            entries
                                .iter()
                                .map(|entry| Setting::new(entry.id, entry.value))
                                .collect(),
                        )
                        .map_err(|_error| invalid())?,
                    ),
                    H2CapturedFrame::WindowUpdate { stream, increment } => {
                        EarlyFrame::WindowUpdate(WindowUpdate::new(
                            StreamId::from(*stream),
                            *increment,
                        ))
                    }
                    H2CapturedFrame::Priority {
                        stream,
                        dependency,
                        weight,
                        exclusive,
                    } => EarlyFrame::Priority(Priority::new(
                        StreamId::from(*stream),
                        StreamDependency::new(StreamId::from(*dependency), *weight, *exclusive),
                    )),
                })
            })
            .collect()
    }

    pub fn canonical(&self, limits: H2CaptureLimits) -> Result<CanonicalValue, ProfileDataError> {
        self.encode(limits, false)
    }

    /// Different setting IDs can be ordered independently. Occurrences of one
    /// ID remain ordered because the last value determines the effective setting.
    pub fn structural(&self, limits: H2CaptureLimits) -> Result<CanonicalValue, ProfileDataError> {
        self.encode(limits, true)
    }

    fn encode(
        &self,
        limits: H2CaptureLimits,
        structural: bool,
    ) -> Result<CanonicalValue, ProfileDataError> {
        self.encode_with_ack_policy(limits, structural, true)
    }

    // Older structural rows include protocol-generated ACKs. Keep their exact
    // validation separate from the normalizer used for all new observations.
    fn encode_with_ack_policy(
        &self,
        limits: H2CaptureLimits,
        structural: bool,
        omit_acknowledgements: bool,
    ) -> Result<CanonicalValue, ProfileDataError> {
        self.completeness.require_complete("H2 early capture")?;
        if !matches!(
            self.frames.first(),
            Some(H2CapturedFrame::Settings { ack: false, .. })
        ) {
            return Err(ProfileDataError::Incomplete("H2 initial SETTINGS"));
        }
        if self.frames.len() > limits.frames {
            return Err(bounded());
        }
        let mut remaining = limits.settings;
        // Validate aggregate input before structural sorting allocates references.
        let mut bytes = 26usize;
        for frame in &self.frames {
            let length = match frame {
                H2CapturedFrame::Settings { ack, entries } => {
                    if *ack && !entries.is_empty() {
                        return Err(invalid());
                    }
                    remaining = remaining.checked_sub(entries.len()).ok_or_else(bounded)?;
                    for entry in entries {
                        match SettingId::from(entry.id) {
                            SettingId::EnablePush
                            | SettingId::EnableConnectProtocol
                            | SettingId::NoRfc7540Priorities
                                if entry.value > 1 =>
                            {
                                return Err(invalid());
                            }
                            SettingId::InitialWindowSize
                                if entry.value > u32::from(StreamId::MAX) =>
                            {
                                return Err(invalid());
                            }
                            SettingId::MaxFrameSize
                                if !(DEFAULT_MAX_FRAME_SIZE..=MAX_MAX_FRAME_SIZE)
                                    .contains(&entry.value) =>
                            {
                                return Err(invalid());
                            }
                            _ => (),
                        }
                    }
                    entries
                        .len()
                        .checked_mul(6)
                        .and_then(|length| length.checked_add(10))
                        .ok_or_else(bounded)?
                }
                H2CapturedFrame::WindowUpdate { stream, increment } => {
                    if StreamId::checked(*stream).is_err()
                        || *increment == 0
                        || *increment > u32::from(StreamId::MAX)
                    {
                        return Err(invalid());
                    }
                    9
                }
                H2CapturedFrame::Priority {
                    stream, dependency, ..
                } => {
                    if *stream == 0
                        || StreamId::checked(*stream).is_err()
                        || StreamId::checked(*dependency).is_err()
                        || stream == dependency
                    {
                        return Err(invalid());
                    }
                    11
                }
            };
            bytes = bytes.checked_add(length).ok_or_else(bounded)?;
            if bytes > limits.bytes {
                return Err(bounded());
            }
        }
        let mut writer = CanonicalWriter::new(
            if structural {
                CanonicalDomain::H2Structure
            } else {
                CanonicalDomain::H2
            },
            limits.bytes,
        )?;
        writer.u8(self.completeness.tag())?;
        // Keep acknowledgements in diagnostic samples, but regenerate them
        // from the peer exchange instead of treating their timing as identity.
        let frames = self.frames.iter().filter(|frame| {
            !structural || !omit_acknowledgements || !frame.is_protocol_generated()
        });
        writer.u64(frames.clone().count() as u64)?;
        for frame in frames {
            match frame {
                H2CapturedFrame::Settings { ack, entries } => {
                    writer.u8(0)?;
                    writer.u8(u8::from(*ack))?;
                    writer.u64(entries.len() as u64)?;
                    if structural {
                        let mut ordered: Vec<_> = entries.iter().collect();
                        ordered.sort_by_key(|entry| entry.id);
                        for entry in ordered {
                            writer.u16(entry.id)?;
                            writer.u32(entry.value)?;
                        }
                    } else {
                        for entry in entries {
                            writer.u16(entry.id)?;
                            writer.u32(entry.value)?;
                        }
                    }
                }
                H2CapturedFrame::WindowUpdate { stream, increment } => {
                    writer.u8(1)?;
                    writer.u32(*stream)?;
                    writer.u32(*increment)?;
                }
                H2CapturedFrame::Priority {
                    stream,
                    dependency,
                    weight,
                    exclusive,
                } => {
                    writer.u8(2)?;
                    writer.u32(*stream)?;
                    writer.u32(*dependency)?;
                    writer.u8(*weight)?;
                    writer.u8(u8::from(*exclusive))?;
                }
            }
        }
        Ok(writer.finish())
    }

    pub fn from_canonical(
        value: &CanonicalValue,
        limits: H2CaptureLimits,
    ) -> Result<Self, ProfileDataError> {
        Self::decode(value, limits, false)
    }

    pub(super) fn decode(
        value: &CanonicalValue,
        limits: H2CaptureLimits,
        structural: bool,
    ) -> Result<Self, ProfileDataError> {
        let domain = if structural {
            CanonicalDomain::H2Structure
        } else {
            CanonicalDomain::H2
        };
        value.verify(domain, limits.bytes)?;
        let mut reader = CanonicalReader::new(&value.bytes, domain)?;
        let completeness = ProfileCaptureCompleteness::from_tag(reader.u8()?)?;
        completeness.require_complete("H2 early capture")?;
        let count = reader.count(limits.frames.min(limits.bytes))?;
        let mut remaining = limits.settings.min(limits.bytes / 6);
        let mut frames = Vec::new();
        for _ in 0..count {
            frames.push(match reader.u8()? {
                0 => {
                    let ack = boolean(&mut reader)?;
                    let count = reader.count(remaining)?;
                    remaining -= count;
                    let mut entries = Vec::new();
                    for _ in 0..count {
                        entries.push(H2CapturedSetting {
                            id: reader.u16()?,
                            value: reader.u32()?,
                        });
                    }
                    H2CapturedFrame::Settings {
                        ack,
                        entries: entries.into(),
                    }
                }
                1 => H2CapturedFrame::WindowUpdate {
                    stream: reader.u32()?,
                    increment: reader.u32()?,
                },
                2 => H2CapturedFrame::Priority {
                    stream: reader.u32()?,
                    dependency: reader.u32()?,
                    weight: reader.u8()?,
                    exclusive: boolean(&mut reader)?,
                },
                _ => return Err(invalid()),
            });
        }
        reader.finish()?;
        let capture = Self {
            completeness,
            frames: frames.into(),
        };
        if capture.encode(limits, structural)?.bytes != value.bytes
            && (!structural
                || capture.encode_with_ack_policy(limits, true, false)?.bytes != value.bytes)
        {
            return Err(invalid());
        }
        Ok(capture)
    }
}

fn boolean(reader: &mut CanonicalReader<'_>) -> Result<bool, ProfileDataError> {
    match reader.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invalid()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{
        CaptureLevel, CapturedSlot, CapturedSlotKind, JointCapture, JointCaptureLimits,
        OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture,
    };
    use rama_core::bytes::BytesMut;
    use rama_http::proto::h2::frame::{
        EarlyFrameStreamContext, Head, Kind, Settings, StreamId, WindowUpdate,
    };
    use sha2::{Digest as _, Sha256};

    fn source(entries: &[(u16, u32)]) -> EarlyFrameCapture {
        let payload: Vec<u8> = entries
            .iter()
            .flat_map(|(id, value)| id.to_be_bytes().into_iter().chain(value.to_be_bytes()))
            .collect();
        let settings = Settings::load_observed(
            Head::new(Kind::Settings, 0, StreamId::zero()),
            &payload,
            true,
        )
        .unwrap();
        let mut recorder = EarlyFrameStreamContext::new_recorder();
        recorder.record_settings_frame(&settings);
        recorder.record_windows_update_frame(WindowUpdate::new(StreamId::zero(), 100));
        recorder.freeze_recorder().unwrap()
    }
    fn captured(entries: &[(u16, u32)]) -> H2Capture {
        H2Capture::capture(&source(entries), H2CaptureLimits::default()).unwrap()
    }
    fn resign(mut value: CanonicalValue, offset: usize, replacement: u8) -> CanonicalValue {
        value.bytes[offset] = replacement;
        value.id.0 = Sha256::digest(&value.bytes).into();
        value
    }

    #[test]
    fn acknowledgements_do_not_change_h2_structure_or_replay() {
        let limits = H2CaptureLimits::default();
        let plain = captured(&[(1, 4096)]);
        let mut frames = plain.frames.clone().into_vec();
        frames.insert(
            1,
            H2CapturedFrame::Settings {
                ack: true,
                entries: Box::default(),
            },
        );
        let acknowledged = H2Capture {
            frames: frames.into(),
            ..plain
        };
        assert_ne!(
            plain.canonical(limits).unwrap().id,
            acknowledged.canonical(limits).unwrap().id
        );
        assert_eq!(
            plain.structural(limits).unwrap().id,
            acknowledged.structural(limits).unwrap().id
        );
        assert_eq!(
            plain.replay_frames(limits).unwrap(),
            acknowledged.replay_frames(limits).unwrap()
        );
    }

    #[test]
    fn h2_canonical_bytes_match_independent_vectors() {
        let limits = H2CaptureLimits::default();
        let capture = captured(&[(1, 4096), (0xffff, 7)]);
        for (value, expected, digest) in [
            (capture.canonical(limits).unwrap(), b"\x72\x61\x6d\x61\x2d\x70\x72\x6f\x66\x69\x6c\x65\x00\x00\x01\x00\x0c\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x00\x00\x10\x00\xff\xff\x00\x00\x00\x07\x01\x00\x00\x00\x00\x00\x00\x00\x64".as_slice(), [0xce, 0x94, 0x9f, 0x08, 0x46, 0x1c, 0x46, 0x62, 0xf7, 0x98, 0x30, 0xda, 0x69, 0xf6, 0x06, 0x38, 0xa4, 0x88, 0xe5, 0xe6, 0x09, 0x22, 0x27, 0x4a, 0x86, 0x46, 0xab, 0x1d, 0xea, 0x34, 0xa8, 0x22]),
            (capture.structural(limits).unwrap(), b"\x72\x61\x6d\x61\x2d\x70\x72\x6f\x66\x69\x6c\x65\x00\x00\x01\x00\x0d\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x00\x00\x10\x00\xff\xff\x00\x00\x00\x07\x01\x00\x00\x00\x00\x00\x00\x00\x64".as_slice(), [0xd3, 0x79, 0x31, 0x7b, 0x41, 0x2f, 0x0a, 0x2a, 0x91, 0xad, 0x05, 0xf6, 0x69, 0x48, 0xee, 0xed, 0xdb, 0xa9, 0x0e, 0xfb, 0xa0, 0xf2, 0x28, 0x32, 0x7f, 0xac, 0x60, 0x72, 0x7b, 0x39, 0x86, 0xb3]),
        ] {
            assert_eq!(value.bytes.as_ref(), expected);
            assert_eq!(value.id.0, digest);
        }
    }

    #[test]
    fn h2_wire_capture_preserves_unknown_duplicates_and_frame_order() {
        let limits = H2CaptureLimits::default();
        let capture = captured(&[(1, 4096), (0xfefe, 99), (1, 8192)]);
        let value = capture.canonical(limits).unwrap();
        let restored = H2Capture::from_canonical(&value, limits).unwrap();
        assert_eq!(
            serde_json::to_vec(&capture).unwrap(),
            serde_json::to_vec(&restored).unwrap()
        );
        assert!(
            matches!(&restored.frames[0], H2CapturedFrame::Settings { ack: false, entries } if entries.len() == 3 && entries[1].id == 0xfefe && entries[1].value == 99 && entries[2].value == 8192)
        );
        let mut reversed = restored.clone();
        reversed.frames.reverse();
        reversed.canonical(limits).unwrap_err();
        let mut frames = restored.frames.into_vec();
        frames.push(H2CapturedFrame::WindowUpdate {
            stream: 0,
            increment: 200,
        });
        let mut ordered = H2Capture {
            completeness: ProfileCaptureCompleteness::Complete,
            frames: frames.into(),
        };
        let first = ordered.canonical(limits).unwrap();
        let structure = ordered.structural(limits).unwrap();
        ordered.frames.swap(1, 2);
        assert_ne!(first.id, ordered.canonical(limits).unwrap().id);
        assert_ne!(structure.id, ordered.structural(limits).unwrap().id);
    }

    #[test]
    fn h2_replay_compiles_exact_settings_and_early_frame_order() {
        let capture = captured(&[(1, 4_096), (0xfefe, 99), (1, 8_192)]);
        let frames = capture.replay_frames(H2CaptureLimits::default()).unwrap();
        assert_eq!(frames.len(), 2);
        let EarlyFrame::Settings(settings) = &frames[0] else {
            panic!("initial frame must remain SETTINGS");
        };
        let mut encoded = BytesMut::new();
        settings.encode(&mut encoded);
        assert_eq!(
            &encoded[9..],
            &[
                0, 1, 0, 0, 16, 0, 0xfe, 0xfe, 0, 0, 0, 99, 0, 1, 0, 0, 32, 0,
            ]
        );
        assert!(matches!(frames[1], EarlyFrame::WindowUpdate(_)));
    }

    #[test]
    fn h2_structure_keeps_duplicate_setting_semantics() {
        let limits = H2CaptureLimits::default();
        let first = captured(&[(1, 4096), (0xfefe, 99), (1, 8192)]);
        let reordered = captured(&[(0xfefe, 99), (1, 4096), (1, 8192)]);
        let changed = captured(&[(1, 8192), (0xfefe, 99), (1, 4096)]);
        assert_ne!(
            first.canonical(limits).unwrap().id,
            reordered.canonical(limits).unwrap().id
        );
        assert_eq!(
            first.structural(limits).unwrap().id,
            reordered.structural(limits).unwrap().id
        );
        assert_ne!(
            first.structural(limits).unwrap().id,
            changed.structural(limits).unwrap().id
        );
        let value = first.structural(limits).unwrap();
        value
            .validate_content(CanonicalDomain::H2Structure, limits.bytes)
            .unwrap();
    }

    #[test]
    fn h2_incomplete_or_legacy_observations_do_not_gain_profile_capability() {
        let limits = H2CaptureLimits::default();
        let legacy: EarlyFrameCapture =
            serde_json::from_slice(&serde_json::to_vec(&source(&[(1, 1)])).unwrap()).unwrap();
        H2Capture::capture(&legacy, limits).unwrap_err();
        let partial = source(&vec![(0xffff, 1); 257]);
        assert!(partial.is_complete());
        H2Capture::capture(&partial, limits).unwrap_err();
        let mut recorder = EarlyFrameStreamContext::new_recorder();
        for _ in 0..17 {
            recorder.record_windows_update_frame(WindowUpdate::new(StreamId::zero(), 1));
        }
        H2Capture::capture(&recorder.freeze_recorder().unwrap(), limits).unwrap_err();
        let mut capture = captured(&[(1, 1)]);
        let canonical = capture.canonical(limits).unwrap();
        capture.completeness = ProfileCaptureCompleteness::Incomplete;
        capture.canonical(limits).unwrap_err();
        capture.structural(limits).unwrap_err();
        for tag in [0, 2, 255] {
            H2Capture::from_canonical(&resign(canonical.clone(), 17, tag), limits).unwrap_err();
        }
    }

    #[test]
    fn h2_capture_checks_aggregate_budgets_and_canonical_bytes() {
        let base = H2CaptureLimits::default();
        let source = source(&[(1, 4096), (0xffff, 7)]);
        let capture = H2Capture::capture(&source, base).unwrap();
        let value = capture.canonical(base).unwrap();
        let exact = H2CaptureLimits {
            frames: 2,
            settings: 2,
            bytes: value.bytes.len(),
        };
        H2Capture::capture(&source, exact).unwrap();
        H2Capture::from_canonical(&value, exact).unwrap();
        for limits in [
            H2CaptureLimits { frames: 1, ..exact },
            H2CaptureLimits {
                settings: 1,
                ..exact
            },
            H2CaptureLimits {
                bytes: exact.bytes - 1,
                ..exact
            },
        ] {
            H2Capture::capture(&source, limits).unwrap_err();
            capture.canonical(limits).unwrap_err();
            capture.structural(limits).unwrap_err();
            H2Capture::from_canonical(&value, limits).unwrap_err();
        }
        for end in 0..value.bytes.len() {
            let mut shortened = value.clone();
            shortened.bytes = shortened.bytes[..end].into();
            shortened.id.0 = Sha256::digest(&shortened.bytes).into();
            H2Capture::from_canonical(&shortened, base).unwrap_err();
        }
        let mut corrupt = value.clone();
        corrupt.id.0[0] ^= 1;
        H2Capture::from_canonical(&corrupt, base).unwrap_err();
        H2Capture::from_canonical(&resign(value.clone(), 27, 2), base).unwrap_err();
        H2Capture::from_canonical(&resign(value.clone(), 27, 1), base).unwrap_err(); // ACK with entries
        H2Capture::from_canonical(&resign(value, 26, 255), base).unwrap_err();
    }

    #[test]
    fn h2_hand_built_frames_enforce_protocol_limits() {
        let limits = H2CaptureLimits::default();
        for frame in [
            H2CapturedFrame::WindowUpdate {
                stream: 0,
                increment: 0,
            },
            H2CapturedFrame::WindowUpdate {
                stream: 1 << 31,
                increment: 1,
            },
            H2CapturedFrame::WindowUpdate {
                stream: 0,
                increment: 1 << 31,
            },
            H2CapturedFrame::Priority {
                stream: 0,
                dependency: 1,
                weight: 0,
                exclusive: false,
            },
            H2CapturedFrame::Priority {
                stream: 1,
                dependency: 1,
                weight: 0,
                exclusive: false,
            },
            H2CapturedFrame::Priority {
                stream: 1 << 31,
                dependency: 0,
                weight: 255,
                exclusive: true,
            },
            H2CapturedFrame::Priority {
                stream: 1,
                dependency: 1 << 31,
                weight: 255,
                exclusive: true,
            },
        ] {
            let capture = H2Capture {
                completeness: ProfileCaptureCompleteness::Complete,
                frames: vec![
                    H2CapturedFrame::Settings {
                        ack: false,
                        entries: Box::default(),
                    },
                    frame,
                ]
                .into(),
            };
            capture.canonical(limits).unwrap_err();
            capture.structural(limits).unwrap_err();
        }
        for (id, value) in [
            (2, 2),
            (8, 2),
            (9, 2),
            (4, 1 << 31),
            (5, (1 << 14) - 1),
            (5, 1 << 24),
        ] {
            let capture = H2Capture {
                completeness: ProfileCaptureCompleteness::Complete,
                frames: vec![H2CapturedFrame::Settings {
                    ack: false,
                    entries: vec![H2CapturedSetting { id, value }].into(),
                }]
                .into(),
            };
            capture.canonical(limits).unwrap_err();
            capture.structural(limits).unwrap_err();
        }
    }

    #[test]
    fn h2_capture_requires_initial_non_ack_settings() {
        let limits = H2CaptureLimits::default();
        for frames in [
            vec![],
            vec![H2CapturedFrame::Settings {
                ack: true,
                entries: Box::default(),
            }],
            vec![H2CapturedFrame::WindowUpdate {
                stream: 0,
                increment: 1,
            }],
        ] {
            let capture = H2Capture {
                completeness: ProfileCaptureCompleteness::Complete,
                frames: frames.into(),
            };
            capture.canonical(limits).unwrap_err();
            capture.structural(limits).unwrap_err();
        }
        let capture = H2Capture {
            completeness: ProfileCaptureCompleteness::Complete,
            frames: vec![
                H2CapturedFrame::Settings {
                    ack: false,
                    entries: Box::default(),
                },
                H2CapturedFrame::Settings {
                    ack: true,
                    entries: Box::default(),
                },
            ]
            .into(),
        };
        let value = capture.canonical(limits).unwrap();
        H2Capture::from_canonical(&value, limits).unwrap();
    }

    #[test]
    fn h2_joint_slots_remain_connection_owned_and_tcp_bound() {
        let limits = JointCaptureLimits::default();
        let mut joint = JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Connection,
            slots: vec![CapturedSlot {
                kind: CapturedSlotKind::Http2EarlyFrames,
                value: captured(&[(1, 4096)])
                    .canonical(H2CaptureLimits::default())
                    .unwrap(),
            }]
            .into(),
        };
        let value = joint.canonical(limits).unwrap();
        JointCapture::from_canonical(&value, limits).unwrap();
        joint
            .structural(limits)
            .unwrap()
            .validate_content(CanonicalDomain::JointStructure, limits.bytes)
            .unwrap();
        joint.level = CaptureLevel::Request;
        joint.canonical(limits).unwrap_err();
        joint.structural(limits).unwrap_err();
        joint.level = CaptureLevel::Connection;
        let mut slots = joint.slots.into_vec();
        slots.push(CapturedSlot {
            kind: CapturedSlotKind::QuicVersions,
            value: OrderedProtocolCapture::capture(
                ProfileCaptureCompleteness::Complete,
                OrderNamespace::QuicVersion,
                [(1, [])],
                OrderCaptureLimits::default(),
            )
            .unwrap()
            .canonical(OrderCaptureLimits::default())
            .unwrap(),
        });
        joint.slots = slots.into();
        joint.canonical(limits).unwrap_err();
        joint.structural(limits).unwrap_err();
    }
}
