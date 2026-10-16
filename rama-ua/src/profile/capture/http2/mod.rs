//! Bounded H2 settings and early frames, captured before semantic collapse.

use rama_http::proto::h2::frame::{
    DEFAULT_MAX_FRAME_SIZE, EarlyFrame, EarlyFrameCapture, MAX_MAX_FRAME_SIZE, Priority, Setting,
    SettingId, Settings, StreamDependency, StreamId, WindowUpdate,
};
use rama_utils::octets::kib;
use serde::Serialize;

use crate::profile::{
    capture::completeness::ProfileCaptureCompleteness,
    format::canonical::{
        CanonicalDomain, CanonicalReader, CanonicalValue, CanonicalWriter, ProfileDataError,
    },
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

    pub(in crate::profile) fn decode(
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
mod tests;
