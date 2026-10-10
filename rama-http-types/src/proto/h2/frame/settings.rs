use std::fmt;

use super::{
    Error, Frame, FrameSize, Head, Kind, Setting, SettingId, SettingOrder, SettingsConfig,
    StreamId, util,
};

use rama_core::bytes::BytesMut;
use rama_core::telemetry::tracing;
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    pub flags: SettingsFlags,
    pub config: SettingsConfig,
    /// Optional bounded wire observation. Semantic configuration is independent.
    #[serde(skip)]
    pub observation: Option<Box<SettingsObservation>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsObservation {
    pub entries: Box<[Setting]>,
    pub complete: bool,
}

#[derive(Copy, Clone, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct SettingsFlags(u8);

const ACK: u8 = 0x1;
const ALL: u8 = ACK;

/// The default value of SETTINGS_HEADER_TABLE_SIZE
pub const DEFAULT_SETTINGS_HEADER_TABLE_SIZE: usize = 4_096;

/// The default value of SETTINGS_INITIAL_WINDOW_SIZE
pub const DEFAULT_INITIAL_WINDOW_SIZE: u32 = 65_535;

/// The default value of MAX_FRAME_SIZE
pub const DEFAULT_MAX_FRAME_SIZE: FrameSize = 16_384;

/// INITIAL_WINDOW_SIZE upper bound
const MAX_INITIAL_WINDOW_SIZE: usize = (1 << 31) - 1;

/// MAX_FRAME_SIZE upper bound
pub const MAX_MAX_FRAME_SIZE: FrameSize = (1 << 24) - 1;

// ===== impl Settings =====

impl Settings {
    #[must_use]
    pub fn ack() -> Self {
        Self {
            flags: SettingsFlags::ack(),
            ..Self::default()
        }
    }

    rama_utils::macros::generate_set_and_with! {
        pub fn config(mut self, config: SettingsConfig) -> Self {
            self.config = config;
            self
        }
    }

    pub fn merge(&mut self, other: Self) {
        self.config.merge(other.config);
    }

    pub fn load(head: Head, payload: &[u8]) -> Result<Self, Error> {
        Self::load_inner(head, payload, Some(usize::MAX))
    }

    /// Decode semantic settings without allocating optional observation data.
    /// When enabled, at most 256 ordered occurrences are retained. Exceeding the
    /// observation limit does not reject otherwise valid peer settings.
    pub fn load_observed(head: Head, payload: &[u8], observe: bool) -> Result<Self, Error> {
        let mut settings = Self::load_inner(head, payload, observe.then_some(256))?;
        if observe {
            const MAXIMUM: usize = 256;
            let count = payload.len() / 6;
            let entries = payload
                .as_chunks::<6>()
                .0
                .iter()
                .take(MAXIMUM)
                .map(|entry| Setting::load(entry))
                .collect::<Result<Vec<_>, _>>()?;
            settings.observation = Some(Box::new(SettingsObservation {
                entries: entries.into_boxed_slice(),
                complete: count <= MAXIMUM,
            }));
        }
        Ok(settings)
    }

    fn load_inner(head: Head, payload: &[u8], order_limit: Option<usize>) -> Result<Self, Error> {
        debug_assert_eq!(head.kind(), super::Kind::Settings);

        if !head.stream_id().is_zero() {
            return Err(Error::InvalidStreamId);
        }

        // Load the flag
        let flag = SettingsFlags::load(head.flag());

        if flag.is_ack() {
            // Ensure that the payload is empty
            if !payload.is_empty() {
                return Err(Error::InvalidPayloadLength);
            }

            // Return the ACK frame
            return Ok(Self::ack());
        }

        // Ensure the payload length is correct, each setting is 6 bytes long.
        if !payload.len().is_multiple_of(6) {
            tracing::debug!("invalid settings payload length; len={:?}", payload.len());
            return Err(Error::InvalidPayloadAckSettings);
        }

        let mut settings = Self::default();
        debug_assert!(!settings.flags.is_ack());

        let mut setting_order = SettingOrder::default();

        for raw in payload.chunks(6) {
            let setting = Setting::load(raw)?;
            if order_limit.is_some_and(|limit| setting_order.len() < limit) {
                setting_order.push(setting.id);
            }
            match setting.id {
                SettingId::HeaderTableSize => {
                    settings.config.header_table_size = Some(setting.value);
                }
                SettingId::EnablePush => match setting.value {
                    0 | 1 => {
                        settings.config.enable_push = Some(setting.value);
                    }
                    _ => {
                        return Err(Error::InvalidSettingValue);
                    }
                },
                SettingId::MaxConcurrentStreams => {
                    settings.config.max_concurrent_streams = Some(setting.value);
                }
                SettingId::InitialWindowSize => {
                    if setting.value as usize > MAX_INITIAL_WINDOW_SIZE {
                        // RFC 9113 §6.5.2: this is specifically a FLOW_CONTROL_ERROR,
                        // not a generic PROTOCOL_ERROR.
                        return Err(Error::InvalidInitialWindowSize);
                    } else {
                        settings.config.initial_window_size = Some(setting.value);
                    }
                }
                SettingId::MaxFrameSize => {
                    if (DEFAULT_MAX_FRAME_SIZE..=MAX_MAX_FRAME_SIZE).contains(&setting.value) {
                        settings.config.max_frame_size = Some(setting.value);
                    } else {
                        return Err(Error::InvalidSettingValue);
                    }
                }
                SettingId::MaxHeaderListSize => {
                    settings.config.max_header_list_size = Some(setting.value);
                }
                SettingId::EnableConnectProtocol => match setting.value {
                    0 | 1 => {
                        settings.config.enable_connect_protocol = Some(setting.value);
                    }
                    _ => {
                        return Err(Error::InvalidSettingValue);
                    }
                },
                SettingId::NoRfc7540Priorities => match setting.value {
                    0 | 1 => settings.config.no_rfc7540_priorities = Some(setting.value),
                    _ => return Err(Error::InvalidSettingValue),
                },
                SettingId::Unknown(id) => {
                    tracing::trace!(
                        "ignore unknown h2 frame setting w/ id {id}: value = {}",
                        setting.value
                    );
                }
            }
        }

        if !setting_order.is_empty() {
            settings.config.setting_order = Some(setting_order);
        }

        Ok(settings)
    }

    fn payload_len(&self) -> usize {
        let mut len = 0;
        self.for_each(|_| len += 6);
        len
    }

    pub fn encode(&self, dst: &mut BytesMut) {
        // Create & encode an appropriate frame head
        let head = Head::new(Kind::Settings, self.flags.into(), StreamId::zero());
        let payload_len = self.payload_len();

        tracing::trace!("encoding SETTINGS; len={}", payload_len);

        head.encode(payload_len, dst);

        // Encode the settings
        self.for_each(|setting| {
            tracing::trace!("encoding setting; val={:?}", setting);
            setting.encode(dst)
        });
    }

    fn for_each<F: FnMut(Setting)>(&self, mut f: F) {
        let mut settings_order = self.config.setting_order.clone().unwrap_or_default();
        settings_order.extend_with_default();

        for id in settings_order {
            match id {
                SettingId::HeaderTableSize => {
                    if let Some(value) = self.config.header_table_size {
                        f(Setting { id, value });
                    }
                }
                SettingId::EnablePush => {
                    if let Some(value) = self.config.enable_push {
                        f(Setting { id, value });
                    }
                }
                SettingId::MaxConcurrentStreams => {
                    if let Some(value) = self.config.max_concurrent_streams {
                        f(Setting { id, value });
                    }
                }
                SettingId::InitialWindowSize => {
                    if let Some(value) = self.config.initial_window_size {
                        f(Setting { id, value });
                    }
                }
                SettingId::MaxFrameSize => {
                    if let Some(value) = self.config.max_frame_size {
                        f(Setting { id, value });
                    }
                }
                SettingId::MaxHeaderListSize => {
                    if let Some(value) = self.config.max_header_list_size {
                        f(Setting { id, value });
                    }
                }
                SettingId::EnableConnectProtocol => {
                    if let Some(value) = self.config.enable_connect_protocol {
                        f(Setting { id, value });
                    }
                }
                SettingId::NoRfc7540Priorities => {
                    if let Some(value) = self.config.no_rfc7540_priorities {
                        f(Setting { id, value });
                    }
                }
                SettingId::Unknown(id) => {
                    tracing::trace!("ignore unknown setting w/ id {id}, nop apply",)
                }
            }
        }
    }
}

impl<T> From<Settings> for Frame<T> {
    fn from(src: Settings) -> Self {
        Self::Settings(src)
    }
}

impl fmt::Debug for Settings {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut builder = f.debug_struct("Settings");
        builder.field("flags", &self.flags);
        builder.field("config", &self.config);
        builder.finish()
    }
}

// ===== impl SettingsFlags =====

impl SettingsFlags {
    pub fn empty() -> Self {
        Self(0)
    }

    pub fn load(bits: u8) -> Self {
        Self(bits & ALL)
    }

    pub fn ack() -> Self {
        Self(ACK)
    }

    pub fn is_ack(self) -> bool {
        self.0 & ACK == ACK
    }
}

impl From<SettingsFlags> for u8 {
    fn from(src: SettingsFlags) -> Self {
        src.0
    }
}

impl fmt::Debug for SettingsFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        util::debug_flags(f, self.0)
            .flag_if(self.is_ack(), "ACK")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    /// RFC 9113 §6.5.2: a SETTINGS_INITIAL_WINDOW_SIZE value above
    /// 2^31-1 MUST be treated as a FLOW_CONTROL_ERROR — distinct from a
    /// generic PROTOCOL_ERROR. Verify the dedicated error variant fires.
    #[test]
    fn settings_initial_window_size_overflow_is_flow_control_error() {
        let head = Head::new(Kind::Settings, 0, StreamId::zero());
        // SettingId::InitialWindowSize = 0x4, value = 2^31 (one over the cap).
        let mut payload = [0u8; 6];
        payload[0] = 0x00;
        payload[1] = 0x04; // setting id
        payload[2..6].copy_from_slice(&(1u32 << 31).to_be_bytes());

        let err = Settings::load(head, &payload).expect_err("must reject");
        assert_matches!(
            err,
            Error::InvalidInitialWindowSize,
            "expected InvalidInitialWindowSize, got {err:?}",
        );
    }

    /// A valid INITIAL_WINDOW_SIZE just at the boundary (2^31-1) must succeed.
    #[test]
    fn settings_initial_window_size_max_ok() {
        let head = Head::new(Kind::Settings, 0, StreamId::zero());
        let mut payload = [0u8; 6];
        payload[0] = 0x00;
        payload[1] = 0x04;
        payload[2..6].copy_from_slice(&((1u32 << 31) - 1).to_be_bytes());

        let settings = Settings::load(head, &payload).expect("must accept boundary");
        assert_eq!(settings.config.initial_window_size, Some((1 << 31) - 1));
    }
}

#[cfg(test)]
mod observation_tests {
    use super::*;
    use crate::proto::h2::frame::Kind;

    #[test]
    fn settings_observation_retains_unknowns_and_repeated_values_only_when_enabled() {
        let entries = [(1_u16, 100_u32), (0x42, 99), (1, 200), (0x42, 7)];
        let mut payload = Vec::new();
        for (id, value) in entries {
            payload.extend_from_slice(&id.to_be_bytes());
            payload.extend_from_slice(&value.to_be_bytes());
        }
        let head = Head::new(Kind::Settings, 0, StreamId::zero());
        let observed = Settings::load_observed(head, &payload, true).unwrap();
        assert_eq!(observed.config.header_table_size, Some(200));
        let wire = observed.observation.unwrap();
        assert!(wire.complete);
        assert_eq!(
            wire.entries
                .iter()
                .map(|entry| (u16::from(entry.id), entry.value))
                .collect::<Vec<_>>(),
            entries
        );
        let ordinary = Settings::load_observed(head, &payload, false).unwrap();
        assert_eq!(ordinary.config.header_table_size, Some(200));
        assert!(ordinary.observation.is_none());
        assert!(ordinary.config.setting_order.is_none());
        let legacy = Settings::load(head, &payload).unwrap();
        assert!(legacy.observation.is_none());
        assert!(legacy.config.setting_order.is_some());
    }

    #[test]
    fn settings_observation_caps_never_change_protocol_admission() {
        for count in [0, 1, 255, 256, 257, 1024] {
            let mut payload = Vec::new();
            for value in 0..count {
                payload.extend_from_slice(&0x42_u16.to_be_bytes());
                payload.extend_from_slice(&(value as u32).to_be_bytes());
            }
            let head = Head::new(Kind::Settings, 0, StreamId::zero());
            let observed = Settings::load_observed(head, &payload, true).unwrap();
            let wire = observed.observation.unwrap();
            assert_eq!(wire.entries.len(), count.min(256));
            assert_eq!(wire.complete, count <= 256);
            assert!(
                Settings::load_observed(head, &payload, false)
                    .unwrap()
                    .observation
                    .is_none()
            );
        }
        let head = Head::new(Kind::Settings, 0, StreamId::zero());
        for observe in [false, true] {
            Settings::load_observed(head, &[0, 2, 0, 0, 0, 2], observe).unwrap_err();
            Settings::load_observed(head, &[0], observe).unwrap_err();
            let ack = Head::new(Kind::Settings, 1, StreamId::zero());
            Settings::load_observed(ack, &[0; 6], observe).unwrap_err();
        }
    }
}

#[cfg(test)]
mod boolean_setting_tests {
    use super::*;

    #[test]
    fn all_boolean_settings_reject_non_boolean_values_on_every_decode_path() {
        let head = Head::new(Kind::Settings, 0, StreamId::zero());
        for id in [2u16, 8, 9] {
            for value in [0u32, 1, 2, 255, u32::MAX] {
                let payload: Vec<_> = id
                    .to_be_bytes()
                    .into_iter()
                    .chain(value.to_be_bytes())
                    .collect();
                for observe in [None, Some(false), Some(true)] {
                    let result = match observe {
                        None => Settings::load(head, &payload),
                        Some(observe) => Settings::load_observed(head, &payload, observe),
                    };
                    if value <= 1 {
                        result.unwrap();
                    } else {
                        assert!(
                            matches!(result, Err(Error::InvalidSettingValue)),
                            "id={id}, value={value}, observe={observe:?}"
                        );
                    }
                }
            }
        }
    }
}
