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
            let setting = Setting::load(raw);
            setting_order.push(setting.id);
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
                        return Err(Error::InvalidSettingValue);
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
                SettingId::NoRfc7540Priorities => {
                    settings.config.no_rfc7540_priorities = Some(setting.value);
                }
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
