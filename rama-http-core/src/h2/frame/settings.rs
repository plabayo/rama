use std::fmt;

use crate::h2::frame::{Error, Frame, FrameSize, Head, Kind, StreamId, util};
use rama_core::bytes::BytesMut;

use rama_http_types::proto::h2::frame::SettingOrder;
pub use rama_http_types::proto::h2::frame::{Setting, SettingId, SettingsConfig};

#[derive(Clone, Default, Eq, PartialEq)]
pub struct Settings {
    flags: SettingsFlags,
    pub(crate) config: SettingsConfig,
}

#[derive(Copy, Clone, Eq, PartialEq, Default)]
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
    pub fn ack() -> Settings {
        Settings {
            flags: SettingsFlags::ack(),
            ..Settings::default()
        }
    }

    pub fn is_ack(&self) -> bool {
        self.flags.is_ack()
    }

    pub fn initial_window_size(&self) -> Option<u32> {
        self.config.initial_window_size
    }

    pub fn set_config(&mut self, config: SettingsConfig) {
        self.config = config;
    }

    pub fn set_initial_window_size(&mut self, size: Option<u32>) {
        self.config.initial_window_size = size;
    }

    pub fn max_concurrent_streams(&self) -> Option<u32> {
        self.config.max_concurrent_streams
    }

    pub fn set_max_concurrent_streams(&mut self, max: Option<u32>) {
        self.config.max_concurrent_streams = max;
    }

    pub fn max_frame_size(&self) -> Option<u32> {
        self.config.max_frame_size
    }

    pub fn set_max_frame_size(&mut self, size: Option<u32>) {
        if let Some(val) = size {
            assert!((DEFAULT_MAX_FRAME_SIZE..=MAX_MAX_FRAME_SIZE).contains(&val));
        }
        self.config.max_frame_size = size;
    }

    pub fn max_header_list_size(&self) -> Option<u32> {
        self.config.max_header_list_size
    }

    pub fn set_max_header_list_size(&mut self, size: Option<u32>) {
        self.config.max_header_list_size = size;
    }

    pub fn is_push_enabled(&self) -> Option<bool> {
        self.config.enable_push.map(|val| val != 0)
    }

    pub fn set_enable_push(&mut self, enable: bool) {
        self.config.enable_push = Some(enable as u32);
    }

    pub fn is_extended_connect_protocol_enabled(&self) -> Option<bool> {
        self.config.enable_connect_protocol.map(|val| val != 0)
    }

    pub fn set_enable_connect_protocol(&mut self, val: Option<u32>) {
        self.config.enable_connect_protocol = val;
    }

    pub fn header_table_size(&self) -> Option<u32> {
        self.config.header_table_size
    }

    pub fn set_header_table_size(&mut self, size: Option<u32>) {
        self.config.header_table_size = size;
    }

    pub fn set_unknown_setting_9(&mut self, size: Option<u32>) {
        self.config.unknown_setting_9 = size;
    }

    pub fn set_setting_order(&mut self, order: Option<SettingOrder>) {
        self.config.setting_order = order;
    }

    pub fn load(head: Head, payload: &[u8]) -> Result<Settings, Error> {
        debug_assert_eq!(head.kind(), crate::h2::frame::Kind::Settings);

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
            return Ok(Settings::ack());
        }

        // Ensure the payload length is correct, each setting is 6 bytes long.
        if payload.len() % 6 != 0 {
            tracing::debug!("invalid settings payload length; len={:?}", payload.len());
            return Err(Error::InvalidPayloadAckSettings);
        }

        let mut settings = Settings::default();
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
                SettingId::Unknown(0x09) => {
                    settings.config.unknown_setting_9 = Some(setting.value);
                }
                SettingId::Unknown(id) => {
                    tracing::trace!(
                        %id,
                        value = %setting.value,
                        "ignore unknown h2 frame setting",
                    );
                }
            }
        }

        if !setting_order.is_empty() {
            settings.set_setting_order(Some(setting_order));
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
                SettingId::Unknown(0x09) => {
                    if let Some(value) = self.config.unknown_setting_9 {
                        f(Setting { id, value });
                    }
                }
                SettingId::Unknown(id) => {
                    tracing::trace!(
                        %id,
                        "ignore unknown setting, nop apply",
                    )
                }
            }
        }
    }
}

impl<T> From<Settings> for Frame<T> {
    fn from(src: Settings) -> Frame<T> {
        Frame::Settings(src)
    }
}

impl fmt::Debug for Settings {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut builder = f.debug_struct("Settings");
        builder.field("flags", &self.flags);
        builder.field("setting_order", &self.config.setting_order);

        self.for_each(|setting| match setting.id {
            SettingId::EnablePush => {
                builder.field("enable_push", &setting.value);
            }
            SettingId::HeaderTableSize => {
                builder.field("header_table_size", &setting.value);
            }
            SettingId::InitialWindowSize => {
                builder.field("initial_window_size", &setting.value);
            }
            SettingId::MaxConcurrentStreams => {
                builder.field("max_concurrent_streams", &setting.value);
            }
            SettingId::MaxFrameSize => {
                builder.field("max_frame_size", &setting.value);
            }
            SettingId::MaxHeaderListSize => {
                builder.field("max_header_list_size", &setting.value);
            }
            SettingId::EnableConnectProtocol => {
                builder.field("enable_connect_protocol", &setting.value);
            }
            SettingId::Unknown(0x09) => {
                builder.field("unknown_setting9", &setting.value);
            }
            SettingId::Unknown(id) => {
                builder.field(&format!("unknown_unknown_setting_{id}"), &setting.value);
            }
        });

        builder.finish()
    }
}

// ===== impl SettingsFlags =====

impl SettingsFlags {
    pub fn empty() -> SettingsFlags {
        SettingsFlags(0)
    }

    pub fn load(bits: u8) -> SettingsFlags {
        SettingsFlags(bits & ALL)
    }

    pub fn ack() -> SettingsFlags {
        SettingsFlags(ACK)
    }

    pub fn is_ack(&self) -> bool {
        self.0 & ACK == ACK
    }
}

impl From<SettingsFlags> for u8 {
    fn from(src: SettingsFlags) -> u8 {
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
