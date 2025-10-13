//! Akamai HTTP2 Fingerprinting implementation for Rama.
//!
//! The fingerprint format is: `S[;]|WU|P[,]|PS[,]`
//!
//! Where:
//! - S = SETTINGS frame parameters (id:value pairs, semicolon-separated)
//! - WU = WINDOW_UPDATE increment value (or "00" if not present)
//! - P = PRIORITY frames (stream_id:exclusive:depends_on:weight, comma-separated, or "0" if not present)
//! - PS = Pseudo-header order (m=method, p=path, a=authority, s=scheme, comma-separated)

use itertools::Itertools as _;
use rama_core::context::Extensions;
use rama_http_types::proto::h2::{
    PseudoHeader, PseudoHeaderOrder,
    frame::{
        EarlyFrame, EarlyFrameCapture,
        SettingId::{
            EnableConnectProtocol, EnablePush, HeaderTableSize, InitialWindowSize,
            MaxConcurrentStreams, MaxFrameSize, MaxHeaderListSize, NoRfc7540Priorities, Unknown,
        },
        StreamId,
    },
};
use std::fmt;

#[derive(Clone)]
pub struct AkamaiH2 {
    settings: Vec<(u16, u32)>,
    window_update: Option<u32>,
    priority_frames: Vec<AkamaiPriorityFrame>,
    pseudo_header_order: Vec<char>,
}

#[derive(Clone, Debug)]
struct AkamaiPriorityFrame {
    stream_id: u32,
    exclusive: bool,
    depends_on: u32,
    weight: u8,
}

impl AkamaiH2 {
    pub fn compute(ext: &Extensions) -> Result<Self, AkamaiH2ComputeError> {
        let early_frames = ext
            .get::<EarlyFrameCapture>()
            .ok_or(AkamaiH2ComputeError::MissingEarlyFrames)?;

        let pseudo_header_order = ext
            .get::<PseudoHeaderOrder>()
            .ok_or(AkamaiH2ComputeError::MissingPseudoHeaders)?;

        let mut settings = Vec::new();
        let mut window_update = None;
        let mut priority_frames = Vec::new();

        for frame in early_frames.iter() {
            match frame {
                EarlyFrame::Settings(s) => {
                    if !s.is_ack()
                        && let Some(order) = &s.config.setting_order
                    {
                        for setting_id in order.iter() {
                            let value = match setting_id {
                                HeaderTableSize => s.config.header_table_size,
                                EnablePush => s.config.enable_push,
                                MaxConcurrentStreams => s.config.max_concurrent_streams,
                                InitialWindowSize => s.config.initial_window_size,
                                MaxFrameSize => s.config.max_frame_size,
                                MaxHeaderListSize => s.config.max_header_list_size,
                                EnableConnectProtocol => s.config.enable_connect_protocol,
                                NoRfc7540Priorities => s.config.no_rfc7540_priorities,
                                Unknown(_) => None,
                            };
                            if let Some(val) = value {
                                settings.push((setting_id.into(), val));
                            }
                        }
                    }
                }
                EarlyFrame::WindowUpdate(wu) => {
                    // Only capture connection-level WINDOW_UPDATE (stream_id == 0)
                    if wu.stream_id == StreamId::zero() && window_update.is_none() {
                        window_update = Some(wu.size_increment);
                    }
                }
                EarlyFrame::Priority(p) => {
                    priority_frames.push(AkamaiPriorityFrame {
                        stream_id: p.stream_id.into(),
                        exclusive: p.dependency.is_exclusive,
                        depends_on: p.dependency.dependency_id.into(),
                        weight: p.dependency.weight,
                    });
                }
            }
        }

        let pseudo_order = pseudo_header_order
            .iter()
            .filter_map(|ph| match ph {
                PseudoHeader::Method => Some('m'),
                PseudoHeader::Path => Some('p'),
                PseudoHeader::Authority => Some('a'),
                PseudoHeader::Scheme => Some('s'),
                _ => None,
            })
            .collect();

        Ok(Self {
            settings,
            window_update,
            priority_frames,
            pseudo_header_order: pseudo_order,
        })
    }

    #[inline]
    #[must_use]
    pub fn to_human_string(&self) -> String {
        format!("{self:#?}")
    }

    fn fmt_as(&self, f: &mut fmt::Formatter<'_>, as_hash: bool) -> fmt::Result {
        let settings = self
            .settings
            .iter()
            .map(|(id, val)| format!("{id}:{val}"))
            .join(";");

        let window_update = self
            .window_update
            .map(|v| v.to_string())
            .unwrap_or_else(|| "00".to_owned());

        let priority = if self.priority_frames.is_empty() {
            "0".to_owned()
        } else {
            self.priority_frames
                .iter()
                .map(|p| {
                    format!(
                        "{}:{}:{}:{}",
                        p.stream_id,
                        if p.exclusive { 1 } else { 0 },
                        p.depends_on,
                        p.weight
                    )
                })
                .join(",")
        };

        let pseudo = self.pseudo_header_order.iter().join(",");

        // Format: S[;]|WU|P[,]|PS[,]
        let raw = format!("{settings}|{window_update}|{priority}|{pseudo}");

        if as_hash {
            write!(f, "{}", md5_hash(&raw))
        } else {
            write!(f, "{raw}")
        }
    }
}

impl fmt::Display for AkamaiH2 {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_as(f, true)
    }
}

impl fmt::Debug for AkamaiH2 {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_as(f, false)
    }
}

fn md5_hash(s: &str) -> String {
    let hash = md5::compute(s.as_bytes());
    format!("{hash:x}")
}

#[derive(Debug, Clone)]
pub enum AkamaiH2ComputeError {
    MissingEarlyFrames,
    MissingPseudoHeaders,
}

impl fmt::Display for AkamaiH2ComputeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEarlyFrames => {
                write!(f, "AkamaiH2 Compute Error: missing early frame capture")
            }
            Self::MissingPseudoHeaders => {
                write!(f, "AkamaiH2 Compute Error: missing pseudo-header order")
            }
        }
    }
}

impl std::error::Error for AkamaiH2ComputeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_http_types::proto::h2::{
        PseudoHeaderOrder,
        frame::{
            EarlyFrame, Priority, SettingOrder, Settings, SettingsConfig, StreamDependency,
            StreamId, WindowUpdate,
        },
    };

    fn create_early_frame_capture(frames: &[EarlyFrame]) -> EarlyFrameCapture {
        serde_json::from_str(&serde_json::to_string(frames).unwrap()).unwrap()
    }

    #[test]
    fn test_akamai_h2_basic() {
        let mut ext = Extensions::default();

        let mut pseudo_order = PseudoHeaderOrder::new();
        pseudo_order.push(PseudoHeader::Method);
        pseudo_order.push(PseudoHeader::Path);
        pseudo_order.push(PseudoHeader::Authority);
        pseudo_order.push(PseudoHeader::Scheme);
        ext.insert(pseudo_order);

        let mut frames = Vec::new();

        let settings_config = SettingsConfig {
            header_table_size: Some(65536),
            enable_push: Some(0),
            initial_window_size: Some(131072),
            max_frame_size: Some(16384),
            setting_order: Some(SettingOrder::from_iter([
                HeaderTableSize,
                EnablePush,
                InitialWindowSize,
                MaxFrameSize,
            ])),
            ..Default::default()
        };
        frames.push(EarlyFrame::Settings(Settings {
            config: settings_config,
            flags: Default::default(),
        }));

        frames.push(EarlyFrame::WindowUpdate(WindowUpdate {
            stream_id: StreamId::zero(),
            size_increment: 12517377,
        }));

        ext.insert(create_early_frame_capture(&frames));

        let akamai_h2 = AkamaiH2::compute(&ext).expect("compute akamai h2");

        let debug_str = format!("{akamai_h2:?}");
        assert_eq!(debug_str, "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s");

        let hash_str = format!("{akamai_h2}");
        assert_eq!(hash_str, "6ea73faa8fc5aac76bded7bd238f6433");
    }

    #[test]
    fn test_akamai_h2_with_priority() {
        let mut ext = Extensions::default();

        let mut pseudo_order = PseudoHeaderOrder::new();
        pseudo_order.push(PseudoHeader::Method);
        pseudo_order.push(PseudoHeader::Path);
        pseudo_order.push(PseudoHeader::Authority);
        pseudo_order.push(PseudoHeader::Scheme);
        ext.insert(pseudo_order);

        let mut frames = Vec::new();

        let settings_config = SettingsConfig {
            header_table_size: Some(65536),
            setting_order: Some(SettingOrder::from_iter([HeaderTableSize])),
            ..Default::default()
        };
        frames.push(EarlyFrame::Settings(Settings {
            config: settings_config,
            flags: Default::default(),
        }));

        frames.push(EarlyFrame::Priority(Priority {
            stream_id: StreamId::from(3),
            dependency: StreamDependency {
                dependency_id: StreamId::zero(),
                weight: 200,
                is_exclusive: false,
            },
        }));

        ext.insert(create_early_frame_capture(&frames));

        let akamai_h2 = AkamaiH2::compute(&ext).expect("compute akamai h2");

        let debug_str = format!("{akamai_h2:?}");
        assert!(debug_str.contains("3:0:0:200"), "debug_str: {debug_str}");
    }

    #[test]
    fn test_akamai_h2_no_window_update() {
        let mut ext = Extensions::default();

        let mut pseudo_order = PseudoHeaderOrder::new();
        pseudo_order.push(PseudoHeader::Method);
        pseudo_order.push(PseudoHeader::Scheme);
        pseudo_order.push(PseudoHeader::Path);
        pseudo_order.push(PseudoHeader::Authority);
        ext.insert(pseudo_order);

        let mut frames = Vec::new();

        let settings_config = SettingsConfig {
            header_table_size: Some(4096),
            enable_push: Some(1),
            setting_order: Some(SettingOrder::from_iter([HeaderTableSize, EnablePush])),
            ..Default::default()
        };
        frames.push(EarlyFrame::Settings(Settings {
            config: settings_config,
            flags: Default::default(),
        }));

        ext.insert(create_early_frame_capture(&frames));

        let akamai_h2 = AkamaiH2::compute(&ext).expect("compute akamai h2");

        // Should have "00" for window update when not present
        let debug_str = format!("{akamai_h2:?}");
        assert!(debug_str.contains("|00|"), "debug_str: {debug_str}");
        assert!(debug_str.starts_with("1:4096;2:1|00|0|m,s,p,a"));
    }

    #[test]
    fn test_akamai_h2_multiple_priorities() {
        let mut ext = Extensions::default();

        let mut pseudo_order = PseudoHeaderOrder::new();
        pseudo_order.push(PseudoHeader::Method);
        pseudo_order.push(PseudoHeader::Path);
        pseudo_order.push(PseudoHeader::Authority);
        pseudo_order.push(PseudoHeader::Scheme);
        ext.insert(pseudo_order);

        let mut frames = Vec::new();

        let settings_config = SettingsConfig {
            initial_window_size: Some(65535),
            setting_order: Some(SettingOrder::from_iter([InitialWindowSize])),
            ..Default::default()
        };
        frames.push(EarlyFrame::Settings(Settings {
            config: settings_config,
            flags: Default::default(),
        }));

        frames.push(EarlyFrame::Priority(Priority {
            stream_id: StreamId::from(3),
            dependency: StreamDependency {
                dependency_id: StreamId::zero(),
                weight: 200,
                is_exclusive: false,
            },
        }));

        frames.push(EarlyFrame::Priority(Priority {
            stream_id: StreamId::from(5),
            dependency: StreamDependency {
                dependency_id: StreamId::zero(),
                weight: 100,
                is_exclusive: true,
            },
        }));

        frames.push(EarlyFrame::Priority(Priority {
            stream_id: StreamId::from(7),
            dependency: StreamDependency {
                dependency_id: StreamId::from(5),
                weight: 50,
                is_exclusive: false,
            },
        }));

        ext.insert(create_early_frame_capture(&frames));

        let akamai_h2 = AkamaiH2::compute(&ext).expect("compute akamai h2");

        let debug_str = format!("{akamai_h2:?}");
        assert!(debug_str.contains("3:0:0:200"), "debug_str: {debug_str}");
        assert!(debug_str.contains("5:1:0:100"), "debug_str: {debug_str}");
        assert!(debug_str.contains("7:0:5:50"), "debug_str: {debug_str}");
    }

    #[test]
    fn test_akamai_h2_chrome_like() {
        let mut ext = Extensions::default();

        let mut pseudo_order = PseudoHeaderOrder::new();
        pseudo_order.push(PseudoHeader::Method);
        pseudo_order.push(PseudoHeader::Authority);
        pseudo_order.push(PseudoHeader::Scheme);
        pseudo_order.push(PseudoHeader::Path);
        ext.insert(pseudo_order);

        let mut frames = Vec::new();

        let settings_config = SettingsConfig {
            header_table_size: Some(65536),
            enable_push: Some(0),
            max_concurrent_streams: Some(1000),
            initial_window_size: Some(6291456),
            max_frame_size: Some(16384),
            max_header_list_size: Some(262144),
            setting_order: Some(SettingOrder::from_iter([
                HeaderTableSize,
                EnablePush,
                MaxConcurrentStreams,
                InitialWindowSize,
                MaxFrameSize,
                MaxHeaderListSize,
            ])),
            ..Default::default()
        };
        frames.push(EarlyFrame::Settings(Settings {
            config: settings_config,
            flags: Default::default(),
        }));

        frames.push(EarlyFrame::WindowUpdate(WindowUpdate {
            stream_id: StreamId::zero(),
            size_increment: 15663105,
        }));

        ext.insert(create_early_frame_capture(&frames));

        let akamai_h2 = AkamaiH2::compute(&ext).expect("compute akamai h2");

        let debug_str = format!("{akamai_h2:?}");
        assert!(debug_str.ends_with("m,a,s,p"), "debug_str: {debug_str}");
        assert!(debug_str.contains("1:65536;2:0;3:1000;4:6291456;5:16384;6:262144"));
    }

    #[test]
    fn test_akamai_h2_firefox_like() {
        let mut ext = Extensions::default();

        let mut pseudo_order = PseudoHeaderOrder::new();
        pseudo_order.push(PseudoHeader::Method);
        pseudo_order.push(PseudoHeader::Path);
        pseudo_order.push(PseudoHeader::Authority);
        pseudo_order.push(PseudoHeader::Scheme);
        ext.insert(pseudo_order);

        let mut frames = Vec::new();

        let settings_config = SettingsConfig {
            header_table_size: Some(65536),
            enable_push: Some(0),
            max_concurrent_streams: Some(100),
            initial_window_size: Some(131072),
            max_frame_size: Some(16384),
            setting_order: Some(SettingOrder::from_iter([
                HeaderTableSize,
                EnablePush,
                MaxConcurrentStreams,
                InitialWindowSize,
                MaxFrameSize,
            ])),
            ..Default::default()
        };
        frames.push(EarlyFrame::Settings(Settings {
            config: settings_config,
            flags: Default::default(),
        }));

        frames.push(EarlyFrame::WindowUpdate(WindowUpdate {
            stream_id: StreamId::zero(),
            size_increment: 12517377,
        }));

        ext.insert(create_early_frame_capture(&frames));

        let akamai_h2 = AkamaiH2::compute(&ext).expect("compute akamai h2");

        let debug_str = format!("{akamai_h2:?}");
        assert!(debug_str.ends_with("m,p,a,s"), "debug_str: {debug_str}");
        assert!(debug_str.contains("12517377"));
    }

}
