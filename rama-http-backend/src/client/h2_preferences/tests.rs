use super::*;
use rama_core::bytes::BytesMut;
use rama_http_types::proto::h2::{
    PseudoHeader,
    frame::{EarlyFrameStreamContext, Head, Kind, Setting, SettingId, SettingsConfig, StreamId},
};
use std::collections::hash_map::DefaultHasher;

fn identity(
    params: Option<H2ClientContextParams>,
    order: Option<PseudoHeaderOrder>,
) -> Option<H2WirePreferences> {
    let extensions = Extensions::new();
    if let Some(params) = params {
        extensions.insert(params);
    }
    if let Some(order) = order {
        extensions.insert(order);
    }
    H2WirePreferences::from_extensions(&extensions)
}

fn hash(value: Option<&H2WirePreferences>) -> u64 {
    let mut state = DefaultHasher::new();
    value.hash(&mut state);
    state.finish()
}

fn literal(entries: &[(u16, u32)]) -> Settings {
    Settings::from_ordered_entries(
        entries
            .iter()
            .map(|(id, value)| Setting::new(*id, *value))
            .collect(),
    )
    .unwrap()
}

#[test]
fn effective_frames_and_pseudo_order_follow_connector_precedence() {
    let preferred: Arc<[EarlyFrame]> = [EarlyFrame::Settings(literal(&[(2, 0), (1, 4096)]))].into();
    let mut recorder = EarlyFrameStreamContext::new_recorder();
    recorder.record_settings_frame(&literal(&[(2, 0), (1, 0)]));
    let legacy = recorder.freeze_recorder().unwrap();
    let params = || H2ClientContextParams {
        replay_early_frames: Some(preferred.clone()),
        ..Default::default()
    };
    let left = identity(Some(params()), None);
    let mut override_params = params();
    override_params.early_frames = Some(legacy);
    let right = identity(Some(override_params), None);
    assert_eq!(left, right);
    assert_eq!(hash(left.as_ref()), hash(right.as_ref()));

    let order: PseudoHeaderOrder = [
        PseudoHeader::Method,
        PseudoHeader::Scheme,
        PseudoHeader::Path,
        PseudoHeader::Authority,
    ]
    .into_iter()
    .collect();
    let other: PseudoHeaderOrder = [
        PseudoHeader::Method,
        PseudoHeader::Authority,
        PseudoHeader::Scheme,
        PseudoHeader::Path,
    ]
    .into_iter()
    .collect();
    let from_bare = identity(None, Some(order.clone()));
    let from_params = identity(
        Some(H2ClientContextParams {
            headers_pseudo_order: Some(order),
            ..Default::default()
        }),
        Some(other.clone()),
    );
    assert_eq!(from_bare, from_params);
    assert_eq!(hash(from_bare.as_ref()), hash(from_params.as_ref()));
    assert_ne!(from_bare, identity(None, Some(other)));
}

#[test]
fn settings_identity_follows_current_encoded_entries_not_semantic_equality() {
    let original = literal(&[(2, 0), (0xa0a1, 5), (1, 32), (1, 64)]);
    let mut changed = original.clone();
    // Direct mutation makes the old literal snapshot stale even though config Eq ignores order.
    changed.config.setting_order = Some(
        [SettingId::HeaderTableSize, SettingId::EnablePush]
            .into_iter()
            .collect(),
    );
    assert_eq!(original, changed);
    let encode = |settings| {
        identity(
            Some(H2ClientContextParams {
                initial_settings: Some(Arc::new(settings)),
                ..Default::default()
            }),
            None,
        )
    };
    let original_key = encode(original.clone());
    assert_ne!(original_key, encode(changed.clone()));
    let plain = Settings::default().with_config(SettingsConfig {
        enable_push: Some(0),
        header_table_size: Some(64),
        setting_order: changed.config.setting_order.clone(),
        ..Default::default()
    });
    let plain_key = encode(plain);
    let changed_key = encode(changed);
    assert_ne!(
        plain_key, changed_key,
        "whole-frame preparation rejects stale observations"
    );
    let early = |settings| {
        identity(
            Some(H2ClientContextParams {
                replay_early_frames: Some([EarlyFrame::Settings(settings)].into()),
                ..Default::default()
            }),
            None,
        )
    };
    let plain = Settings::default().with_config(SettingsConfig {
        enable_push: Some(0),
        header_table_size: Some(64),
        setting_order: Some(
            [SettingId::HeaderTableSize, SettingId::EnablePush]
                .into_iter()
                .collect(),
        ),
        ..Default::default()
    });
    let mut changed = original.clone();
    changed.config.setting_order = plain.config.setting_order.clone();
    let left = early(plain);
    let right = early(changed);
    assert_eq!(
        left, right,
        "early frames use direct encoding, not whole-frame preparation"
    );
    assert_eq!(hash(left.as_ref()), hash(right.as_ref()));

    let observed = Settings::load_observed(
        Head::new(Kind::Settings, 0, StreamId::zero()),
        &[0, 2, 0, 0, 0, 0],
        true,
    )
    .unwrap();
    let semantic = Settings::default().with_config(SettingsConfig {
        enable_push: Some(0),
        ..Default::default()
    });
    assert_ne!(
        encode(observed),
        encode(semantic),
        "validation metadata may conservatively partition overrides"
    );
    let mut wire = BytesMut::new();
    original.encode(&mut wire);
    let observed = Settings::load_observed(
        Head::new(Kind::Settings, 0, StreamId::zero()),
        &wire[9..],
        true,
    )
    .unwrap();
    let observed_key = encode(observed);
    assert_eq!(
        original_key, observed_key,
        "to_literal retains received unknown/duplicate occurrences"
    );
    assert_eq!(hash(original_key.as_ref()), hash(observed_key.as_ref()));
    let mut incomplete = original.clone();
    incomplete.observation.as_mut().unwrap().complete = false;
    assert_ne!(
        original_key,
        encode(incomplete),
        "incomplete input must reach handshake rejection, not reuse"
    );
    let mut stale = original.clone();
    stale.config.header_table_size = Some(32);
    assert_ne!(
        original_key,
        encode(stale),
        "stale semantic fields must reach handshake rejection"
    );
    assert_eq!(original_key, encode(original));
}

#[test]
fn empty_and_runtime_only_params_do_not_partition_but_wire_knobs_do() {
    assert_eq!(
        identity(None, None),
        identity(Some(H2ClientContextParams::default()), None)
    );
    assert_eq!(
        identity(None, None),
        identity(
            Some(H2ClientContextParams {
                initial_max_send_streams: Some(4),
                max_send_buf_size: Some(128),
                max_concurrent_reset_streams: Some(4),
                max_pending_accept_reset_streams: Some(4),
                max_local_error_reset_streams: Some(4),
                reset_stream_duration: Some(Duration::from_secs(4)),
                ..Default::default()
            }),
            None
        )
    );
    let modifications: [fn(&mut H2ClientContextParams); 10] = [
        |p| p.init_stream_window_size = Some(65_535),
        |p| p.init_connection_window_size = Some(65_535),
        |p| p.header_table_size = Some(4096),
        |p| p.max_frame_size = Some(16384),
        |p| p.max_header_list_size = Some(1_000_000),
        |p| p.max_concurrent_streams = Some(100),
        |p| p.keep_alive_interval = Some(Duration::from_secs(30)),
        |p| p.keep_alive_timeout = Some(Duration::from_secs(5)),
        |p| p.keep_alive_while_idle = Some(false),
        |p| p.adaptive_window = Some(false),
    ];
    for modify in modifications {
        let mut params = H2ClientContextParams::default();
        modify(&mut params);
        assert_ne!(identity(None, None), identity(Some(params.clone()), None));
        let left = identity(Some(params.clone()), None);
        let right = identity(Some(params), None);
        assert_eq!(left, right);
        assert_eq!(hash(left.as_ref()), hash(right.as_ref()));
    }
}
