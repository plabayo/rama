use super::*;
use crate::profile::model::http::{Http2Profile, Http2Settings, HttpHeadersProfile};
use rama_http::{
    Request,
    proto::h2::{
        PseudoHeaderOrder,
        frame::{EarlyFrame, Settings},
    },
};
use rama_utils::octets::kib;

#[test]
fn legacy_connect_modifier_passes_h3_without_applying_h1_or_h2_settings() {
    let input = Request::new(());
    let profile = HttpProfile { h1: None, h2: None };
    apply_legacy_settings(&input, Version::HTTP_3, &profile).unwrap();
    assert!(
        input
            .extensions()
            .get_ref::<Http1ClientContextParams>()
            .is_none()
    );
    assert!(
        input
            .extensions()
            .get_ref::<H2ClientContextParams>()
            .is_none()
    );
}

#[test]
fn legacy_h2_settings_keep_existing_connection_parameters() {
    let input = Request::new(());
    let pseudo_order = PseudoHeaderOrder::new();
    input.extensions().insert(H2ClientContextParams {
        headers_pseudo_order: Some(pseudo_order.clone()),
        replay_early_frames: Some(vec![EarlyFrame::Settings(Settings::default())].into()),
        max_send_buf_size: Some(kib(128) as u32),
        ..H2ClientContextParams::default()
    });
    let profile = HttpProfile {
        h1: None,
        h2: Some(Http2Profile {
            headers: HttpHeadersProfile {
                navigate: None,
                fetch: None,
                xhr: None,
                form: None,
                ws: None,
            },
            settings: Some(Http2Settings {
                http_pseudo_headers: None,
                early_frames: None,
            }),
        }),
    };

    apply_legacy_settings(&input, Version::HTTP_2, &profile).unwrap();

    let params = input
        .extensions()
        .get_ref::<H2ClientContextParams>()
        .unwrap();
    assert_eq!(params.headers_pseudo_order, Some(pseudo_order));
    assert!(params.replay_early_frames.is_some());
    assert_eq!(params.max_send_buf_size, Some(kib(128) as u32));
}
