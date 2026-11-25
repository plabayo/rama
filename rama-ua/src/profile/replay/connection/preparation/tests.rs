use super::*;
use rama_core::extensions::NoExtensionsTransfer;
use rama_http::proto::h2::frame::Settings;
use std::time::Duration;

fn retained(parameter: H2ClientParameter) -> [ProfilePreservationDifference; 1] {
    [ProfilePreservationDifference::RetainedH2ClientParameter { parameter }]
}

#[test]
fn preparing_twice_leaves_the_last_replay_and_reports_nothing() {
    let input = Extensions::new();
    let mut report = ProfilePreservationReport::default();
    apply_profile_h2_replay(&input, Arc::from([]), &mut report);
    let last: Arc<[EarlyFrame]> = Arc::from([]);
    apply_profile_h2_replay(&input, last.clone(), &mut report);
    assert!(report.is_exact());
    assert!(Arc::ptr_eq(
        input
            .get_ref::<H2ClientContextParams>()
            .unwrap()
            .replay_early_frames
            .as_ref()
            .unwrap(),
        &last
    ));
}

#[test]
fn retry_still_reports_other_caller_wire_settings() {
    let input = Extensions::new();
    let mut report = ProfilePreservationReport::default();
    apply_profile_h2_replay(&input, Arc::from([]), &mut report);
    let mut caller = input.get_ref::<H2ClientContextParams>().unwrap().clone();
    caller.max_frame_size = Some(32768);
    input.insert(caller);
    apply_profile_h2_replay(&input, Arc::from([]), &mut report);
    assert_eq!(
        report.differences.as_ref(),
        retained(H2ClientParameter::MaximumFrameSize)
    );
    assert_eq!(
        input
            .get_arc::<H2ClientContextParams>()
            .unwrap()
            .max_frame_size,
        Some(32768)
    );
}

fn new_wire_overrides() -> [(H2ClientParameter, H2ClientContextParams); 2] {
    [
        (
            H2ClientParameter::InitialSettings,
            H2ClientContextParams {
                initial_settings: Some(Arc::new(Settings::default())),
                ..Default::default()
            },
        ),
        (
            H2ClientParameter::HeaderTableSize,
            H2ClientContextParams {
                header_table_size: Some(8192),
                ..Default::default()
            },
        ),
    ]
}

#[test]
fn h2_preparation_reports_initial_frame_and_table_overrides_on_first_attempt_and_retry() {
    for (parameter, supplied) in new_wire_overrides() {
        for retry in [false, true] {
            let input = Extensions::new();
            let recipe: Arc<[EarlyFrame]> = Arc::from([]);
            if retry {
                apply_profile_h2_replay(
                    &input,
                    recipe.clone(),
                    &mut ProfilePreservationReport::default(),
                );
            }
            let mut params = input
                .get_arc::<H2ClientContextParams>()
                .as_deref()
                .cloned()
                .unwrap_or_default();
            params.initial_settings = supplied.initial_settings.clone();
            params.header_table_size = supplied.header_table_size;
            input.insert(params);
            let mut report = ProfilePreservationReport::default();
            apply_profile_h2_replay(&input, recipe, &mut report);
            assert_eq!(report.differences.as_ref(), retained(parameter));
            let retained = input.get_arc::<H2ClientContextParams>().unwrap();
            assert_eq!(retained.header_table_size, supplied.header_table_size);
            if let Some(supplied) = &supplied.initial_settings {
                assert!(Arc::ptr_eq(
                    retained.initial_settings.as_ref().unwrap(),
                    supplied
                ));
            }
        }
    }
}

#[test]
fn compatible_h2_preparation_reports_and_retains_wire_overrides_including_retry() {
    for (parameter, supplied) in new_wire_overrides() {
        let input = Extensions::new();
        input.insert(supplied.clone());
        for _ in 0..2 {
            let recipe: Arc<[EarlyFrame]> = Arc::from([]);
            let mut report = ProfilePreservationReport::default();
            apply_profile_h2_replay(&input, recipe.clone(), &mut report);
            assert_eq!(
                report.differences.as_ref(),
                [ProfilePreservationDifference::RetainedH2ClientParameter { parameter },]
            );
            let retained = input.get_arc::<H2ClientContextParams>().unwrap();
            assert_eq!(retained.header_table_size, supplied.header_table_size);
            if let Some(supplied) = &supplied.initial_settings {
                assert!(Arc::ptr_eq(
                    retained.initial_settings.as_ref().unwrap(),
                    supplied
                ));
            }
            assert!(Arc::ptr_eq(
                retained.replay_early_frames.as_ref().unwrap(),
                &recipe
            ));
        }
    }
}

#[test]
fn local_buffer_and_reset_budgets_do_not_become_wire_profile_overrides() {
    let input = Extensions::new();
    input.insert(H2ClientContextParams {
        max_send_buf_size: Some(131072),
        initial_max_send_streams: Some(8),
        max_concurrent_reset_streams: Some(8),
        max_pending_accept_reset_streams: Some(8),
        reset_stream_duration: Some(Duration::from_secs(5)),
        ..Default::default()
    });
    let mut report = ProfilePreservationReport::default();
    apply_profile_h2_replay(&input, Arc::from([]), &mut report);
    assert!(report.is_exact());
    let retained = input.get_arc::<H2ClientContextParams>().unwrap();
    assert_eq!(retained.max_send_buf_size, Some(131072));
    assert_eq!(retained.initial_max_send_streams, Some(8));
    assert_eq!(retained.max_concurrent_reset_streams, Some(8));
    assert_eq!(retained.max_pending_accept_reset_streams, Some(8));
}

#[test]
fn prepared_connection_components_stop_at_child_connections() {
    let extensions = Extensions::new();
    let components = PreparedConnectionComponents {
        #[cfg(feature = "tls")]
        tls: None,
        #[cfg(feature = "tls")]
        tls_outer: None,
        quic_parameters: None,
        quic_outer_parameters: None,
        h3_peer_settings: None,
        h3_settings_evidence: None,
        quic_versions: None,
        h2_early_frames: None,
        quic_first_flight: None,
        h3_sequence: None,
        h3_bootstrap: None,
        preservation_report: ProfilePreservationReport::default(),
    };
    extensions.insert(components);
    assert!(extensions.fork().contains::<PreparedConnectionComponents>());
    assert!(
        !extensions
            .fork_connection(&NoExtensionsTransfer::new())
            .contains::<PreparedConnectionComponents>()
    );
}

#[test]
fn profile_h2_settings_stop_at_child_connections() {
    let input = Extensions::new();
    apply_profile_h2_replay(
        &input,
        Arc::from([]),
        &mut ProfilePreservationReport::default(),
    );
    assert!(input.contains::<H2ClientContextParams>());
    // A child connection, such as the one to a proxy, gets none of them.
    let child = input.fork_connection(&NoExtensionsTransfer::new());
    assert!(!child.contains::<H2ClientContextParams>());
}

#[test]
fn a_value_inserted_after_the_last_preparation_answers_until_the_next_one() {
    let input = Extensions::new();
    apply_profile_h2_replay(
        &input,
        Arc::from([]),
        &mut ProfilePreservationReport::default(),
    );
    let later: Arc<[EarlyFrame]> = Arc::from([]);
    let mut params = input.get_ref::<H2ClientContextParams>().unwrap().clone();
    params.replay_early_frames = Some(later.clone());
    input.insert(params);
    let replay = || {
        input
            .get_ref::<H2ClientContextParams>()
            .unwrap()
            .replay_early_frames
            .clone()
            .unwrap()
    };
    assert!(Arc::ptr_eq(&replay(), &later));
    let again: Arc<[EarlyFrame]> = Arc::from([]);
    apply_profile_h2_replay(
        &input,
        again.clone(),
        &mut ProfilePreservationReport::default(),
    );
    assert!(Arc::ptr_eq(&replay(), &again));
}
