use super::*;
use rama_http::proto::h2::frame::Settings;
use std::time::Duration;

fn retained(parameter: H2ClientParameter) -> [ProfilePreservationDifference; 1] {
    [ProfilePreservationDifference::RetainedH2ClientParameter { parameter }]
}

#[test]
fn retry_accepts_only_the_recipe_installed_by_preparation() {
    let input = Extensions::new();
    let frames: Arc<[EarlyFrame]> = Arc::from([]);
    let mut report = ProfilePreservationReport::default();
    apply_profile_h2_replay(&input, frames.clone(), &mut report);
    apply_profile_h2_replay(&input, frames, &mut report);
    assert!(report.is_exact());

    let mut caller = input.get_ref::<H2ClientContextParams>().unwrap().clone();
    caller.replay_early_frames = Some(Arc::from([]));
    input.insert(caller);
    apply_profile_h2_replay(&input, Arc::from([]), &mut report);
    assert_eq!(
        report.differences.as_ref(),
        retained(H2ClientParameter::ReplayEarlyFrames)
    );
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
            .get_ref::<H2ClientContextParams>()
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
                .get_ref::<H2ClientContextParams>()
                .cloned()
                .unwrap_or_default();
            params.initial_settings = supplied.initial_settings.clone();
            params.header_table_size = supplied.header_table_size;
            input.insert(params);
            let mut report = ProfilePreservationReport::default();
            apply_profile_h2_replay(&input, recipe, &mut report);
            assert_eq!(report.differences.as_ref(), retained(parameter));
            let retained = input.get_ref::<H2ClientContextParams>().unwrap();
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
            let retained = input.get_ref::<H2ClientContextParams>().unwrap();
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
        max_local_error_reset_streams: Some(8),
        reset_stream_duration: Some(Duration::from_secs(5)),
        ..Default::default()
    });
    let mut report = ProfilePreservationReport::default();
    apply_profile_h2_replay(&input, Arc::from([]), &mut report);
    assert!(report.is_exact());
    let retained = input.get_ref::<H2ClientContextParams>().unwrap();
    assert_eq!(retained.max_send_buf_size, Some(131072));
    assert_eq!(retained.initial_max_send_streams, Some(8));
    assert_eq!(retained.max_concurrent_reset_streams, Some(8));
    assert_eq!(retained.max_pending_accept_reset_streams, Some(8));
    assert_eq!(retained.max_local_error_reset_streams, Some(8));
}
