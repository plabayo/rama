use super::*;

#[test]
fn retry_accepts_only_the_recipe_installed_by_preparation() {
    let input = Extensions::new();
    let frames: Arc<[EarlyFrame]> = Arc::from([]);
    let mut report = ProfilePreservationReport::default();
    apply_profile_h2_replay(
        &input,
        frames.clone(),
        ProfilePreservationMode::Strict,
        &mut report,
    )
    .unwrap();
    apply_profile_h2_replay(&input, frames, ProfilePreservationMode::Strict, &mut report).unwrap();

    let mut caller = input.get_ref::<H2ClientContextParams>().unwrap().clone();
    caller.replay_early_frames = Some(Arc::from([]));
    input.insert(caller);
    assert!(matches!(
        apply_profile_h2_replay(
            &input,
            Arc::from([]),
            ProfilePreservationMode::Strict,
            &mut report
        ),
        Err(ProfileReplayError::IncompatibleH2ClientParameter(
            H2ClientParameter::ReplayEarlyFrames
        ))
    ));
}

#[test]
fn retry_still_checks_other_caller_wire_settings() {
    let input = Extensions::new();
    let mut report = ProfilePreservationReport::default();
    apply_profile_h2_replay(
        &input,
        Arc::from([]),
        ProfilePreservationMode::Strict,
        &mut report,
    )
    .unwrap();
    let mut caller = input.get_ref::<H2ClientContextParams>().unwrap().clone();
    caller.max_frame_size = Some(32768);
    input.insert(caller);
    assert!(matches!(
        apply_profile_h2_replay(
            &input,
            Arc::from([]),
            ProfilePreservationMode::Strict,
            &mut report
        ),
        Err(ProfileReplayError::IncompatibleH2ClientParameter(
            H2ClientParameter::MaximumFrameSize
        ))
    ));
}
