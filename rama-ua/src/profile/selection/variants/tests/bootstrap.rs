use super::*;
use crate::profile::capture::http3::bootstrap::{H3BootstrapCapture, H3BootstrapLimits};
use rama_http::proto::h3::observation::ObservedEncoderBindings;

fn selected(reference: ValueId) -> SelectedProfile {
    let context = ConnectionContext::default();
    let mut profile = profile("bootstrap", h3_capabilities(), context.clone());
    let bootstrap = H3BootstrapCapture {
        request: reference,
        method: Method::GET,
        fields: 1,
        bindings: ObservedEncoderBindings {
            stream_id: 0,
            complete: true,
            insertions: Vec::new(),
        },
    }
    .canonical(H3BootstrapLimits::default())
    .unwrap();
    let mut connection =
        JointCapture::from_canonical(&connection_variant(1), JointCaptureLimits::default())
            .unwrap();
    let mut slots = connection.slots.into_vec();
    slots.push(CapturedSlot {
        kind: CapturedSlotKind::Http3Bootstrap,
        value: bootstrap,
    });
    connection.slots = slots.into();
    let connection = connection.canonical(JointCaptureLimits::default()).unwrap();
    let pin = connection.id;
    let analysis = Arc::make_mut(profile.captured.as_mut().unwrap());
    analysis.scopes[0] = scope(1, analysis.id, None, context.clone(), vec![(connection, 1)]);
    let database: UserAgentDatabase = [profile].into_iter().collect();
    let mut request = request(context);
    request.pins.connection = Some(pin);
    database
        .select(&request, ProfileSeed([1; 32]), DrawKey([2; 32]))
        .unwrap()
}

#[test]
fn bootstrap_selection_pins_the_existing_initial_request_recipe() {
    let request = request_variant().id;
    let selected = selected(request)
        .for_connection_bootstrap(ProfileSeed([1; 32]), DrawKey([2; 32]))
        .unwrap();
    assert_eq!(selected.pins.request, Some(request));
}

#[test]
fn bootstrap_selection_rejects_missing_method_and_caller_pin_conflicts() {
    let initial = request_variant().id;
    assert!(matches!(
        selected(ValueId([9; 32])).for_connection_bootstrap(ProfileSeed([1; 32]), DrawKey([2; 32])),
        Err(SelectionError::IncompatiblePin(_))
    ));
    let mut wrong_method = selected(initial);
    let FlowKey::Http { method, .. } = &mut wrong_method.flow else {
        panic!("fixture must select an HTTP flow")
    };
    *method = Method::HEAD;
    wrong_method
        .for_connection_bootstrap(ProfileSeed([1; 32]), DrawKey([2; 32]))
        .unwrap_err();
    let mut conflict = selected(initial);
    conflict.pins.request = Some(ValueId([8; 32]));
    conflict
        .for_connection_bootstrap(ProfileSeed([1; 32]), DrawKey([2; 32]))
        .unwrap_err();
}

#[test]
fn static_connection_warmup_does_not_invent_an_initial_request_pin() {
    let database: UserAgentDatabase = [profile(
        "static",
        h3_capabilities(),
        ConnectionContext::default(),
    )]
    .into_iter()
    .collect();
    let selected = database
        .select(
            &request(ConnectionContext::default()),
            ProfileSeed([1; 32]),
            DrawKey([2; 32]),
        )
        .unwrap()
        .for_connection_bootstrap(ProfileSeed([1; 32]), DrawKey([2; 32]))
        .unwrap();
    assert_eq!(selected.pins.request, None);
}

#[test]
fn connection_warmup_keeps_http1_and_http2_selection_unchanged() {
    for version in [Version::HTTP_11, Version::HTTP_2] {
        let mut selected = selected(request_variant().id);
        let FlowKey::Http {
            version: flow_version,
            ..
        } = &mut selected.flow
        else {
            panic!("fixture must select an HTTP flow")
        };
        *flow_version = version;
        let selected = selected
            .for_connection_bootstrap(ProfileSeed([1; 32]), DrawKey([2; 32]))
            .unwrap();
        assert_eq!(selected.pins.request, None);
    }
}
