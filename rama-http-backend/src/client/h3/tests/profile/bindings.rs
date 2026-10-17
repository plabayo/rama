use super::*;
use rama_net::address::Host;
use rama_quic_proto::transport_parameters::TransportParameterId;
use rama_tls::client::{ServerVerifyMode, TlsServerName, TlsServerVerify};
use rama_ua::profile::{capture::order::ProtocolValue, replay::request::ProfilePreservationMode};

#[tokio::test]
async fn final_http_target_and_protocol_are_validated_without_pending_state() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let fixture = fixture().await;
        let mut input = fixture.input();
        fixture.install(&input);
        input = input.with_application_protocol(Protocol::HTTP);
        rejected(fixture.prepare_connection(&input));
        input = input.with_application_protocol(Protocol::HTTPS);
        input
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_2));
        rejected(fixture.prepare_connection(&input));
        input
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_3));
        // Repeated attempts prepare independent native state, never a shared take.
        fixture.prepare_connection(&input).unwrap();
        fixture.prepare_connection(&input).unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn caller_security_and_reuse_survive_derived_wire_settings() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let fixture = fixture().await;
        for mode in [ServerVerifyMode::Disable, ServerVerifyMode::Auto] {
            let input = fixture.input();
            fixture.install(&input);
            input.extensions().insert(TlsServerVerify(mode));
            let caller = Extensions::new();
            caller.extend(input.extensions());
            let (prepared, _) = fixture.prepare_connection(&input).unwrap();
            assert_eq!(
                prepared.authenticated_identity.is_some(),
                mode != ServerVerifyMode::Disable
            );
            assert_eq!(
                input
                    .extensions()
                    .get_ref::<TlsServerVerify>()
                    .map(|verify| verify.0),
                Some(mode)
            );
            assert!(ConnectionReuse::new(prepared.reuse).matches(&caller));
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn caller_and_captured_quic_recipes_cannot_silently_override_each_other() {
    let fixture = fixture().await;
    let input = fixture.input();
    let (context, _) = selection::selected(
        "parameter-policy",
        &fixture.capture,
        Some(&fixture.parameters),
        None,
    );
    context.publish(input.extensions());
    let error = fixture.prepare_connection(&input).err().unwrap();
    assert!(
        error.to_string().contains("QUIC profiles conflict"),
        "{error}"
    );
    assert_eq!(
        input.extensions().get_ref::<QuicProfile>().unwrap(),
        &fixture.profile
    );
}

#[tokio::test]
async fn captured_quic_limits_must_admit_all_h3_critical_streams() {
    let fixture = fixture().await;
    let input = fixture.target();
    let mut parameters = fixture.parameters.clone();
    let streams = parameters
        .fields
        .iter_mut()
        .find(|field| field.id == u64::from(TransportParameterId::InitialMaxStreamsUni))
        .unwrap();
    streams.value = ProtocolValue::Literal(vec![2].into());
    let (context, _) = selection::selected(
        "parameter-limits",
        &fixture.capture,
        Some(&parameters),
        None,
    );
    context.publish(input.extensions());
    let error = fixture.prepare_connection(&input).err().unwrap();
    assert!(
        error.to_string().contains("three critical streams"),
        "{error}"
    );
}

#[tokio::test]
async fn captured_versions_cannot_disagree_with_their_parameter_tuple() {
    let fixture = fixture().await;
    let input = fixture.target();
    let (_, selected) = selection::selected(
        "version-tuple",
        &fixture.capture,
        Some(&fixture.parameters),
        None,
    );
    let mut components = selected.prepare_components().unwrap();
    components.quic_versions.as_mut().unwrap().fields.swap(0, 1);
    let error = fixture
        .compiler()
        .compile(
            &input,
            &selected,
            &mut components,
            ProfilePreservationMode::Strict,
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("version list and parameter tuple disagree"),
        "{error}"
    );
}

#[tokio::test]
async fn unsupported_original_flight_is_refused_before_dial() {
    let fixture = fixture().await;
    let mut flight = fixture.flight.clone();
    flight.flight.coalesced = true;
    let input = fixture.target();
    let (context, _) = selection::selected(
        "unsupported-original-flight",
        &fixture.capture,
        Some(&fixture.parameters),
        Some(&flight),
    );
    context.publish(input.extensions());
    rejected(fixture.prepare_connection(&input));
    assert!(!input.extensions().contains::<QuicProfile>());
}

#[tokio::test]
async fn destination_identity_must_preserve_captured_sni_presence() {
    let fixture = fixture().await;
    let input = fixture.input();
    fixture.install(&input);
    input
        .extensions()
        .insert(TlsServerName(Host::try_from("127.0.0.1").unwrap()));
    let error = fixture.prepare_connection(&input).err().unwrap();
    assert!(
        error.to_string().contains("captured SNI presence differ"),
        "{error}"
    );
}
