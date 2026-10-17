use super::*;
use rama_net::{address::Host, tls::TlsAlpn};
use rama_quic_proto::transport_parameters::TransportParameterId;
use rama_tls::client::{ServerVerifyMode, TlsServerName, TlsServerVerify};
use rama_ua::profile::{
    capture::order::ProtocolValue, replay::request::ProfilePreservationMode,
    selection::variants::ConnectionSelection,
};

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

#[tokio::test]
async fn explicit_caller_alpn_is_not_erased_by_captured_h3_settings() {
    let fixture = fixture().await;
    for offer in [TlsAlpn::empty(), TlsAlpn::http_2()] {
        let input = fixture.input();
        fixture.install(&input);
        input.extensions().insert(offer.clone());
        let error = fixture.serve(input.clone()).await.err().unwrap();
        assert!(error.to_string().contains("explicit ALPN"), "{error}");
        assert_eq!(input.extensions().get_ref::<TlsAlpn>(), Some(&offer));
        assert!(!input.extensions().contains::<ConnectionSelection>());
    }
}

#[tokio::test]
async fn captured_alpn_must_preserve_explicit_order_and_extra_protocols() {
    let mut fixture = fixture().await;
    for protocols in [
        vec![ApplicationProtocol::HTTP_3, ApplicationProtocol::HTTP_2],
        vec![ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_3],
    ] {
        let input = fixture.input();
        fixture.install(&input);
        let offer = TlsAlpn(protocols.into_iter().collect());
        input.extensions().insert(offer.clone());
        let error = fixture.serve(input.clone()).await.err().unwrap();
        assert!(
            error.to_string().contains("ALPN offers conflict"),
            "{error}"
        );
        assert_eq!(input.extensions().get_ref::<TlsAlpn>(), Some(&offer));
    }

    // Wire-equivalent public aliases are accepted and actually reach the peer.
    let input = fixture.input();
    fixture.install(&input);
    input.extensions().insert(TlsAlpn(
        [ApplicationProtocol::Unknown(b"h3".to_vec())]
            .into_iter()
            .collect(),
    ));
    let transport = fixture.serve(input).await.unwrap().conn;
    request(transport).await;
    let captures = fixture.task.take().unwrap().await.unwrap();
    assert_eq!(captures.len(), 2);
    assert_eq!(captures[1].0, fixture.capture);
}
