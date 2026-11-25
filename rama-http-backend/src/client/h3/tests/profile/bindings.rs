use super::*;
use rama_net::{
    address::{Domain, Host},
    tls::{ServerName, TlsAlpn},
};
use rama_quic_proto::transport_parameters::TransportParameterId;
use rama_tls::client::{ServerVerifyMode, TlsClientSni, TlsServerVerify};
use rama_ua::profile::{
    capture::{joint::CapturedSlotKind, order::ProtocolValue},
    replay::request::{
        LoweredProfileItem, ProfilePreservationDifference, ProfilePreservationReport,
    },
};

fn reported(input: &ConnectRequest, difference: &ProfilePreservationDifference) -> bool {
    input
        .extensions()
        .get_ref::<ProfilePreservationReport>()
        .is_some_and(|report| report.differences.contains(difference))
}

fn lowered(item: LoweredProfileItem) -> ProfilePreservationDifference {
    ProfilePreservationDifference::LoweredProfileItem { item }
}

#[tokio::test]
async fn final_http_target_and_protocol_are_validated_without_pending_state() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let fixture = fixture().await;
        let mut input = fixture.input();
        fixture.install(&input);
        input = input.with_application_protocol(Protocol::HTTP);
        rejected(fixture.prepare_connection(&input).await);
        input = input.with_application_protocol(Protocol::HTTPS);
        input
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_2));
        rejected(fixture.prepare_connection(&input).await);
        input
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_3));
        // Repeated attempts prepare independent native state, never a shared take.
        fixture.prepare_connection(&input).await.unwrap();
        fixture.prepare_connection(&input).await.unwrap();
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
            let prepared = fixture.prepare_connection(&input).await.unwrap();
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
async fn an_earlier_quic_profile_is_replaced_by_the_captured_one() {
    let fixture = fixture().await;
    let input = fixture.input();
    let (context, _) = selection::selected(
        "parameter-policy",
        &fixture.capture,
        Some(&fixture.parameters),
        None,
    );
    context.publish(input.extensions());
    fixture.prepare_connection(&input).await.unwrap();
    assert_ne!(
        input.extensions().get_ref::<QuicProfile>().unwrap(),
        &fixture.profile
    );
}

#[tokio::test]
async fn captured_quic_limits_are_raised_to_admit_all_h3_critical_streams() {
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
    let prepared = fixture.prepare_connection(&input).await.unwrap();
    assert_eq!(
        prepared.profile.unwrap().limits().initial_max_streams_uni,
        3
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
        .compile(&input, &selected, &mut components)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("version list and parameter tuple disagree"),
        "{error}"
    );
}

#[tokio::test]
async fn unsupported_original_flight_is_reported_before_dial() {
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
    fixture.prepare_connection(&input).await.unwrap();
    assert!(reported(
        &input,
        &ProfilePreservationDifference::UnsupportedConnectionComponent {
            component: CapturedSlotKind::QuicFirstFlight
        }
    ));
    // The parameter tuple still applies; only the packet layout is native.
    assert!(input.extensions().contains::<QuicProfile>());
}

#[tokio::test]
async fn destination_identity_overrides_and_reports_captured_sni_presence() {
    // An IP address spelled as a name is still an IP identity, sent without SNI.
    let ip_as_name = Host::Name(Domain::try_from("127.0.0.1").unwrap());
    for server_name in [Host::try_from("127.0.0.1").unwrap(), ip_as_name] {
        let fixture = fixture().await;
        let input = fixture.input();
        fixture.install(&input);
        input
            .extensions()
            .insert(ServerName::try_from(server_name).unwrap());
        fixture.prepare_connection(&input).await.unwrap();
        assert!(reported(
            &input,
            &lowered(LoweredProfileItem::TlsServerNamePresence)
        ));
    }
}

#[tokio::test]
async fn conflicting_caller_alpn_is_lowered_to_http3() {
    for offer in [TlsAlpn::empty(), TlsAlpn::http_2()] {
        let fixture = fixture().await;
        let input = fixture.input();
        fixture.install(&input);
        input.extensions().insert(offer);
        request(fixture.serve(input).await.unwrap().conn).await;
    }
}

#[tokio::test]
async fn explicit_alpn_order_and_extra_protocols_are_retained_and_reported() {
    let mut fixture = fixture().await;
    for protocols in [
        vec![ApplicationProtocol::HTTP_3, ApplicationProtocol::HTTP_2],
        vec![ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_3],
    ] {
        let input = fixture.input();
        fixture.install(&input);
        let offer = TlsAlpn(protocols.into_iter().collect());
        input.extensions().insert(offer.clone());
        fixture.prepare_connection(&input).await.unwrap();
        assert!(reported(
            &input,
            &lowered(LoweredProfileItem::CallerTlsAlpn)
        ));
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

#[tokio::test]
async fn unchanged_ech_and_caller_settings_reuse_the_admitted_quic_recipe() {
    let fixture = fixture().await;
    let input = fixture.target();
    fixture.install(&input);
    let (mut preparation, compiled) = prepare(
        &input,
        fixture.connector.tls_config(),
        fixture.connector.tls_provider(),
    )
    .unwrap()
    .unwrap();
    preparation.apply_http(&input).unwrap();
    <CompiledConnection as InstalledConnectionProfile<ConnectRequest>>::apply(
        compiled,
        input.extensions(),
    );
    let installed = input.extensions().get_arc::<TlsClientSni>().unwrap();
    prepare_h3(&fixture.connector, &input).await.unwrap();
    assert!(Arc::ptr_eq(
        &installed,
        &input.extensions().get_arc::<TlsClientSni>().unwrap()
    ));
}

#[tokio::test]
async fn late_caller_sni_suppression_survives_final_quic_preparation() {
    let fixture = fixture().await;
    let input = fixture.target();
    fixture.install(&input);
    let (mut preparation, compiled) = prepare(
        &input,
        fixture.connector.tls_config(),
        fixture.connector.tls_provider(),
    )
    .unwrap()
    .unwrap();
    preparation.apply_http(&input).unwrap();
    <CompiledConnection as InstalledConnectionProfile<ConnectRequest>>::apply(
        compiled,
        input.extensions(),
    );
    assert_ne!(
        input.extensions().get_ref::<TlsClientSni>(),
        Some(&TlsClientSni::Disabled)
    );
    input.extensions().insert(TlsClientSni::Disabled);
    prepare_h3(&fixture.connector, &input).await.unwrap();
    assert_eq!(
        input.extensions().get_ref::<TlsClientSni>(),
        Some(&TlsClientSni::Disabled)
    );
}
