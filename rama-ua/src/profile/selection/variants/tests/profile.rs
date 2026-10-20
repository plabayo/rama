use super::*;

#[test]
fn advertised_alpn_requires_every_possible_http_outcome() {
    let required =
        CapabilitySet::for_alpn(&TlsAlpn::http_auto(), SelectionTransport::TcpTls).unwrap();
    assert_eq!(
        required,
        CapabilitySet {
            h1: true,
            h2: true,
            tls_tcp: true,
            ..CapabilitySet::default()
        }
    );
    assert!(matches!(
        CapabilitySet::for_alpn(
            &TlsAlpn(vec![ApplicationProtocol::HTTP_3].into()),
            SelectionTransport::TcpTls,
        ),
        Err(SelectionError::IncompatibleTransport)
    ));
}

#[test]
fn selection_requires_flow_and_complete_capability_closure() {
    let context = ConnectionContext::default();
    let database: UserAgentDatabase = [
        profile(
            "incomplete",
            CapabilitySet {
                h3: true,
                ..CapabilitySet::default()
            },
            context.clone(),
        ),
        profile("complete", h3_capabilities(), context.clone()),
    ]
    .into_iter()
    .collect();
    let selected = database
        .select(&request(context), ProfileSeed([3; 32]), DrawKey([4; 32]))
        .unwrap();
    assert_eq!(selected.profile().key.client.as_ref(), "complete");
}

#[test]
fn ip_family_does_not_fragment_a_wire_equivalent_selection() {
    let captured = ConnectionContext {
        ip_family: Some(ConnectionIpFamily::V4),
        ..ConnectionContext::default()
    };
    let requested = ConnectionContext {
        ip_family: Some(ConnectionIpFamily::V6),
        ..ConnectionContext::default()
    };
    let database: UserAgentDatabase = [profile("complete", h3_capabilities(), captured.clone())]
        .into_iter()
        .collect();
    let captured_selection = database
        .select(
            &request(captured.clone()),
            ProfileSeed([46; 32]),
            DrawKey([47; 32]),
        )
        .unwrap();
    let selected = database
        .select(
            &request(requested.clone()),
            ProfileSeed([46; 32]),
            DrawKey([47; 32]),
        )
        .unwrap();
    let captured_connection = captured_selection
        .connection(&captured, ProfileSeed([46; 32]), DrawKey([48; 32]))
        .unwrap();
    let connection = selected
        .connection(&requested, ProfileSeed([46; 32]), DrawKey([48; 32]))
        .unwrap();
    assert_eq!(connection.variant, captured_connection.variant);
    assert_eq!(connection.effective.context.connection, captured);
    let request = selected
        .request(
            &connection,
            &flow(requested.clone(), Version::HTTP_3),
            &HeaderMap::new(),
            ProfileSeed([46; 32]),
            DrawKey([49; 32]),
        )
        .unwrap();
    assert_eq!(
        request
            .effective
            .flow
            .canonical(MAXIMUM_IDENTITY_BYTES)
            .unwrap()
            .id,
        flow(requested, Version::HTTP_3)
            .canonical(MAXIMUM_IDENTITY_BYTES)
            .unwrap()
            .id
    );

    let incompatible = ConnectionContext {
        resumption: ResumptionContext::Fresh,
        ip_family: Some(ConnectionIpFamily::V6),
        ..ConnectionContext::default()
    };
    assert!(matches!(
        selected.connection(&incompatible, ProfileSeed([46; 32]), DrawKey([48; 32]),),
        Err(SelectionError::IncompatibleConnectionContext)
    ));
}
