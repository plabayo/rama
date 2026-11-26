use rama_quic_proto::coding::Codec as _;
use rama_tls::client::TlsEchAccepted;
use rama_ua::profile::{
    capture::{
        order::ProtocolValue,
        tls::{TlsCapturedExtension, TlsCapturedExtensionValue},
    },
    model::identity::FlowKey,
    selection::{
        DrawKey, ProfileSeed,
        capabilities::CapabilitySet,
        database::UserAgentDatabase,
        variants::{ProfileSelector, SelectionRequest, VariantPins},
    },
};
use tokio::time::timeout;

use super::*;

#[tokio::test]
async fn derived_profiles_in_paired_only_and_mixed_databases_connect_without_ech() {
    timeout(Duration::from_secs(15), async {
        for (mixed, reduced) in [(false, false), (true, false), (false, true), (true, true)] {
            let mut fixture = fixture_with_connections(
                QuicProfile::standard().with_transport_parameters(
                    TransportParameterProfile::standard()
                        .try_with_grease(GreaseParameter::None)
                        .unwrap(),
                ),
                if mixed { 3 } else { 2 },
            )
            .await;
            let mut outer = fixture.capture.clone();
            outer.ciphers.reverse();
            let mut extensions = outer.extensions.into_vec();
            extensions.push(TlsCapturedExtension {
                id: u16::from(ExtensionId::ENCRYPTED_CLIENT_HELLO),
                value: TlsCapturedExtensionValue::EchOuter {
                    kdf: 1,
                    aead: 1,
                    enc: 32,
                    payload: 320,
                },
            });
            outer.extensions = extensions.into();
            let mut inner = outer.clone();
            for extension in &mut inner.extensions {
                if matches!(extension.value, TlsCapturedExtensionValue::EchOuter { .. }) {
                    extension.value = TlsCapturedExtensionValue::EchInner;
                }
            }
            let ordinary_outer = outer.clone();
            let mut parameters = fixture.parameters.clone();
            if reduced {
                parameters.fields = parameters
                    .fields
                    .into_vec()
                    .into_iter()
                    .filter(|field| matches!(field.id, 11 | 15 | 17))
                    .collect();
                let mut encoded = Vec::new();
                for field in &parameters.fields {
                    VarInt::from_u64(field.id).unwrap().encode(&mut encoded);
                    let size = match &field.value {
                        ProtocolValue::Literal(bytes) => bytes.len(),
                        ProtocolValue::ConnectionLength(length) => *length,
                    };
                    VarInt::from_u64(size as u64).unwrap().encode(&mut encoded);
                    encoded.resize(encoded.len() + size, 0);
                }
                for extension in &mut outer.extensions {
                    if extension.id == u16::from(ExtensionId::QUIC_TRANSPORT_PARAMETERS) {
                        extension.value = TlsCapturedExtensionValue::ConnectionLength(
                            u16::try_from(encoded.len()).unwrap(),
                        );
                    }
                }
            }
            let paired =
                selection::database("paired", &inner, Some(&outer), Some(&parameters), None);
            let ordinary = selection::database(
                "ordinary",
                &ordinary_outer,
                None,
                Some(&fixture.parameters),
                None,
            );
            let database: UserAgentDatabase = paired
                .iter()
                .chain(ordinary.iter().filter(|_| mixed))
                .cloned()
                .collect();
            let mut expected = Vec::new();
            for profile in database.iter() {
                let seed = ProfileSeed([4; 32]);
                let key = DrawKey([6; 32]);
                let selected = Arc::new(
                    database
                        .select(
                            &SelectionRequest {
                                client: ProfileSelector {
                                    client: Some(profile.key.client.clone()),
                                    ..ProfileSelector::default()
                                },
                                required: CapabilitySet {
                                    h3: true,
                                    tls_quic: true,
                                    quic: true,
                                    ..CapabilitySet::default()
                                },
                                flow: FlowKey::Http {
                                    version: Version::HTTP_3,
                                    method: "GET".parse().unwrap(),
                                    initiator: None,
                                    fetch: None,
                                    connection: ConnectionContext::default(),
                                },
                                pins: VariantPins::default(),
                            },
                            seed,
                            key,
                        )
                        .unwrap(),
                );
                let selection = selected
                    .connection(&ConnectionContext::default(), seed, key)
                    .unwrap();
                assert!(!selection.ech_ready);
                let mut components = selection.prepare_components().unwrap();
                components.use_ech_outer_for_replay(false).unwrap();
                let expected_hello = components.tls.unwrap();
                assert!(!expected_hello.extensions.iter().any(|extension| matches!(
                    extension.value,
                    TlsCapturedExtensionValue::EchInner
                )));
                expected.push((expected_hello, components.quic_parameters.unwrap()));
                let input = fixture.target();
                selected
                    .emulation_context(seed, key, DrawKey([7; 32]))
                    .publish(input.extensions());
                let established = fixture.serve(input).await.unwrap();
                assert_eq!(
                    established
                        .conn
                        .connection
                        .extensions()
                        .get_ref::<TlsEchAccepted>(),
                    Some(&TlsEchAccepted(false))
                );
                request(established.conn).await;
            }
            let actual = fixture.task.take().unwrap().await.unwrap();
            assert_eq!(actual.len(), expected.len() + 1);
            for (actual, expected) in actual.iter().skip(1).zip(expected) {
                assert_eq!(
                    actual.0.clone().with_grease_placeholders().unwrap(),
                    expected.0.with_grease_placeholders().unwrap()
                );
                assert_eq!(
                    actual
                        .1
                        .canonical(OrderCaptureLimits::default())
                        .unwrap()
                        .bytes,
                    expected
                        .1
                        .canonical(OrderCaptureLimits::default())
                        .unwrap()
                        .bytes
                );
            }
        }
    })
    .await
    .unwrap();
}
