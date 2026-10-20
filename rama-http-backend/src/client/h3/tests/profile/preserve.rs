use super::*;
use rama_core::{ServiceInput, service::service_fn};
use rama_http_types::proto::h3::ClientSettingsProfile;
use rama_quic_proto::profile::InitialFlightLayout;
use rama_ua::{
    HttpAgent, TlsAgent, UserAgent,
    profile::replay::{
        connection::PreparedConnectionComponents,
        request::{LoweredProfileItem, ProfilePreservationDifference, ProfilePreservationReport},
    },
};

fn report(input: &ConnectRequest) -> Box<[ProfilePreservationDifference]> {
    input
        .extensions()
        .get_ref::<ProfilePreservationReport>()
        .unwrap()
        .differences
        .clone()
}

fn lowered(item: LoweredProfileItem) -> ProfilePreservationDifference {
    ProfilePreservationDifference::LoweredProfileItem { item }
}

fn unsupported(component: CapturedSlotKind) -> ProfilePreservationDifference {
    ProfilePreservationDifference::UnsupportedConnectionComponent { component }
}

#[tokio::test]
async fn preserved_tls_keeps_captured_parameters_without_the_recorded_initial_layout() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut fixture = fixture().await;
        // A captured offer the native one cannot equal proves the caller's TLS was used.
        fixture.capture.ciphers.reverse();
        let input = fixture.target();
        let (context, _) = selection::selected(
            "caller-tls-transport",
            &fixture.capture,
            Some(&fixture.parameters),
            Some(&fixture.flight),
        );
        context.publish(input.extensions());
        input
            .extensions()
            .insert(UserAgent::new("caller/1").with_tls_agent(TlsAgent::Preserve));
        let established = fixture.serve(input).await.unwrap();
        let profile = established
            .input
            .extensions()
            .get_ref::<QuicProfile>()
            .unwrap();
        assert!(!matches!(
            profile.packetization().layout(),
            InitialFlightLayout::Recorded(_)
        ));
        let differences = report(&established.input);
        assert!(differences.contains(&lowered(LoweredProfileItem::CallerTls)));
        assert!(differences.contains(&unsupported(CapturedSlotKind::QuicFirstFlight)));
        assert!(!differences.contains(&unsupported(CapturedSlotKind::QuicParameters)));
        request(established.conn).await;
        let captures = fixture.task.take().unwrap().await.unwrap();
        assert_ne!(captures[1].0, fixture.capture);
        assert_eq!(
            captures[1]
                .1
                .canonical(OrderCaptureLimits::default())
                .unwrap()
                .bytes,
            fixture
                .parameters
                .canonical(OrderCaptureLimits::default())
                .unwrap()
                .bytes
        );
    })
    .await
    .unwrap();
}

/// Prepare through the UA connect modifier against a connector that never dials.
async fn prepared(
    fixture: &Fixture,
    input: ConnectRequest,
) -> EstablishedClientConnection<ServiceInput<()>, ConnectRequest> {
    let inner = service_fn(async |input: ConnectRequest| {
        let conn = ServiceInput::new(());
        conn.extensions().insert(TargetHttpVersion(Version::HTTP_3));
        Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
    });
    ProfileEmulateHttpConnectModifier::new(inner)
        .with_connection_compiler(fixture.compiler())
        .serve(input)
        .await
        .unwrap()
}

#[tokio::test]
async fn preserved_http_leaves_captured_h3_startup_unapplied() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let fixture = fixture().await;
        for keep in [false, true] {
            let input = fixture.input();
            fixture.install(&input);
            if keep {
                input
                    .extensions()
                    .insert(UserAgent::new("caller/1").with_http_agent(HttpAgent::Preserve));
            }
            let established = prepared(&fixture, input).await;
            let extensions = established.input.extensions();
            assert_eq!(extensions.contains::<ClientSettingsProfile>(), !keep);
            let prepared = extensions
                .get_ref::<PreparedConnectionComponents>()
                .unwrap();
            assert_eq!(prepared.h3_peer_settings.is_none(), keep);
            assert!(!keep || prepared.h3_sequence.is_none() && prepared.h3_bootstrap.is_none());
            assert_eq!(
                report(&established.input).contains(&lowered(LoweredProfileItem::CallerHttp)),
                keep
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn connections_are_not_shared_across_preservation_modes() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let fixture = fixture().await;
        let agents = [
            None,
            Some(UserAgent::new("caller/1").with_tls_agent(TlsAgent::Preserve)),
            Some(UserAgent::new("caller/1").with_http_agent(HttpAgent::Preserve)),
        ];
        let request_for = |agent: &Option<UserAgent>| {
            let input = fixture.input();
            fixture.install(&input);
            if let Some(agent) = agent {
                input.extensions().insert(agent.clone());
            }
            input
        };
        for (index, agent) in agents.iter().enumerate() {
            let established = prepared(&fixture, request_for(agent)).await;
            let reuse = established
                .conn
                .extensions()
                .get_ref::<ConnectionReuse>()
                .unwrap()
                .clone();
            for (other, other_agent) in agents.iter().enumerate() {
                let candidate = request_for(other_agent);
                assert_eq!(
                    reuse.matches(candidate.extensions()),
                    index == other,
                    "connection opened with {agent:?} offered to {other_agent:?}",
                );
            }
        }
    })
    .await
    .unwrap();
}
