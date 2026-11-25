use std::collections::BTreeMap;

use super::*;
use rama_ua::profile::{
    capture::{
        CAPTURE_REVISION,
        headers::{HeaderCapture, HeaderCapturePolicy},
        http2::{H2Capture, H2CaptureLimits, H2CapturedFrame},
        joint::{CaptureLevel, CapturedSlot, JointCapture, JointCaptureLimits},
        observation::ProfileCapture,
    },
    evidence::{
        ProfileEvidence, ProfileScopeEvidence,
        ingestion::ObservationId,
        window::{ProfileWindowLimits, RetainedBucketWindow},
    },
    format::archive::{ProfileArchiveEntry, ProfileArchiveLimits, ProfileArchiveWriter},
    model::identity::{ConnectionContext, FlowKey, ProfileKey},
    selection::{
        DrawKey, ProfileSeed,
        capabilities::CapabilitySet,
        database::UserAgentDatabase,
        variants::{EmulationContext, ProfileSelector, SelectionRequest, VariantPins},
    },
};

// Use a loaded counted profile, so the reuse witness comes from the same public
// selection/compilation path as the UA connector, rather than a fabricated key.
pub(super) fn selected(client: &str) -> (EmulationContext, ConnectionSelection) {
    selected_with_tls(client, true)
}

pub(super) fn selected_with_tls(
    client: &str,
    tls: bool,
) -> (EmulationContext, ConnectionSelection) {
    let slots = if tls {
        vec![CapturedSlot {
            kind: CapturedSlotKind::TcpTls,
            value: capture().canonical(TlsCaptureLimits::default()).unwrap(),
        }]
    } else {
        Vec::new()
    };
    selected_connections(
        client,
        tls,
        vec![(ConnectionContext::default(), slots)],
        &ConnectionContext::default(),
    )
}

/// Draw `client`'s connection for `draw` from connections observed with their TLS slots.
pub(super) fn selected_connections(
    client: &str,
    tls: bool,
    connections: Vec<(ConnectionContext, Vec<CapturedSlot>)>,
    draw: &ConnectionContext,
) -> (EmulationContext, ConnectionSelection) {
    let flow = FlowKey::Http {
        version: "HTTP/2.0".parse().unwrap(),
        method: "GET".parse().unwrap(),
        initiator: None,
        fetch: None,
        connection: ConnectionContext::default(),
    };
    let database = connection_database(client, connections);
    let selected = Arc::new(
        database
            .select(
                &SelectionRequest {
                    client: ProfileSelector::default(),
                    required: CapabilitySet {
                        h2: true,
                        tls_tcp: tls,
                        ..CapabilitySet::default()
                    },
                    flow,
                    pins: VariantPins::default(),
                },
                ProfileSeed([4; 32]),
                DrawKey([5; 32]),
            )
            .unwrap(),
    );
    let connection = selected
        .connection(draw, ProfileSeed([4; 32]), DrawKey([6; 32]))
        .unwrap();
    let context =
        selected.emulation_context(ProfileSeed([4; 32]), DrawKey([6; 32]), DrawKey([7; 32]));
    (context, connection)
}

pub(super) fn connection_database(
    client: &str,
    connections: Vec<(ConnectionContext, Vec<CapturedSlot>)>,
) -> UserAgentDatabase {
    let flow = FlowKey::Http {
        version: "HTTP/2.0".parse().unwrap(),
        method: "GET".parse().unwrap(),
        initiator: None,
        fetch: None,
        connection: ConnectionContext::default(),
    };
    let request = HeaderCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        version: "HTTP/2.0".parse().unwrap(),
        fields: Box::default(),
    }
    .canonical(&HeaderCapturePolicy::default())
    .unwrap();
    let early_frames = H2Capture {
        completeness: ProfileCaptureCompleteness::Complete,
        frames: vec![H2CapturedFrame::Settings {
            ack: false,
            entries: Box::default(),
        }]
        .into(),
    }
    .canonical(H2CaptureLimits::default())
    .unwrap();
    let observations = connections
        .into_iter()
        .map(|(context, mut slots)| {
            slots.push(CapturedSlot {
                kind: CapturedSlotKind::Http2EarlyFrames,
                value: early_frames.clone(),
            });
            (None, context, CaptureLevel::Connection, slots)
        })
        .chain([(
            Some(flow),
            ConnectionContext::default(),
            CaptureLevel::Request,
            vec![CapturedSlot {
                kind: CapturedSlotKind::Headers,
                value: request,
            }],
        )]);
    // Observations of one scope share its window.
    let mut windows = BTreeMap::new();
    for (sequence, (flow, connection, level, slots)) in (1..).zip(observations) {
        let observation = ProfileCapture {
            revision: CAPTURE_REVISION,
            profile: ProfileKey::new(client),
            flow,
            connection,
            joint: JointCapture {
                completeness: ProfileCaptureCompleteness::Complete,
                level,
                slots: slots.into(),
            },
        };
        let prepared = observation
            .prepare(false, JointCaptureLimits::default())
            .unwrap();
        for bucket in prepared.buckets {
            let (_, _, _, window) = windows.entry(bucket.scope.id).or_insert_with(|| {
                (
                    bucket.scope.clone(),
                    prepared.flow.clone(),
                    bucket.structure.clone(),
                    RetainedBucketWindow::new(
                        bucket.value.validated_domain(65536).unwrap(),
                        bucket.scope.id,
                        [3; 32],
                        ProfileWindowLimits::default(),
                    )
                    .unwrap(),
                )
            });
            window
                .observe(
                    100,
                    100,
                    ObservationId {
                        run: [1; 16],
                        sequence,
                    },
                    &bucket.value,
                )
                .unwrap();
        }
    }
    let scopes: Vec<_> = windows
        .into_values()
        .map(|(scope, flow, structure, window)| ProfileScopeEvidence {
            scope,
            flow,
            structure,
            window: window.snapshot(),
        })
        .collect();
    let archive =
        ProfileArchiveWriter::new(Vec::new(), false, 100, 14, ProfileArchiveLimits::default())
            .unwrap()
            .write_profile(ProfileArchiveEntry {
                evidence: ProfileEvidence {
                    format_version: 1,
                    profile: ProfileKey::new(client).canonical(65536).unwrap(),
                    scopes: scopes.into(),
                },
                sampler_seed: [3; 32],
            })
            .unwrap()
            .finish()
            .unwrap();
    UserAgentDatabase::try_from_archive(&archive, false, 100, 14, ProfileArchiveLimits::default())
        .unwrap()
}
