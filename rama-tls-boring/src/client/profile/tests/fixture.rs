use super::*;
use rama_ua::profile::{
    capture::{
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
    let flow = FlowKey::Http {
        version: "HTTP/2.0".parse().unwrap(),
        method: "GET".parse().unwrap(),
        initiator: None,
        fetch: None,
        connection: ConnectionContext::default(),
    };
    let mut scopes = Vec::new();
    for level in [CaptureLevel::Connection, CaptureLevel::Request] {
        let observation = ProfileCapture {
            profile: ProfileKey::new(client),
            flow: (level == CaptureLevel::Request).then(|| flow.clone()),
            connection: ConnectionContext::default(),
            joint: JointCapture {
                completeness: ProfileCaptureCompleteness::Complete,
                level,
                slots: if level == CaptureLevel::Connection {
                    let mut slots = Vec::new();
                    if tls {
                        slots.push(CapturedSlot {
                            kind: CapturedSlotKind::TcpTls,
                            value: capture().canonical(TlsCaptureLimits::default()).unwrap(),
                        });
                    }
                    slots.push(CapturedSlot {
                        kind: CapturedSlotKind::Http2EarlyFrames,
                        value: H2Capture {
                            completeness: ProfileCaptureCompleteness::Complete,
                            frames: vec![H2CapturedFrame::Settings {
                                ack: false,
                                entries: Box::default(),
                            }]
                            .into(),
                        }
                        .canonical(H2CaptureLimits::default())
                        .unwrap(),
                    });
                    slots.into()
                } else {
                    vec![CapturedSlot {
                        kind: CapturedSlotKind::Headers,
                        value: HeaderCapture {
                            completeness: ProfileCaptureCompleteness::Complete,
                            version: "HTTP/2.0".parse().unwrap(),
                            fields: Box::default(),
                        }
                        .canonical(&HeaderCapturePolicy::default())
                        .unwrap(),
                    }]
                    .into()
                },
            },
        };
        let prepared = observation
            .prepare(false, JointCaptureLimits::default())
            .unwrap();
        for bucket in prepared.buckets {
            let mut window = RetainedBucketWindow::new(
                bucket.value.validated_domain(65536).unwrap(),
                bucket.scope.id,
                [3; 32],
                ProfileWindowLimits::default(),
            )
            .unwrap();
            window
                .observe(
                    100,
                    100,
                    ObservationId {
                        run: [1; 16],
                        sequence: 1,
                    },
                    &bucket.value,
                )
                .unwrap();
            scopes.push(ProfileScopeEvidence {
                scope: bucket.scope,
                flow: prepared.flow.clone(),
                structure: bucket.structure,
                window: window.snapshot(),
            });
        }
    }
    scopes.sort_unstable_by_key(|scope| scope.scope.id);
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
    let database = UserAgentDatabase::try_from_archive(
        &archive,
        false,
        100,
        14,
        ProfileArchiveLimits::default(),
    )
    .unwrap();
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
        .connection(
            &ConnectionContext::default(),
            ProfileSeed([4; 32]),
            DrawKey([6; 32]),
        )
        .unwrap();
    let context =
        selected.emulation_context(ProfileSeed([4; 32]), DrawKey([6; 32]), DrawKey([7; 32]));
    (context, connection)
}
