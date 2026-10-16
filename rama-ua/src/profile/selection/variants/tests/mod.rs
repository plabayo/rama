use crate::profile::selection::capabilities::SelectionTransport;
use rama_net::tls::{ApplicationProtocol, TlsAlpn};
use std::ptr;

use rama_http::{HeaderMap, HeaderName, HeaderValue, Method, Version};

use super::shapes::request_header_shape;
use super::*;
use crate::profile::{
    analysis::{
        capture::{AnalyzedCaptureVariant, CountedCaptureAnalysis},
        profile::{AnalyzedProfile, AnalyzedProfileComponents, AnalyzedProfileScope},
    },
    capture::{
        completeness::ProfileCaptureCompleteness,
        headers::{
            HeaderCapture, HeaderCapturePolicy, HeaderOccurrence, HeaderValueSource, RequestBinding,
        },
        joint::{CaptureLevel, CapturedSlot, CapturedSlotKind, JointCapture, JointCaptureLimits},
        order::{OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture},
    },
    evidence::{
        UntrackedDistinctSnapshot,
        counts::{CounterSnapshot, ObservationLosses},
    },
    model::identity::{ConnectionIpFamily, FetchContext, ProfileKey, ResumptionContext},
};
use rama_http::header::COOKIE;

fn flow(context: ConnectionContext, version: Version) -> FlowKey {
    FlowKey::Http {
        version,
        method: Method::GET,
        initiator: None,
        fetch: None,
        connection: context,
    }
}

fn counts(total: u64) -> CounterSnapshot {
    CounterSnapshot {
        total,
        untracked: total,
        values: Box::default(),
        losses: ObservationLosses {
            history_known: true,
            ..ObservationLosses::default()
        },
        untracked_distinct: UntrackedDistinctSnapshot {
            history_known: true,
            ..UntrackedDistinctSnapshot::default()
        },
    }
}

fn connection_variant(version: u64) -> CanonicalValue {
    let value = OrderedProtocolCapture::capture(
        ProfileCaptureCompleteness::Complete,
        OrderNamespace::QuicVersion,
        [(version, [])],
        OrderCaptureLimits::default(),
    )
    .unwrap()
    .canonical(OrderCaptureLimits::default())
    .unwrap();
    JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Connection,
        slots: vec![CapturedSlot {
            kind: CapturedSlotKind::QuicVersions,
            value,
        }]
        .into(),
    }
    .canonical(JointCaptureLimits::default())
    .unwrap()
}

fn request_variant() -> CanonicalValue {
    JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Request,
        slots: Box::default(),
    }
    .canonical(JointCaptureLimits::default())
    .unwrap()
}

fn request_variant_with_headers(version: Version, fields: Vec<HeaderOccurrence>) -> CanonicalValue {
    let headers = HeaderCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        version,
        fields: fields.into(),
    }
    .canonical(&HeaderCapturePolicy::default())
    .unwrap();

    JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Request,
        slots: vec![CapturedSlot {
            kind: CapturedSlotKind::Headers,
            value: headers,
        }]
        .into(),
    }
    .canonical(JointCaptureLimits::default())
    .unwrap()
}

fn scope(
    tag: u8,
    profile: ValueId,
    flow: Option<ValueId>,
    context: ConnectionContext,
    variants: Vec<(CanonicalValue, u64)>,
) -> AnalyzedProfileScope {
    let total = variants.iter().map(|(_value, weight)| *weight).sum();
    let id = ValueId([tag; 32]);
    AnalyzedProfileScope {
        id,
        context: ProfileObservationScope {
            authorized: false,
            profile,
            flow,
            connection: context,
            structure: ValueId([tag.wrapping_add(100); 32]),
        },
        flow: None,
        structure: request_variant(),
        observations: CountedCaptureAnalysis {
            classifier_revision: 2,
            order_work: 0,
            domain: CanonicalDomain::Joint,
            scope: id,
            counts: counts(total),
            retained_samples: total as usize,
            sample_values: variants.iter().map(|(value, _weight)| value.id).collect(),
            variants: variants
                .into_iter()
                .map(|(value, weight)| AnalyzedCaptureVariant {
                    value,
                    weight: AnalyzedOrderWeight::Counted(ObservationWeight::Exact(weight)),
                })
                .collect(),
            orders: Box::default(),
            numeric: Box::default(),
        },
    }
}

fn profile(
    client: &str,
    capabilities: CapabilitySet,
    context: ConnectionContext,
) -> UserAgentProfile {
    let mut key = ProfileKey::new(client);
    key.version = Some("1".into());
    let canonical = key.canonical(MAXIMUM_IDENTITY_BYTES).unwrap();
    let version = if capabilities.h3 {
        Version::HTTP_3
    } else if capabilities.h2 {
        Version::HTTP_2
    } else {
        Version::HTTP_11
    };
    let request_flow = flow(context.clone(), version);
    let canonical_request_flow = request_flow.canonical(MAXIMUM_IDENTITY_BYTES).unwrap();
    let connection = scope(
        1,
        canonical.id,
        None,
        context.clone(),
        vec![(connection_variant(1), 1), (connection_variant(2), 3)],
    );
    let mut request = scope(
        2,
        canonical.id,
        Some(canonical_request_flow.id),
        context,
        vec![(request_variant(), 4)],
    );
    request.flow = Some(request_flow);
    let indexes = |enabled: bool| enabled.then(|| vec![0, 1].into_boxed_slice());
    UserAgentProfile::from_captured(AnalyzedProfile {
        work_units: 0,
        format_version: 1,
        classifier_revision: 2,
        id: canonical.id,
        key,
        current_day: 1,
        horizon: 1,
        components: AnalyzedProfileComponents {
            h1: indexes(capabilities.h1),
            h2: indexes(capabilities.h2),
            h3: indexes(capabilities.h3),
            tls_tcp: indexes(capabilities.tls_tcp),
            tls_quic: indexes(capabilities.tls_quic),
            quic: indexes(capabilities.quic),
        },
        scopes: vec![connection, request].into(),
    })
}

fn set_request_flow(profile: &mut UserAgentProfile, flow: FlowKey) {
    let canonical = flow.canonical(MAXIMUM_IDENTITY_BYTES).unwrap();
    let analysis = Arc::make_mut(profile.captured.as_mut().unwrap());
    let scope = analysis
        .scopes
        .iter_mut()
        .find(|scope| scope.context.flow.is_some())
        .unwrap();
    scope.context.flow = Some(canonical.id);
    scope.flow = Some(flow);
}

fn h3_capabilities() -> CapabilitySet {
    CapabilitySet {
        h3: true,
        tls_quic: true,
        quic: true,
        ..CapabilitySet::default()
    }
}

fn request(context: ConnectionContext) -> SelectionRequest {
    SelectionRequest {
        client: ProfileSelector::default(),
        required: h3_capabilities(),
        flow: flow(context, Version::HTTP_3),
        pins: VariantPins::default(),
    }
}

mod connection;
mod profile;
mod request;
