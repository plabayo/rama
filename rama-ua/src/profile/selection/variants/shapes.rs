//! Lazily decode the request variants of an immutable database entry once: the
//! bindings selection matches and the plans replay uses come from one decode.
//!
//! Scope and variant coordinates preserve identity even when IDs collide. Cookie
//! layout evidence is retained separately for each negotiated HTTP version.

use std::sync::{Arc, OnceLock};

use rama_http::{
    HeaderName, Version,
    header::{ALT_USED, COOKIE},
};
#[cfg(feature = "tls")]
use rama_tls::ExtensionId;

use super::{CookieLayoutEvidence, FlowVersions, SelectionError};
#[cfg(feature = "tls")]
use super::{derived::OrdinaryEvidence, extension_order::matches_pinned};
#[cfg(test)]
use crate::profile::format::canonical::CanonicalValue;
#[cfg(feature = "tls")]
use crate::profile::{
    analysis::{
        capture::CaptureOrderPath,
        order::{DerivedOrderRule, PinnedOrderElement},
        profile::AnalyzedProfileScope,
    },
    capture::{
        joint::{CapturedSlot, JointCapture, JointCaptureLimits},
        tls::{
            TlsCapture, TlsCaptureLimits, TlsCaptureTransport, TlsCapturedExtensionValue,
            structure::sorted_trust_anchors,
        },
    },
    format::canonical::ValueId,
};
use crate::profile::{
    analysis::{
        capture::{AnalyzedCaptureVariant, VariantValue},
        profile::AnalyzedProfile,
    },
    capture::headers::{HeaderCapture, HeaderValueSource, RequestBinding},
    format::canonical::{CanonicalDomain, ProfileDataError},
    replay::request::{
        CompactCapture, FieldEntry, FieldTable, FieldTableBuilder, PlannedField, PlannedValue,
        RequestReplayPlan,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RequestHeaderShape {
    name: HeaderName,
    occurrence: u32,
    binding: RequestBinding,
}

/// Decoded request variants shared by all selections of one database entry.
/// No captures are decoded until request selection needs them.
#[derive(Debug, Default)]
pub(crate) struct RequestShapeCache {
    decoded: OnceLock<DecodedRequests>,
    cookie_layouts: OnceLock<[CookieLayoutEvidence; 2]>,
    flow_versions: OnceLock<FlowVersions>,
    #[cfg(feature = "tls")]
    connection_modes: OnceLock<ConnectionModes>,
    #[cfg(feature = "tls")]
    ordinary_evidence: OnceLock<OrdinaryEvidence>,
}

/// Connection scope classification and, per paired scope, which variants a GREASE offer may replay.
#[cfg(feature = "tls")]
#[derive(Debug, Default)]
struct ConnectionModes {
    shapes: Box<[ConnectionShape]>,
    grease_variants: Box<[Box<[bool]>]>,
}

#[derive(Debug, Clone, Copy, Default)]
struct ConnectionShape {
    ordinary: bool,
    paired: bool,
    #[cfg(feature = "tls")]
    wire_tls: Option<ValueId>,
    #[cfg(feature = "tls")]
    grease: bool,
    #[cfg(feature = "tls")]
    http1_only_alpn: bool,
}

/// Whether a captured ClientHello offers exactly `http/1.1` in ALPN.
#[cfg(feature = "tls")]
fn alpn_is_http1_only(tls: &TlsCapture) -> bool {
    tls.extensions.iter().any(|extension| {
        extension.id == u16::from(ExtensionId::APPLICATION_LAYER_PROTOCOL_NEGOTIATION)
            && matches!(&extension.value, TlsCapturedExtensionValue::Protocols(protocols)
                if protocols.len() == 1 && protocols[0].as_ref() == b"http/1.1")
    })
}

/// Decoded ClientHellos of one connection scope variant.
#[cfg(feature = "tls")]
struct ConnectionHellos {
    effective: Option<TlsCapture>,
    outer: Option<TlsCapture>,
}

#[cfg(feature = "tls")]
fn connection_hellos(
    variant: &AnalyzedCaptureVariant,
) -> Result<ConnectionHellos, ProfileDataError> {
    let value = variant.value.canonical()?;
    let limits = JointCaptureLimits::default();
    let joint = JointCapture::from_canonical(value.as_ref(), limits)?;
    let tls_limits = TlsCaptureLimits::uniform(limits.value_bytes);
    let decode = |slot: Option<&CapturedSlot>| {
        slot.map(|slot| TlsCapture::from_canonical(&slot.value, tls_limits))
            .transpose()
    };
    Ok(ConnectionHellos {
        effective: decode(joint.effective_tls_slot())?,
        outer: decode(joint.ech_outer_slot())?,
    })
}

#[cfg(feature = "tls")]
fn classify_connections(analysis: &AnalyzedProfile) -> ConnectionModes {
    let connection = |scope: &AnalyzedProfileScope| {
        scope.context.flow.is_none() && scope.observations.domain == CanonicalDomain::Joint
    };
    let mut shapes: Box<[ConnectionShape]> = analysis
        .scopes
        .iter()
        .map(|scope| {
            if !connection(scope) {
                return ConnectionShape::default();
            }
            let classify = || -> Result<ConnectionShape, ProfileDataError> {
                let variant = scope
                    .observations
                    .variants
                    .first()
                    .ok_or(ProfileDataError::Invalid("empty connection scope"))?;
                let hellos = connection_hellos(variant)?;
                let Some(tls) = hellos.effective else {
                    return Ok(ConnectionShape {
                        ordinary: true,
                        ..Default::default()
                    });
                };
                let inner = tls.extensions.iter().any(|extension| {
                    matches!(extension.value, TlsCapturedExtensionValue::EchInner)
                });
                let paired = inner && hellos.outer.is_some();
                let wire = hellos.outer.unwrap_or(tls);
                Ok(ConnectionShape {
                    ordinary: !inner,
                    paired,
                    http1_only_alpn: alpn_is_http1_only(&wire),
                    wire_tls: wire
                        .structural(TlsCaptureLimits::uniform(
                            JointCaptureLimits::default().value_bytes,
                        ))
                        .ok()
                        .map(|value| value.id),
                    grease: false,
                })
            };
            // Malformed evidence remains eligible so the draw surfaces its error.
            classify().unwrap_or(ConnectionShape {
                ordinary: true,
                ..Default::default()
            })
        })
        .collect();
    if !shapes.iter().any(|shape| shape.paired) {
        return ConnectionModes {
            shapes,
            grease_variants: Box::default(),
        };
    }
    let mut evidence = GreaseEvidence::default();
    for (scope, shape) in analysis.scopes.iter().zip(shapes.iter()) {
        if !shape.ordinary || !connection(scope) {
            continue;
        }
        for variant in scope.observations.variants.iter() {
            if let Ok(ConnectionHellos {
                effective: Some(tls),
                ..
            }) = connection_hellos(variant)
                && let Ok(tls) = tls.with_grease_placeholders()
            {
                evidence.add_with_order(
                    &tls,
                    scope
                        .observations
                        .orders
                        .iter()
                        .find(|order| order.path == CaptureOrderPath::TlsExtensions)
                        .and_then(|order| order.evidence.derived.as_ref()),
                );
            }
        }
    }
    let grease_variants: Box<[Box<[bool]>]> = analysis
        .scopes
        .iter()
        .zip(shapes.iter())
        .map(|(scope, shape)| {
            if !shape.paired {
                return Box::default();
            }
            scope
                .observations
                .variants
                .iter()
                .map(|variant| {
                    connection_hellos(variant)
                        .ok()
                        .and_then(|hellos| hellos.outer)
                        .and_then(|outer| outer.with_grease_placeholders().ok())
                        .is_some_and(|outer| evidence.covers(&outer))
                })
                .collect()
        })
        .collect();
    for (shape, variants) in shapes.iter_mut().zip(grease_variants.iter()) {
        shape.grease = variants.contains(&true);
    }
    ConnectionModes {
        shapes,
        grease_variants,
    }
}

/// The ordinary offers of a profile on each transport, GREASE values as numbered slots.
#[cfg(feature = "tls")]
#[derive(Default)]
struct GreaseEvidence {
    tcp: TransportEvidence,
    quic: TransportEvidence,
}

/// Whole offers, and the values seen for extensions whose length varies per connection.
#[cfg(feature = "tls")]
#[derive(Default)]
struct TransportEvidence {
    offers: Vec<OfferShape>,
    shuffles: Vec<(usize, Box<[PinnedOrderElement]>)>,
    varying: Vec<(u16, TlsCapturedExtensionValue)>,
    anchors: Vec<Box<[u8]>>,
}

/// One offer: its ciphers with GREASE slots in place, and every extension with its body,
/// in wire order. Varying extensions keep their id only.
#[cfg(feature = "tls")]
#[derive(Debug, Clone, PartialEq)]
pub(super) struct OfferShape {
    protocol_version: u16,
    ciphers: Box<[u16]>,
    compression: Box<[u8]>,
    extensions: Vec<(u16, Option<TlsCapturedExtensionValue>)>,
    sorted_extensions: Box<[usize]>,
}

#[cfg(feature = "tls")]
impl OfferShape {
    pub(super) fn of(tls: &TlsCapture) -> Self {
        let extensions: Vec<_> = tls
            .extensions
            .iter()
            .filter(|extension| extension.id != u16::from(ExtensionId::PRE_SHARED_KEY))
            .map(|extension| {
                (
                    extension.id,
                    (!varies(extension.id)).then(|| {
                        if extension.id == u16::from(ExtensionId::TRUST_ANCHORS)
                            && let TlsCapturedExtensionValue::Literal(body) = &extension.value
                            && let Some(body) = sorted_trust_anchors(body)
                        {
                            TlsCapturedExtensionValue::Literal(body)
                        } else {
                            extension.value.clone()
                        }
                    }),
                )
            })
            .collect();
        let mut sorted_extensions: Box<[_]> = (0..extensions.len()).collect();
        sorted_extensions.sort_unstable_by_key(|index| extensions[*index].0);
        Self {
            sorted_extensions,
            protocol_version: tls.protocol_version,
            ciphers: tls.ciphers.clone(),
            compression: tls.compression.clone(),
            extensions,
        }
    }

    pub(super) fn same_contents(&self, other: &Self) -> bool {
        if self.protocol_version != other.protocol_version
            || self.ciphers != other.ciphers
            || self.compression != other.compression
        {
            return false;
        }
        self.sorted_extensions
            .iter()
            .map(|index| &self.extensions[*index])
            .eq(other
                .sorted_extensions
                .iter()
                .map(|index| &other.extensions[*index]))
    }
}

/// The ECH payload and QUIC transport parameter lengths vary per connection of one browser.
#[cfg(feature = "tls")]
fn varies(id: u16) -> bool {
    id == u16::from(ExtensionId::ENCRYPTED_CLIENT_HELLO)
        || id == u16::from(ExtensionId::QUIC_TRANSPORT_PARAMETERS)
}

#[cfg(feature = "tls")]
impl GreaseEvidence {
    /// Borrow evidence for the requested TLS transport.
    fn transport(&self, transport: TlsCaptureTransport) -> &TransportEvidence {
        match transport {
            TlsCaptureTransport::Tcp => &self.tcp,
            TlsCaptureTransport::Quic => &self.quic,
        }
    }

    #[cfg(test)]
    /// Add a captured offer to the evidence.
    fn add(&mut self, tls: &TlsCapture) {
        self.add_with_order(tls, None);
    }

    /// Add a captured offer together with its extension-order evidence.
    fn add_with_order(&mut self, tls: &TlsCapture, rule: Option<&DerivedOrderRule>) {
        let evidence = match tls.transport {
            TlsCaptureTransport::Tcp => &mut self.tcp,
            TlsCaptureTransport::Quic => &mut self.quic,
        };
        let shape = OfferShape::of(tls);
        let index = evidence
            .offers
            .iter()
            .position(|offer| *offer == shape)
            .unwrap_or(evidence.offers.len());
        if index == evidence.offers.len() {
            evidence.offers.push(shape);
        }
        if let Some(DerivedOrderRule::Shuffled { pinned, .. }) = rule {
            evidence.shuffles.push((index, pinned.clone()));
        }
        for extension in tls.extensions.iter() {
            if extension.id == u16::from(ExtensionId::TRUST_ANCHORS)
                && let TlsCapturedExtensionValue::Literal(body) = &extension.value
            {
                push_unique(&mut evidence.anchors, body.clone());
            }
        }
        for extension in tls
            .extensions
            .iter()
            .filter(|extension| varies(extension.id))
        {
            push_unique(
                &mut evidence.varying,
                (extension.id, extension.value.clone()),
            );
        }
    }

    /// Whether an ordinary offer equals `outer` but for its varying extensions, each of
    /// whose values an ordinary offer of that transport also sent.
    fn covers(&self, outer: &TlsCapture) -> bool {
        let evidence = self.transport(outer.transport);
        let actual = OfferShape::of(outer);
        let compatible = evidence.offers.iter().enumerate().any(|(index, expected)| {
            *expected == actual
                && !evidence
                    .shuffles
                    .iter()
                    .any(|(shuffled, _)| *shuffled == index)
        }) || evidence.shuffles.iter().any(|(index, pinned)| {
            evidence.offers[*index].same_contents(&actual)
                && matches_pinned(&outer.extensions, pinned)
        });
        compatible
            && outer
                .extensions
                .iter()
                .filter(|extension| extension.id == u16::from(ExtensionId::TRUST_ANCHORS))
                .all(|extension| {
                    let TlsCapturedExtensionValue::Literal(body) = &extension.value else {
                        return true;
                    };
                    evidence.anchors.contains(body)
                        || sorted_trust_anchors(body).is_some_and(|set| {
                            evidence
                                .anchors
                                .iter()
                                .filter(|body| sorted_trust_anchors(body).as_ref() == Some(&set))
                                .take(2)
                                .count()
                                == 2
                        })
                })
            && outer
                .extensions
                .iter()
                .filter(|extension| varies(extension.id))
                .all(|extension| {
                    evidence
                        .varying
                        .iter()
                        .any(|(id, value)| *id == extension.id && *value == extension.value)
                })
    }
}

#[cfg(feature = "tls")]
fn push_unique<T: PartialEq>(values: &mut Vec<T>, value: T) {
    if !values.contains(&value) {
        values.push(value);
    }
}

/// Every request variant of a profile by scope and variant, and the fields their plans share.
#[derive(Debug)]
struct DecodedRequests {
    scopes: Box<[Box<[Result<DecodedRequest, ProfileDataError>]>]>,
    fields: FieldTable,
}

#[derive(Debug)]
struct DecodedRequest {
    shape: DecodedRequestShape,
    plan: DecodedPlan,
}

/// Canonical captures decode into a plan here; compact ones already carry theirs.
#[derive(Debug)]
enum DecodedPlan {
    Decoded(RequestReplayPlan),
    Compact(Arc<CompactCapture>),
}

/// The replay plan of one request variant within its profile's decode.
#[derive(Debug, Clone)]
pub(crate) struct RequestPlanRef {
    cache: Arc<RequestShapeCache>,
    scope: usize,
    variant: usize,
}

impl RequestPlanRef {
    pub(crate) fn resolve(&self) -> Option<(&RequestReplayPlan, &FieldTable)> {
        let decoded = self.cache.decoded.get()?;
        let request = decoded
            .scopes
            .get(self.scope)?
            .get(self.variant)?
            .as_ref()
            .ok()?;
        match &request.plan {
            DecodedPlan::Decoded(plan) => Some((plan, &decoded.fields)),
            DecodedPlan::Compact(capture) => capture.plan(),
        }
    }
}

#[derive(Debug)]
pub(super) struct DecodedRequestShape {
    version: Option<Version>,
    pub(super) fields: Vec<RequestHeaderShape>,
    cookie_layout: CookieLayoutEvidence,
    alt_used: bool,
}

impl RequestShapeCache {
    #[cfg(feature = "tls")]
    /// Borrow the retained evidence for ordinary offers.
    pub(super) fn ordinary_evidence(&self, analysis: &AnalyzedProfile) -> &OrdinaryEvidence {
        self.ordinary_evidence
            .get_or_init(|| OrdinaryEvidence::of(analysis))
    }

    /// Decode each connection scope once. An effective ECH inner is never a
    /// standalone wire offer, whether historical or stored with its outer.
    fn connection_mode(&self, analysis: &AnalyzedProfile, index: usize) -> ConnectionShape {
        #[cfg(feature = "tls")]
        {
            self.connection_modes(analysis)
                .shapes
                .get(index)
                .copied()
                .unwrap_or_default()
        }
        #[cfg(not(feature = "tls"))]
        {
            let _ = (analysis, index);
            ConnectionShape {
                ordinary: true,
                paired: false,
            }
        }
    }

    /// Whether the connection has ordinary-offer evidence.
    pub(super) fn ordinary_connection(&self, analysis: &AnalyzedProfile, index: usize) -> bool {
        self.connection_mode(analysis, index).ordinary
    }

    /// Whether the connection has accepted-ECH evidence.
    pub(super) fn ech_connection(&self, analysis: &AnalyzedProfile, index: usize) -> bool {
        self.connection_mode(analysis, index).paired
    }

    /// Per request kind, the HTTP versions holding a flow of that kind.
    pub(super) fn flow_versions(&self, analysis: &AnalyzedProfile) -> &FlowVersions {
        self.flow_versions
            .get_or_init(|| FlowVersions::of(analysis))
    }

    /// Whether the connection's captured ALPN offer is exactly `http/1.1`.
    pub(super) fn connection_http1_only(&self, analysis: &AnalyzedProfile, index: usize) -> bool {
        #[cfg(feature = "tls")]
        {
            self.connection_mode(analysis, index).http1_only_alpn
        }
        #[cfg(not(feature = "tls"))]
        {
            let _ = (analysis, index);
            false
        }
    }

    /// Whether the connection has a supported GREASE fallback.
    pub(super) fn grease_connection(&self, analysis: &AnalyzedProfile, index: usize) -> bool {
        #[cfg(feature = "tls")]
        {
            self.connection_mode(analysis, index).grease
        }
        #[cfg(not(feature = "tls"))]
        {
            let _ = (analysis, index);
            false
        }
    }

    /// Whether variant `variant` of paired scope `index` may be replayed as a GREASE offer.
    pub(super) fn grease_variant(
        &self,
        analysis: &AnalyzedProfile,
        index: usize,
        variant: usize,
    ) -> bool {
        #[cfg(feature = "tls")]
        {
            self.connection_modes(analysis)
                .grease_variants
                .get(index)
                .and_then(|variants| variants.get(variant))
                .copied()
                .unwrap_or_default()
        }
        #[cfg(not(feature = "tls"))]
        {
            let _ = (analysis, index, variant);
            false
        }
    }

    #[cfg(feature = "tls")]
    /// Decode and retain offer modes for all connection scopes.
    fn connection_modes(&self, analysis: &AnalyzedProfile) -> &ConnectionModes {
        self.connection_modes
            .get_or_init(|| classify_connections(analysis))
    }

    /// A thin pair sample can reuse proven shuffle evidence for the same wire
    /// TLS structure. Other protocol fields still come from the paired tuple.
    #[cfg(feature = "tls")]
    pub(super) fn tls_order_scope<'a>(
        &self,
        analysis: &'a AnalyzedProfile,
        index: usize,
    ) -> &'a AnalyzedProfileScope {
        let scope = &analysis.scopes[index];
        let shape = self.connection_mode(analysis, index);
        if !shape.paired || shape.wire_tls.is_none() || scope.observations.shuffles_tls_extensions()
        {
            return scope;
        }
        analysis
            .scopes
            .iter()
            .enumerate()
            .filter(|(index, candidate)| {
                let candidate_shape = self.connection_mode(analysis, *index);
                candidate_shape.ordinary
                    && candidate_shape.wire_tls == shape.wire_tls
                    && candidate.context.connection == scope.context.connection
                    && candidate.observations.shuffles_tls_extensions()
            })
            .min_by_key(|(_, candidate)| candidate.id)
            .map_or(scope, |(_, candidate)| candidate)
    }

    #[cfg(test)]
    /// Whether the retained request plan has been initialized.
    pub(super) fn is_initialized(&self) -> bool {
        self.decoded.get().is_some()
    }

    /// Access the lazily decoded request plan.
    fn decoded(&self, analysis: &AnalyzedProfile) -> &DecodedRequests {
        self.decoded.get_or_init(|| {
            let mut fields = FieldTableBuilder::default();
            let scopes = analysis
                .scopes
                .iter()
                .map(|scope| {
                    if scope.context.flow.is_some()
                        && scope.observations.domain == CanonicalDomain::Joint
                    {
                        scope
                            .observations
                            .variants
                            .iter()
                            .map(|variant| match &variant.value {
                                VariantValue::Compact(capture) => {
                                    let (plan, table) = capture.plan().ok_or(
                                        ProfileDataError::Invalid("compact request capture"),
                                    )?;
                                    Ok(DecodedRequest {
                                        shape: request_shape(plan, |field| table.get(field)),
                                        plan: DecodedPlan::Compact(Arc::clone(capture)),
                                    })
                                }
                                VariantValue::Canonical(value) => {
                                    let plan = RequestReplayPlan::decode(value, &mut fields)?;
                                    Ok(DecodedRequest {
                                        shape: request_shape(&plan, |field| fields.get(field)),
                                        plan: DecodedPlan::Decoded(plan),
                                    })
                                }
                            })
                            .collect()
                    } else {
                        Box::default()
                    }
                })
                .collect();
            DecodedRequests {
                scopes,
                fields: fields.finish(),
            }
        })
    }

    /// The replay plan of one request variant; `None` when its capture does not
    /// decode, so replay reports that error from the capture itself.
    pub(super) fn plan(
        self: &Arc<Self>,
        analysis: &AnalyzedProfile,
        scope: usize,
        variant: usize,
    ) -> Option<RequestPlanRef> {
        let decoded = self.decoded(analysis);
        decoded.scopes.get(scope)?.get(variant)?.as_ref().ok()?;
        Some(RequestPlanRef {
            cache: Arc::clone(self),
            scope,
            variant,
        })
    }

    /// Return the cookie layout supported by the request evidence.
    pub(super) fn cookie_layout(
        &self,
        analysis: &AnalyzedProfile,
        version: Version,
    ) -> CookieLayoutEvidence {
        let index = match version {
            Version::HTTP_2 => 0,
            Version::HTTP_3 => 1,
            _ => return CookieLayoutEvidence::Unknown,
        };
        // Use observed variants before pinning or random selection. A draw with
        // one cookie field must not erase evidence from another request. Cache
        // this evidence alongside shapes rather than scanning on each request.
        self.cookie_layouts.get_or_init(|| {
            [Version::HTTP_2, Version::HTTP_3].map(|version| {
                if self
                    .decoded(analysis)
                    .scopes
                    .iter()
                    .flat_map(|scope| scope.iter())
                    .filter_map(|request| request.as_ref().ok())
                    .map(|request| &request.shape)
                    .any(|shape| {
                        shape.version == Some(version)
                            && shape.cookie_layout == CookieLayoutEvidence::Split
                    })
                {
                    CookieLayoutEvidence::Split
                } else {
                    CookieLayoutEvidence::Unknown
                }
            })
        })[index]
    }

    /// Return the request shape for the selected variant.
    pub(super) fn shape(
        &self,
        analysis: &AnalyzedProfile,
        scope: usize,
        variant: usize,
        version: Version,
    ) -> Result<&DecodedRequestShape, ProfileDataError> {
        // Scope/variant coordinates retain identity even when supplied IDs
        // collide. They also avoid copying canonical bytes into a cache key.
        let decoded = &self
            .decoded(analysis)
            .scopes
            .get(scope)
            .and_then(|scope| scope.get(variant))
            .ok_or(ProfileDataError::Invalid("request shape cache entry"))?
            .as_ref()
            .map_err(Clone::clone)?
            .shape;
        if decoded.version.is_some_and(|captured| captured != version) {
            return Err(ProfileDataError::Invalid(
                "request selection header version",
            ));
        }
        Ok(decoded)
    }
}

/// The variants matching the caller's request-owned fields that this scope recorded,
/// with how many of the caller's fields that is; without a match, the variants to
/// fall back to and `None`.
pub(super) fn request_variants_for_headers<'a>(
    variants: &[(usize, &'a AnalyzedCaptureVariant)],
    version: Version,
    requested: &HeaderCapture,
    analysis: &AnalyzedProfile,
    scope: usize,
    cache: &RequestShapeCache,
) -> Result<(Vec<&'a AnalyzedCaptureVariant>, Option<usize>), SelectionError> {
    let mut decoded = Vec::with_capacity(variants.len());
    let mut observed = Vec::<RequestHeaderShape>::new();
    let mut observed_alt_used = false;
    for (index, variant) in variants {
        let shape = cache.shape(analysis, scope, *index, version)?;
        for field in &shape.fields {
            if !observed.contains(field) {
                observed.push(field.clone());
            }
        }
        observed_alt_used |= shape.alt_used;
        decoded.push((*variant, shape));
    }

    let mut caller_alt_used = false;
    let mut requested: Vec<_> = requested
        .fields
        .iter()
        .filter_map(|field| {
            let HeaderValueSource::Request(binding) = &field.value else {
                return None;
            };
            if is_stack_owned(&field.name, *binding) {
                caller_alt_used = true;
                return None;
            }
            let shape = RequestHeaderShape {
                name: field.name.clone(),
                occurrence: field.occurrence,
                binding: *binding,
            };
            observed.contains(&shape).then_some(shape)
        })
        .collect();
    sort_request_shape(&mut requested, version);

    // A caller `Alt-Used` needs a captured slot, else it is appended where no browser sends it.
    let require_alt_used = caller_alt_used && observed_alt_used;
    // How many caller request-owned fields this scope recorded at all.
    let covered = requested.len() + usize::from(require_alt_used);
    let compatible: Vec<_> = decoded
        .iter()
        .filter_map(|(variant, shape)| {
            (shape.fields == requested && (!require_alt_used || shape.alt_used)).then_some(*variant)
        })
        .collect();
    if !compatible.is_empty() {
        return Ok((compatible, Some(covered)));
    }
    // The fallback still keeps a caller `Alt-Used` at a captured slot.
    Ok((
        decoded
            .into_iter()
            .filter_map(|(variant, shape)| (!require_alt_used || shape.alt_used).then_some(variant))
            .collect(),
        None,
    ))
}

#[cfg(test)]
pub(super) fn request_header_shape(
    value: &CanonicalValue,
) -> Result<DecodedRequestShape, ProfileDataError> {
    let mut fields = FieldTableBuilder::default();
    let plan = RequestReplayPlan::decode(value, &mut fields)?;
    Ok(request_shape(&plan, |field| fields.get(field)))
}

/// The request-owned fields selection matches, read from a variant's plan.
fn request_shape<'a>(
    plan: &RequestReplayPlan,
    entry: impl Fn(PlannedField) -> &'a FieldEntry,
) -> DecodedRequestShape {
    let mut shape = Vec::new();
    let mut version = None;
    let mut cookie_layout = CookieLayoutEvidence::Unknown;
    let mut alt_used = false;
    if let Some(headers) = plan.headers() {
        version = Some(headers.version);
        if matches!(headers.version, Version::HTTP_2 | Version::HTTP_3)
            && headers
                .fields
                .iter()
                .filter(|field| entry(**field).name == COOKIE)
                .count()
                > 1
        {
            cookie_layout = CookieLayoutEvidence::Split;
        }
        shape.extend(headers.fields.iter().filter_map(|field| {
            let entry = entry(*field);
            let PlannedValue::Request(binding) = &entry.value else {
                return None;
            };
            if is_stack_owned(&entry.name, *binding) {
                alt_used = true;
                return None;
            }
            Some(RequestHeaderShape {
                name: entry.name.clone(),
                occurrence: field.occurrence,
                binding: *binding,
            })
        }));
    }
    sort_request_shape(&mut shape, version.unwrap_or(Version::HTTP_11));
    DecodedRequestShape {
        version,
        fields: shape,
        cookie_layout,
        alt_used,
    }
}

/// The alternative-service layer writes `Alt-Used` for the endpoint in use, so its
/// captured slot stays out of the compared shape; only a caller value asks for that slot.
fn is_stack_owned(name: &HeaderName, binding: RequestBinding) -> bool {
    binding == RequestBinding::Authority && *name == ALT_USED
}

fn sort_request_shape(shape: &mut Vec<RequestHeaderShape>, version: Version) {
    // H2/H3 cookie crumbing describes the browser's layout. The number of
    // cookie pairs belongs to the current request, not the captured site.
    if matches!(version, Version::HTTP_2 | Version::HTTP_3) {
        for field in &mut *shape {
            if field.name == COOKIE && field.binding == RequestBinding::Cookie {
                field.occurrence = 0;
            }
        }
    }
    shape.sort_unstable_by(|left, right| {
        left.name
            .as_str()
            .cmp(right.name.as_str())
            .then_with(|| left.occurrence.cmp(&right.occurrence))
    });
    shape.dedup();
}

#[cfg(all(test, feature = "tls"))]
mod tests {
    #[cfg(feature = "embed-profiles")]
    use std::collections::BTreeMap;

    #[cfg(feature = "embed-profiles")]
    use super::super::derived::{self, DatabaseEvidence};
    use super::*;
    use crate::profile::{
        analysis::order::AnalyzedOrderElement,
        capture::{completeness::ProfileCaptureCompleteness, tls::TlsCapturedExtension},
    };
    #[cfg(feature = "embed-profiles")]
    use crate::profile::{
        capture::{
            joint::CapturedSlotKind,
            quic::{QuicFlightCapture, QuicFlightCaptureLimits},
        },
        format::compiled::decode_compiled_profiles,
    };

    #[expect(
        clippy::unwrap_used,
        reason = "test lists contain at most three identifiers"
    )]
    fn anchor_offer(ids: &[u8]) -> TlsCapture {
        let mut body = vec![0, u8::try_from(ids.len() * 2).unwrap()];
        for id in ids {
            body.extend([1, *id]);
        }
        TlsCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            transport: TlsCaptureTransport::Quic,
            protocol_version: 771,
            ciphers: Box::new([4865]),
            compression: Box::new([0]),
            extensions: Box::new([TlsCapturedExtension {
                id: u16::from(ExtensionId::TRUST_ANCHORS),
                value: TlsCapturedExtensionValue::Literal(body.into()),
            }]),
        }
    }

    #[test]
    fn anchor_permutations_require_observed_variability_of_the_same_multiset() {
        let mut evidence = GreaseEvidence::default();
        evidence.add(&anchor_offer(&[1, 2, 3]));
        assert!(!evidence.covers(&anchor_offer(&[3, 1, 2])));
        evidence.add(&anchor_offer(&[2, 1, 3]));
        assert!(evidence.covers(&anchor_offer(&[3, 1, 2])));
        assert!(!evidence.covers(&anchor_offer(&[3, 1, 1])));
        assert!(!evidence.covers(&anchor_offer(&[1, 2])));
    }

    #[test]
    fn fixed_extension_order_cannot_vouch_for_a_reversed_outer() {
        let mut ordinary = anchor_offer(&[1]);
        let mut extensions = ordinary.extensions.into_vec();
        extensions.push(TlsCapturedExtension {
            id: 1234,
            value: TlsCapturedExtensionValue::Literal(Box::default()),
        });
        ordinary.extensions = extensions.into();
        let mut reversed = ordinary.clone();
        reversed.extensions.reverse();
        let mut evidence = GreaseEvidence::default();
        evidence.add(&ordinary);
        assert!(!evidence.covers(&reversed));
        evidence.add_with_order(
            &ordinary,
            Some(&DerivedOrderRule::Shuffled {
                elements: Box::default(),
                pinned: Box::default(),
            }),
        );
        assert!(evidence.covers(&reversed));
        let mut pinned = GreaseEvidence::default();
        pinned.add_with_order(
            &ordinary,
            Some(&DerivedOrderRule::Shuffled {
                elements: Box::default(),
                pinned: Box::new([PinnedOrderElement {
                    index: 0,
                    element: AnalyzedOrderElement::Literal {
                        id: u64::from(ordinary.extensions[0].id),
                        occurrence: 0,
                    },
                }]),
            }),
        );
        assert!(!pinned.covers(&reversed));
    }

    #[cfg(feature = "embed-profiles")]
    #[test]
    fn embedded_derived_offers_match_whole_ordinary_offers() {
        let mut counts = BTreeMap::new();
        for analysis in
            decode_compiled_profiles(include_bytes!("../../format/embed_profiles.bin")).unwrap()
        {
            let cache = RequestShapeCache::default();
            let database = DatabaseEvidence::default();
            let mut evidence = GreaseEvidence::default();
            let mut parameter_evidence = Vec::new();
            for (index, scope) in analysis.scopes.iter().enumerate() {
                if scope.context.flow.is_some() || !cache.ordinary_connection(&analysis, index) {
                    continue;
                }
                for variant in scope.observations.variants.iter() {
                    if let Some(tls) = connection_hellos(variant).unwrap().effective {
                        let value = variant.value.canonical().unwrap();
                        let joint =
                            JointCapture::from_canonical(&value, JointCaptureLimits::default())
                                .unwrap();
                        if let Some(parameters) = joint
                            .slots
                            .iter()
                            .find(|slot| slot.kind == CapturedSlotKind::QuicParameters)
                        {
                            let length = tls
                                .extensions
                                .iter()
                                .find(|extension| {
                                    extension.id
                                        == u16::from(ExtensionId::QUIC_TRANSPORT_PARAMETERS)
                                })
                                .map(|extension| extension.value.clone());
                            parameter_evidence.push((length, parameters.value.clone()));
                        }
                        evidence.add_with_order(
                            &tls.with_grease_placeholders().unwrap(),
                            scope
                                .observations
                                .orders
                                .iter()
                                .find(|order| order.path == CaptureOrderPath::TlsExtensions)
                                .and_then(|order| order.evidence.derived.as_ref()),
                        );
                    }
                }
            }
            for (index, scope) in analysis.scopes.iter().enumerate() {
                if !cache.ech_connection(&analysis, index) {
                    continue;
                }
                for variant in scope.observations.variants.iter() {
                    let value = variant.value.canonical().unwrap();
                    let mut joint =
                        JointCapture::from_canonical(&value, JointCaptureLimits::default())
                            .unwrap();
                    let outer = connection_hellos(variant).unwrap().outer.unwrap();
                    if evidence.transport(outer.transport).offers.is_empty() {
                        continue;
                    }
                    let captured_version = joint
                        .slots
                        .iter()
                        .find(|slot| slot.kind == CapturedSlotKind::QuicFirstFlight)
                        .map(|slot| {
                            QuicFlightCapture::from_canonical(
                                &slot.value,
                                QuicFlightCaptureLimits::default(),
                            )
                            .unwrap()
                            .flight
                            .version
                        });
                    let ordinary_has_ech =
                        evidence
                            .transport(outer.transport)
                            .offers
                            .iter()
                            .any(|offer| {
                                offer.extensions.iter().any(|(id, _)| {
                                    *id == u16::from(ExtensionId::ENCRYPTED_CLIENT_HELLO)
                                })
                            });
                    derived::derive(&mut joint, cache.ordinary_evidence(&analysis), || {
                        database.family_evidence(analysis.id)
                    })
                    .unwrap();
                    assert_eq!(joint.ech_outer_slot().is_some(), ordinary_has_ech);
                    if let Some(version) = captured_version {
                        let flight = joint
                            .slots
                            .iter()
                            .find(|slot| slot.kind == CapturedSlotKind::QuicFirstFlight)
                            .unwrap();
                        assert_eq!(
                            QuicFlightCapture::from_canonical(
                                &flight.value,
                                QuicFlightCaptureLimits::default()
                            )
                            .unwrap()
                            .flight
                            .version,
                            version
                        );
                    }
                    let outer = TlsCapture::from_canonical(
                        &joint
                            .ech_outer_slot()
                            .or_else(|| joint.effective_tls_slot())
                            .unwrap()
                            .value,
                        TlsCaptureLimits::uniform(JointCaptureLimits::default().value_bytes),
                    )
                    .unwrap()
                    .with_grease_placeholders()
                    .unwrap();
                    let actual = OfferShape::of(&outer);
                    let expected = &evidence.transport(outer.transport).offers;
                    let family = &analysis.key.client;
                    let transport = outer.transport;
                    if transport == TlsCaptureTransport::Quic {
                        let length = outer
                            .extensions
                            .iter()
                            .find(|extension| {
                                extension.id == u16::from(ExtensionId::QUIC_TRANSPORT_PARAMETERS)
                            })
                            .map(|extension| extension.value.clone());
                        let parameters = joint
                            .slots
                            .iter()
                            .find(|slot| slot.kind == CapturedSlotKind::QuicParameters)
                            .unwrap();
                        assert!(
                            parameter_evidence
                                .iter()
                                .any(|(ordinary_length, ordinary)| *ordinary_length == length
                                    && ordinary.bytes == parameters.value.bytes),
                            "{family} {transport:?}: quic_parameters tuple"
                        );
                    }
                    assert!(
                        expected
                            .iter()
                            .any(|offer| offer.protocol_version == actual.protocol_version),
                        "{family} {transport:?}: protocol_version"
                    );
                    assert!(
                        expected.iter().any(|offer| offer.ciphers == actual.ciphers),
                        "{family} {transport:?}: ciphers"
                    );
                    assert!(
                        expected
                            .iter()
                            .any(|offer| offer.compression == actual.compression),
                        "{family} {transport:?}: compression"
                    );
                    for extension in &actual.extensions {
                        assert!(
                            expected
                                .iter()
                                .any(|offer| offer.extensions.contains(extension)),
                            "{family} {transport:?}: extension {} {:?}",
                            extension.0,
                            extension.1
                        );
                    }
                    assert!(
                        evidence.covers(&outer),
                        "{family} {transport:?}: whole offer or varying extension {:?}",
                        outer.extensions
                    );
                    *counts
                        .entry((
                            family.clone(),
                            if transport == TlsCaptureTransport::Tcp {
                                "tcp"
                            } else {
                                "quic"
                            },
                        ))
                        .or_insert(0) += 1;
                }
            }
        }
        for ((family, transport), count) in &counts {
            eprintln!("{family} {transport}: {count} matched, 0 diverged");
        }
        assert!(!counts.is_empty());
    }
}
