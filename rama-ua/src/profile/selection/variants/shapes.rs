//! Lazily decode the request variants of an immutable database entry once: the
//! bindings selection matches and the plans replay uses come from one decode.
//!
//! Scope and variant coordinates preserve identity even when IDs collide. Cookie
//! layout evidence is retained separately for each negotiated HTTP version.

use super::{CookieLayoutEvidence, SelectionError};
#[cfg(test)]
use crate::profile::format::canonical::CanonicalValue;
#[cfg(feature = "tls")]
use crate::profile::{
    analysis::profile::AnalyzedProfileScope,
    capture::{
        joint::{CapturedSlotKind, JointCapture, JointCaptureLimits},
        tls::{TlsCapture, TlsCaptureLimits, TlsCapturedExtensionValue},
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
use rama_http::{HeaderName, Version, header::COOKIE};
use std::sync::{Arc, OnceLock};

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
    #[cfg(feature = "tls")]
    connection_modes: OnceLock<Box<[ConnectionShape]>>,
}

#[derive(Debug, Clone, Copy, Default)]
struct ConnectionShape {
    ordinary: bool,
    paired: bool,
    #[cfg(feature = "tls")]
    wire_tls: Option<ValueId>,
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
}

impl RequestShapeCache {
    /// Decode each connection scope once. An effective ECH inner is never a
    /// standalone wire offer, whether historical or stored with its outer.
    fn connection_mode(&self, analysis: &AnalyzedProfile, index: usize) -> ConnectionShape {
        #[cfg(feature = "tls")]
        {
            self.connection_modes
                .get_or_init(|| {
                    analysis
                        .scopes
                        .iter()
                        .map(|scope| {
                            if scope.context.flow.is_some()
                                || scope.observations.domain != CanonicalDomain::Joint
                            {
                                return ConnectionShape::default();
                            }
                            let classify = || -> Result<ConnectionShape, ProfileDataError> {
                                let variant =
                                    scope.observations.variants.first().ok_or(
                                        ProfileDataError::Invalid("empty connection scope"),
                                    )?;
                                let value = variant.value.canonical()?;
                                let limits = JointCaptureLimits::default();
                                let joint = JointCapture::from_canonical(value.as_ref(), limits)?;
                                let tls_limits = TlsCaptureLimits {
                                    elements: limits.value_bytes,
                                    bytes: limits.value_bytes,
                                };
                                let effective = joint.slots.iter().find(|slot| {
                                    matches!(
                                        slot.kind,
                                        CapturedSlotKind::TcpTls | CapturedSlotKind::QuicTls
                                    )
                                });
                                let outer = joint
                                    .slots
                                    .iter()
                                    .find(|slot| slot.kind == CapturedSlotKind::TlsOuter);
                                let Some(effective) = effective else {
                                    return Ok(ConnectionShape {
                                        ordinary: true,
                                        ..Default::default()
                                    });
                                };
                                let tls = TlsCapture::from_canonical(&effective.value, tls_limits)?;
                                let inner = tls.extensions.iter().any(|extension| {
                                    matches!(extension.value, TlsCapturedExtensionValue::EchInner)
                                });
                                let wire = match outer {
                                    Some(slot) => {
                                        TlsCapture::from_canonical(&slot.value, tls_limits)?
                                    }
                                    None => tls,
                                };
                                Ok(ConnectionShape {
                                    ordinary: !inner,
                                    paired: inner && outer.is_some(),
                                    wire_tls: wire
                                        .structural(tls_limits)
                                        .ok()
                                        .map(|value| value.id),
                                })
                            };
                            // Malformed evidence remains eligible so the draw surfaces its error.
                            classify().unwrap_or(ConnectionShape {
                                ordinary: true,
                                ..Default::default()
                            })
                        })
                        .collect()
                })
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

    pub(super) fn ordinary_connection(&self, analysis: &AnalyzedProfile, index: usize) -> bool {
        self.connection_mode(analysis, index).ordinary
    }

    pub(super) fn ech_connection(&self, analysis: &AnalyzedProfile, index: usize) -> bool {
        self.connection_mode(analysis, index).paired
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
    pub(super) fn is_initialized(&self) -> bool {
        self.decoded.get().is_some()
    }

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

    pub(super) fn shape(
        &self,
        analysis: &AnalyzedProfile,
        scope: usize,
        variant: usize,
        version: Version,
    ) -> Result<&[RequestHeaderShape], ProfileDataError> {
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
        Ok(&decoded.fields)
    }
}

/// The variants matching the caller's request-owned fields that this scope recorded,
/// and how many of the caller's fields that is.
pub(super) fn request_variants_for_headers<'a>(
    variants: &[(usize, &'a AnalyzedCaptureVariant)],
    version: Version,
    requested: &HeaderCapture,
    analysis: &AnalyzedProfile,
    scope: usize,
    cache: &RequestShapeCache,
) -> Result<(Vec<&'a AnalyzedCaptureVariant>, usize), SelectionError> {
    let mut decoded = Vec::with_capacity(variants.len());
    let mut observed = Vec::<RequestHeaderShape>::new();
    for (index, variant) in variants {
        let shape = cache.shape(analysis, scope, *index, version)?;
        for field in shape {
            if !observed.contains(field) {
                observed.push(field.clone());
            }
        }
        decoded.push((*variant, shape));
    }

    let mut requested: Vec<_> = requested
        .fields
        .iter()
        .filter_map(|field| {
            let HeaderValueSource::Request(binding) = &field.value else {
                return None;
            };
            let shape = RequestHeaderShape {
                name: field.name.clone(),
                occurrence: field.occurrence,
                binding: *binding,
            };
            observed.contains(&shape).then_some(shape)
        })
        .collect();
    sort_request_shape(&mut requested, version);

    // How many caller request-owned fields this scope recorded at all.
    let covered = requested.len();
    Ok((
        decoded
            .into_iter()
            .filter_map(|(variant, shape)| (shape == requested).then_some(variant))
            .collect(),
        covered,
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
    }
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
