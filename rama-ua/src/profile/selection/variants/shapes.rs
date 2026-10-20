//! Lazily decode request bindings once per immutable database entry.
//!
//! Scope and variant coordinates preserve identity even when IDs collide. Cookie
//! layout evidence is retained separately for each negotiated HTTP version.

use super::{CookieLayoutEvidence, SelectionError};
use crate::profile::{
    analysis::{capture::AnalyzedCaptureVariant, profile::AnalyzedProfile},
    capture::{
        headers::{HeaderCapture, HeaderCapturePolicy, HeaderValueSource, RequestBinding},
        joint::{CaptureLevel, CapturedSlotKind, JointCapture, JointCaptureLimits},
    },
    format::canonical::{CanonicalDomain, CanonicalValue, ProfileDataError},
};
use rama_http::{HeaderName, Version, header::COOKIE};
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RequestHeaderShape {
    name: HeaderName,
    occurrence: u32,
    binding: RequestBinding,
}

/// Decoded request bindings shared by all selections of one database entry.
/// No captures are decoded until request selection needs them.
#[derive(Debug, Default)]
pub(crate) struct RequestShapeCache {
    shapes: OnceLock<Box<[RequestScopeShapes]>>,
    cookie_layouts: OnceLock<[CookieLayoutEvidence; 2]>,
}

type RequestScopeShapes = Box<[Result<DecodedRequestShape, ProfileDataError>]>;

#[derive(Debug)]
pub(super) struct DecodedRequestShape {
    version: Option<Version>,
    pub(super) fields: Vec<RequestHeaderShape>,
    cookie_layout: CookieLayoutEvidence,
}

impl RequestShapeCache {
    #[cfg(test)]
    pub(super) fn is_initialized(&self) -> bool {
        self.shapes.get().is_some()
    }

    fn decoded(&self, analysis: &AnalyzedProfile) -> &[RequestScopeShapes] {
        self.shapes.get_or_init(|| {
            analysis
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
                            .map(|variant| request_header_shape(&variant.value))
                            .collect()
                    } else {
                        Box::default()
                    }
                })
                .collect()
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
                    .iter()
                    .flat_map(|scope| scope.iter())
                    .filter_map(|shape| shape.as_ref().ok())
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
        let shapes = self.decoded(analysis);
        let decoded = shapes
            .get(scope)
            .and_then(|scope| scope.get(variant))
            .ok_or(ProfileDataError::Invalid("request shape cache entry"))?
            .as_ref()
            .map_err(Clone::clone)?;
        if decoded.version.is_some_and(|captured| captured != version) {
            return Err(ProfileDataError::Invalid(
                "request selection header version",
            ));
        }
        Ok(&decoded.fields)
    }
}

pub(super) fn request_variants_for_headers<'a>(
    variants: &[(usize, &'a AnalyzedCaptureVariant)],
    version: Version,
    requested: &HeaderCapture,
    analysis: &AnalyzedProfile,
    scope: usize,
    cache: &RequestShapeCache,
) -> Result<Vec<&'a AnalyzedCaptureVariant>, SelectionError> {
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

    Ok(decoded
        .into_iter()
        .filter_map(|(variant, shape)| (shape == requested).then_some(variant))
        .collect())
}

pub(super) fn request_header_shape(
    value: &CanonicalValue,
) -> Result<DecodedRequestShape, ProfileDataError> {
    let limits = JointCaptureLimits::default();
    let joint = JointCapture::from_canonical(value, limits)?;
    if joint.level != CaptureLevel::Request {
        return Err(ProfileDataError::Invalid("request selection capture level"));
    }

    let mut shape = Vec::new();
    let mut version = None;
    let mut cookie_layout = CookieLayoutEvidence::Unknown;
    for slot in &joint.slots {
        match slot.kind {
            CapturedSlotKind::Headers => {
                let captured =
                    HeaderCapture::from_canonical(&slot.value, &HeaderCapturePolicy::default())?;
                version = Some(captured.version);
                if matches!(captured.version, Version::HTTP_2 | Version::HTTP_3)
                    && captured
                        .fields
                        .iter()
                        .filter(|field| field.name == COOKIE)
                        .count()
                        > 1
                {
                    cookie_layout = CookieLayoutEvidence::Split;
                }
                shape.extend(captured.fields.iter().filter_map(|field| {
                    let HeaderValueSource::Request(binding) = &field.value else {
                        return None;
                    };
                    Some(RequestHeaderShape {
                        name: field.name.clone(),
                        occurrence: field.occurrence,
                        binding: *binding,
                    })
                }));
            }
            CapturedSlotKind::PseudoHeaders | CapturedSlotKind::RuntimeMetadata => {}
            _ => {
                return Err(ProfileDataError::Invalid(
                    "connection slot in request selection",
                ));
            }
        }
    }
    sort_request_shape(&mut shape, version.unwrap_or(Version::HTTP_11));
    Ok(DecodedRequestShape {
        version,
        fields: shape,
        cookie_layout,
    })
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
