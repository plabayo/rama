//! Draw a fresh TLS extension order per connection for scopes that shuffle it.

use std::collections::BTreeMap;

use rama_tls::is_grease_u16;

use crate::profile::{
    analysis::{
        capture::CaptureOrderPath,
        order::{AnalyzedOrderElement, DerivedOrderRule, PinnedOrderElement},
        profile::AnalyzedProfileScope,
    },
    capture::{
        joint::{CapturedSlotKind, JointCapture, JointCaptureLimits},
        tls::{TlsCapture, TlsCaptureLimits, TlsCapturedExtension},
    },
    format::canonical::{CanonicalDomain, CanonicalValue, ProfileDataError},
    selection::ProfileDraw,
};

fn shuffle(
    extensions: &[TlsCapturedExtension],
    pinned: &[PinnedOrderElement],
    draw: &mut ProfileDraw,
) -> Box<[TlsCapturedExtension]> {
    let mut placed = vec![None; extensions.len()];
    let mut floating = Vec::new();
    let mut reserved = 0;
    let mut occurrences = BTreeMap::<u16, u16>::new();
    for extension in extensions {
        // The classifier keeps constant GREASE slots as literals and varying ones as reserved.
        let occurrence = occurrences.entry(extension.id).or_default();
        let literal = AnalyzedOrderElement::Literal {
            id: u64::from(extension.id),
            occurrence: *occurrence,
        };
        *occurrence += 1;
        let grease = is_grease_u16(extension.id).then(|| {
            reserved += 1;
            AnalyzedOrderElement::Reserved {
                occurrence: reserved - 1,
            }
        });
        let slot = pinned
            .iter()
            .find(|pin| pin.element == literal || Some(pin.element) == grease)
            .and_then(|pin| placed.get_mut(pin.index))
            .filter(|slot| slot.is_none());
        match slot {
            Some(slot) => *slot = Some(extension.clone()),
            None => floating.push(extension.clone()),
        }
    }
    draw.shuffle(&mut floating);
    let mut floating = floating.into_iter();
    placed
        .into_iter()
        .filter_map(|slot| slot.or_else(|| floating.next()))
        .collect()
}

/// The selected capture with a drawn TLS extension order, when its scope shuffles.
pub(super) fn draw_extension_order(
    scope: &AnalyzedProfileScope,
    capture: CanonicalValue,
    draw: &mut ProfileDraw,
) -> Result<CanonicalValue, ProfileDataError> {
    let Some(DerivedOrderRule::Shuffled { pinned, .. }) = scope
        .observations
        .orders
        .iter()
        .find(|order| order.path == CaptureOrderPath::TlsExtensions)
        .and_then(|order| order.evidence.derived.as_ref())
    else {
        return Ok(capture);
    };
    if scope.observations.domain != CanonicalDomain::Joint {
        return Ok(capture);
    }
    let limits = JointCaptureLimits::default();
    let tls_limits = TlsCaptureLimits::default();
    let mut joint = JointCapture::from_canonical(&capture, limits)?;
    for slot in &mut joint.slots {
        if matches!(
            slot.kind,
            CapturedSlotKind::TcpTls | CapturedSlotKind::QuicTls
        ) {
            let mut tls = TlsCapture::from_canonical(&slot.value, tls_limits)?;
            tls.extensions = shuffle(&tls.extensions, pinned, draw);
            slot.value = tls.canonical(tls_limits)?;
        }
    }
    joint.canonical(limits)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    #[cfg(feature = "embed-profiles")]
    use std::slice;

    use rama_tls::{grease_u16, is_grease_u16};
    use rama_utils::octets::kib;

    use super::*;
    #[cfg(feature = "embed-profiles")]
    use crate::profile::format::compiled::{decode_compiled_profiles, encode_compiled_profiles};
    use crate::profile::{
        analysis::profile::{AnalyzedProfile, ProfileAnalysisLimits, analyze_profile_evidence},
        capture::{
            CAPTURE_REVISION,
            completeness::ProfileCaptureCompleteness,
            joint::{CaptureLevel, CapturedSlot},
            observation::ProfileCapture,
            tls::{TlsCaptureTransport, TlsCapturedExtensionValue},
        },
        evidence::{
            ProfileEvidence, ProfileScopeEvidence,
            ingestion::ObservationId,
            window::{ProfileWindowLimits, RetainedBucketWindow},
        },
        format::canonical::ValueId,
        model::identity::{ConnectionContext, ProfileKey},
        selection::{DrawDomain, DrawKey, ProfileDrawContext, ProfileSeed},
    };

    const FLOATING: [u16; 5] = [1000, 2000, 3000, 4000, 5000];

    fn permutations(items: &[u16]) -> Vec<Vec<u16>> {
        if items.len() <= 1 {
            return vec![items.to_vec()];
        }
        let mut all = Vec::new();
        for index in 0..items.len() {
            let mut rest = items.to_vec();
            let first = rest.remove(index);
            for mut tail in permutations(&rest) {
                tail.insert(0, first);
                all.push(tail);
            }
        }
        all
    }

    /// A connection whose ClientHello has fresh GREASE at both ends and shuffled extensions.
    fn hello(order: &[u16], connection: usize) -> CapturedSlot {
        let grease = |offset: usize| grease_u16((connection + offset) % 16).unwrap();
        let mut extensions = vec![TlsCapturedExtension {
            id: grease(0),
            value: TlsCapturedExtensionValue::Literal(Box::default()),
        }];
        extensions.extend(order.iter().map(|&id| TlsCapturedExtension {
            id,
            value: TlsCapturedExtensionValue::Literal(Box::default()),
        }));
        extensions.push(TlsCapturedExtension {
            id: grease(7),
            value: TlsCapturedExtensionValue::Literal(vec![0].into()),
        });
        CapturedSlot {
            kind: CapturedSlotKind::TcpTls,
            value: TlsCapture {
                completeness: ProfileCaptureCompleteness::Complete,
                transport: TlsCaptureTransport::Tcp,
                protocol_version: 0x0303,
                ciphers: vec![grease(3), 0x1301].into(),
                compression: vec![0].into(),
                extensions: extensions.into(),
            }
            .canonical(TlsCaptureLimits::default())
            .unwrap(),
        }
    }

    /// Raw evidence of every order, analyzed as an export would.
    fn analyzed() -> AnalyzedProfile {
        let key = ProfileKey::new("shuffling-browser");
        let mut profile = None;
        let mut windows = BTreeMap::<ValueId, (ProfileScopeEvidence, RetainedBucketWindow)>::new();
        for (connection, order) in permutations(&FLOATING).iter().enumerate() {
            let prepared = ProfileCapture {
                revision: CAPTURE_REVISION,
                profile: key.clone(),
                flow: None,
                connection: ConnectionContext::default(),
                joint: JointCapture {
                    completeness: ProfileCaptureCompleteness::Complete,
                    level: CaptureLevel::Connection,
                    slots: vec![hello(order, connection)].into(),
                },
            }
            .prepare(false, JointCaptureLimits::default())
            .unwrap();
            profile = Some(prepared.profile);
            for input in prepared.buckets.into_vec() {
                let (_, window) = windows.entry(input.scope.id).or_insert_with(|| {
                    let window = RetainedBucketWindow::new(
                        input.value.validated_domain(kib(64)).unwrap(),
                        input.scope.id,
                        [3; 32],
                        ProfileWindowLimits::default(),
                    )
                    .unwrap();
                    let evidence = ProfileScopeEvidence {
                        scope: input.scope.clone(),
                        flow: None,
                        structure: input.structure.clone(),
                        window: window.snapshot(),
                    };
                    (evidence, window)
                });
                window
                    .observe(
                        100,
                        100,
                        ObservationId {
                            run: [1; 16],
                            sequence: connection as u64 + 1,
                        },
                        &input.value,
                    )
                    .unwrap();
            }
        }
        let evidence = ProfileEvidence {
            format_version: 1,
            profile: profile.unwrap(),
            scopes: windows
                .into_values()
                .map(|(mut evidence, window)| {
                    evidence.window = window.snapshot();
                    evidence
                })
                .collect(),
        };
        analyze_profile_evidence(
            &evidence,
            false,
            [3; 32],
            100,
            14,
            ProfileAnalysisLimits::default(),
        )
        .unwrap()
    }

    fn drawn_ids(scope: &AnalyzedProfileScope, key: u8) -> Vec<u16> {
        let capture = scope.observations.variants[0]
            .value
            .canonical()
            .unwrap()
            .into_owned();
        let mut draw = ProfileDraw::new(
            ProfileSeed([5; 32]),
            ProfileDrawContext {
                profile: ValueId([2; 32]),
                analysis_revision: 4,
                scope: scope.id,
                key: DrawKey([key; 32]),
                domain: DrawDomain::TlsExtensions,
                slot: 0,
            },
        );
        let drawn = draw_extension_order(scope, capture, &mut draw).unwrap();
        let joint = JointCapture::from_canonical(&drawn, JointCaptureLimits::default()).unwrap();
        let tls =
            TlsCapture::from_canonical(&joint.slots[0].value, TlsCaptureLimits::default()).unwrap();
        tls.extensions
            .iter()
            .map(|extension| extension.id)
            .collect()
    }

    fn assert_shuffled_with_grease_ends(profile: &AnalyzedProfile) {
        let scope = profile
            .scopes
            .iter()
            .find(|scope| {
                scope.context.flow.is_none() && scope.observations.domain == CanonicalDomain::Joint
            })
            .unwrap();
        // Every order the shuffle explains reads as one connection variant.
        assert_eq!(scope.observations.variants.len(), 1);
        let mut orders = BTreeSet::new();
        for key in 0..64 {
            let drawn = drawn_ids(scope, key);
            assert_eq!(drawn, drawn_ids(scope, key));
            assert_eq!(drawn.len(), FLOATING.len() + 2);
            assert!(is_grease_u16(drawn[0]), "{drawn:?}");
            assert!(is_grease_u16(drawn[drawn.len() - 1]), "{drawn:?}");
            let mut floating = drawn[1..drawn.len() - 1].to_vec();
            orders.insert(floating.clone());
            floating.sort_unstable();
            assert_eq!(floating, FLOATING);
        }
        assert!(orders.len() > 1, "{orders:?}");
    }

    #[test]
    fn shuffled_connections_keep_their_grease_ends_and_draw_the_rest() {
        assert_shuffled_with_grease_ends(&analyzed());
    }

    #[cfg(feature = "embed-profiles")]
    #[test]
    fn compiled_shuffled_connections_keep_their_grease_ends_and_draw_the_rest() {
        let compiled = decode_compiled_profiles(
            &encode_compiled_profiles(slice::from_ref(&analyzed())).unwrap(),
        )
        .unwrap();
        assert_shuffled_with_grease_ends(&compiled[0]);
    }
}
