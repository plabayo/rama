//! User-Agent profile emulation per connection: drawing the connection variant of a
//! selected profile and compiling it for the native TLS or QUIC connector.

#![expect(
    clippy::unwrap_used,
    reason = "bench: panic-on-error is the standard pattern for harnesses"
)]

use std::{
    mem,
    sync::{Arc, LazyLock},
};

use divan::{Bencher, black_box};
use rama::{
    bytes::Bytes,
    extensions::ExtensionsRef as _,
    http::{Method, Version},
    net::{
        Protocol, address::HostWithPort, client::ConnectRequest, http::TargetHttpVersion,
        tls::TargetEchConfig,
    },
    quic::{
        profile::replay::ConnectionProfileCompiler as QuicCompiler,
        tls::{BoringTlsProvider, QuicClientConfigProvider},
    },
    tls::{
        boring::client::profile::compiler::ConnectionProfileCompiler as TcpCompiler,
        client::TlsClientConfig,
    },
    ua::profile::{
        capture::joint::{CapturedSlotKind, JointCapture, JointCaptureLimits},
        format::canonical::{CanonicalDomain, ValueId},
        model::{
            identity::{ConnectionContext, FlowKey},
            runtime_hints::RequestInitiator,
            ua::UserAgentProfile,
        },
        replay::connection::{
            compiler::ConnectionProfileCompiler, preparation::ConnectionPreparation,
        },
        selection::{
            DrawKey, ProfileSeed,
            capabilities::CapabilitySet,
            database::UserAgentDatabase,
            variants::{
                ConnectionOfferMode, EmulationContext, ProfileSelector, SelectedProfile,
                SelectionRequest, VariantPins,
            },
        },
    },
};

mod bench_alloc;

fn main() {
    divan::main();
}

static DATABASE: LazyLock<UserAgentDatabase> =
    LazyLock::new(|| UserAgentDatabase::try_embedded().unwrap());

/// How the connection to the target offers ECH.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ech {
    /// An ordinary captured offer.
    Ordinary,
    /// A captured ECH pair, the target publishing an ECH configuration.
    Real,
    /// A captured ECH pair whose outer is offered with GREASE ECH: the target publishes none.
    Grease,
    /// A paired-only profile whose non-ECH offer must be derived.
    Derived,
}

/// The first captured ECH pair of `selected` that also holds every slot in `slots`.
fn paired_variant(selected: &SelectedProfile, slots: &[CapturedSlotKind]) -> Option<ValueId> {
    let analysis = selected.profile().captured.as_ref()?;
    analysis
        .scopes
        .iter()
        .filter(|scope| scope.context.flow.is_none())
        .flat_map(|scope| scope.observations.variants.iter())
        .find_map(|variant| {
            let value = variant.value.canonical().ok()?;
            let joint = JointCapture::from_canonical(&value, JointCaptureLimits::default()).ok()?;
            let kinds: Vec<_> = joint.slots.iter().map(|slot| slot.kind).collect();
            (kinds.contains(&CapturedSlotKind::TlsOuter)
                && slots.iter().all(|slot| kinds.contains(slot)))
            .then(|| variant.value.id())
        })
}

/// Isolate paired connection scopes while retaining their request recipes and component indices.
fn paired_database(profile: &UserAgentProfile) -> Option<UserAgentDatabase> {
    let mut profile = profile.clone();
    let analysis = Arc::make_mut(profile.captured.as_mut()?);
    let mut next = 0;
    let mut mapping = Vec::with_capacity(analysis.scopes.len());
    for scope in analysis.scopes.iter() {
        let keep = if scope.context.flow.is_none()
            && scope.observations.domain == CanonicalDomain::Joint
        {
            let value = scope
                .observations
                .variants
                .first()?
                .value
                .canonical()
                .ok()?;
            let joint = JointCapture::from_canonical(&value, JointCaptureLimits::default()).ok()?;
            joint
                .slots
                .iter()
                .any(|slot| slot.kind == CapturedSlotKind::TlsOuter)
        } else {
            true
        };
        mapping.push(keep.then(|| {
            let index = next;
            next += 1;
            index
        }));
    }
    analysis.scopes = mem::take(&mut analysis.scopes)
        .into_vec()
        .into_iter()
        .enumerate()
        .filter_map(|(index, scope)| mapping[index].map(|_| scope))
        .collect();
    for component in [
        &mut analysis.components.h1,
        &mut analysis.components.h2,
        &mut analysis.components.h3,
        &mut analysis.components.tls_tcp,
        &mut analysis.components.tls_quic,
        &mut analysis.components.quic,
    ] {
        *component = component.take().map(|indices| {
            indices
                .iter()
                .filter_map(|index| mapping[*index])
                .collect::<Box<[_]>>()
        });
        if component.as_ref().is_some_and(|indices| indices.is_empty()) {
            *component = None;
        }
    }
    Some([profile].into_iter().collect())
}

/// A connect input carrying the emulation context of `client` for `version`.
fn input(client: &str, version: Version, ech: Ech) -> ConnectRequest {
    let (required, initiator, slots) = if version == Version::HTTP_3 {
        (
            CapabilitySet {
                h3: true,
                tls_quic: true,
                quic: true,
                ..CapabilitySet::default()
            },
            // The embedded HTTP/3 captures are form submissions.
            RequestInitiator::Form,
            [
                CapturedSlotKind::QuicTls,
                CapturedSlotKind::QuicParameters,
                CapturedSlotKind::Http3Settings,
            ]
            .as_slice(),
        )
    } else {
        (
            CapabilitySet {
                h2: true,
                tls_tcp: true,
                ..CapabilitySet::default()
            },
            RequestInitiator::Navigate,
            [CapturedSlotKind::TcpTls, CapturedSlotKind::Http2EarlyFrames].as_slice(),
        )
    };
    let flow = FlowKey::Http {
        version,
        method: Method::GET,
        initiator: Some(initiator),
        fetch: None,
        connection: ConnectionContext::default(),
    };
    let key = DrawKey([2; 32]);
    let select = |seed, pins| {
        DATABASE.select(
            &SelectionRequest {
                client: ProfileSelector {
                    client: Some(client.into()),
                    ..ProfileSelector::default()
                },
                required,
                flow: flow.clone(),
                pins,
            },
            seed,
            key,
        )
    };
    let (seed, selected) = (1..=u8::MAX)
        .map(|byte| ProfileSeed([byte; 32]))
        .find_map(|seed| {
            let selected = select(seed, VariantPins::default()).ok()?;
            if ech == Ech::Ordinary {
                return Some((seed, selected));
            }
            let pins = VariantPins {
                connection: Some(paired_variant(&selected, slots)?),
                request: None,
            };
            let selected = select(seed, pins).ok()?;
            let selected = if ech == Ech::Derived {
                paired_database(selected.profile())?
                    .select(
                        &SelectionRequest {
                            client: ProfileSelector::default(),
                            required,
                            flow: flow.clone(),
                            pins,
                        },
                        seed,
                        key,
                    )
                    .ok()?
            } else {
                selected
            };
            if ech == Ech::Derived {
                selected
                    .connection(&ConnectionContext::default(), seed, key)
                    .ok()?;
            }
            if ech == Ech::Grease {
                let (_, mode) = selected
                    .connection_with_offer_mode(&ConnectionContext::default(), seed, key, false)
                    .ok()?;
                if mode != ConnectionOfferMode::Grease {
                    return None;
                }
            }
            Some((seed, selected))
        })
        .unwrap();
    let target: HostWithPort = "origin.example:443".parse().unwrap();
    let request = ConnectRequest::new(target.clone()).with_application_protocol(Protocol::HTTPS);
    request.extensions().insert(TargetHttpVersion(version));
    if ech == Ech::Real {
        request
            .extensions()
            .insert(TargetEchConfig::new(target, Bytes::from_static(b"config")));
    }
    let pins = selected.pins();
    EmulationContext {
        selected: Arc::new(selected),
        seed,
        connection_key: key,
        request_key: key,
        pins,
    }
    .publish(request.extensions());
    request
}

/// Draw, decode and compile one connection, keeping the selection as the connect modifier does.
fn connect<C: ConnectionProfileCompiler<ConnectRequest>>(
    bencher: Bencher<'_, '_>,
    compiler: &C,
    input: &ConnectRequest,
) {
    bencher.bench_local(|| {
        let ech = compiler.ech_ready(input);
        let (preparation, compiled) =
            ConnectionPreparation::prepare_with_ech(input, ech, |selection, components| {
                compiler.compile(input, selection, components)
            })
            .unwrap()
            .unwrap();
        black_box((preparation.selection().clone(), preparation, compiled))
    });
}

#[divan::bench(args = [Ech::Ordinary, Ech::Real, Ech::Grease, Ech::Derived])]
fn boring_tcp(bencher: Bencher<'_, '_>, ech: Ech) {
    let compiler = TcpCompiler::new(TlsClientConfig::default_http());
    connect(bencher, &compiler, &input("Chromium", Version::HTTP_2, ech));
}

#[divan::bench(args = [Ech::Ordinary, Ech::Real, Ech::Grease, Ech::Derived])]
fn quic_replay(bencher: Bencher<'_, '_>, ech: Ech) {
    let provider: Arc<dyn QuicClientConfigProvider> = Arc::new(BoringTlsProvider::new());
    let compiler = QuicCompiler::new(TlsClientConfig::default_http(), provider);
    connect(bencher, &compiler, &input("Chromium", Version::HTTP_3, ech));
}
