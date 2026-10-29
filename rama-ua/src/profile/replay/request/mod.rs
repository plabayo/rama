mod plan;
mod qpack;

use std::{collections::VecDeque, error::Error, fmt};

use rama_core::{extensions::Extension, telemetry::tracing};
use rama_http::{
    HeaderMap, HeaderName, HeaderValue, Version,
    header::{COOKIE, Entry},
    proto::{
        h2::PseudoHeaderOrder,
        h3::qpack::{
            FieldSectionBase,
            encoding::{FieldPreferences, HeaderPreferences},
        },
    },
};
use serde::Serialize;

pub(crate) use self::plan::{FieldTable, FieldTableBuilder, PlannedValue, RequestReplayPlan};
use self::plan::{PlannedHeaders, PlannedSlot};
use super::h3_bootstrap::Insertions;
use crate::profile::{
    capture::{
        headers::RequestBinding,
        http3::{H3ClientSequenceCapture, bootstrap::H3BootstrapCapture},
        joint::CapturedSlotKind,
    },
    format::canonical::ProfileDataError,
    model::identity::FlowKey,
    selection::variants::{CookieLayoutEvidence, RequestSelection},
};

/// A caller-provided H2 option that can add or change connection wire output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum H2ClientParameter {
    InitialSettings,
    HeaderTableSize,
    EarlyFrames,
    ReplayEarlyFrames,
    InitialStreamWindowSize,
    InitialConnectionWindowSize,
    KeepAliveInterval,
    KeepAliveTimeout,
    KeepAliveWhileIdle,
    MaximumHeaderListSize,
    MaximumFrameSize,
    MaximumConcurrentStreams,
    AdaptiveWindow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
/// One observable difference between the selected capture and emitted request.
pub enum ProfilePreservationDifference {
    /// Reserved SETTINGS were retained without classification evidence.
    UnanalyzedHttp3ReservedSettings,
    /// No capture proves how to lay out several caller cookie pairs; retain
    /// the caller's fields without claiming an exact captured layout.
    UnknownCookieLayout,
    /// The selected capture has no wire compiler in this connector. Its presence
    /// in connection extensions does not establish that it was applied.
    UnsupportedConnectionComponent {
        component: CapturedSlotKind,
    },
    /// The caller set another value; the profile's value is replayed.
    CallerValueReplaced {
        name: HeaderName,
        occurrence: u32,
    },
    MissingRequestBinding {
        name: HeaderName,
        occurrence: u32,
        binding: RequestBinding,
    },
    AppendedCallerField {
        name: HeaderName,
        occurrence: u32,
    },
    /// Replay retained a caller option that can alter H2 wire output.
    RetainedH2ClientParameter {
        parameter: H2ClientParameter,
    },
    /// A captured property was emitted with native or caller behaviour instead.
    LoweredProfileItem {
        item: LoweredProfileItem,
    },
}

/// A captured property replaced by native or caller behaviour during replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum LoweredProfileItem {
    /// SNI presence follows the destination identity.
    TlsServerNamePresence,
    /// The caller's explicit ALPN offer was retained.
    CallerTlsAlpn,
    /// The captured ALPN offer lacks the required HTTP version.
    TlsAlpnTargetVersion,
    /// The caller's required session offer was retained.
    CallerTlsSessionOffer,
    /// A captured session offer is sent only when a compatible stored session exists.
    TlsSessionOfferOptional,
    /// The caller's TLS version bounds were retained.
    CallerTlsVersionBounds,
    /// The caller's cipher suite policy was retained.
    CallerTlsCipherSuites,
    /// The captured TLS offer cannot be replayed safely; the connection uses native TLS.
    TlsNativeConnection,
    /// Legacy version or compression fields use native values.
    TlsLegacyFields,
    /// A field native TLS always sends was absent from the capture.
    TlsRequiredField { extension: u16 },
    /// A captured extension or its shape has no native equivalent.
    TlsExtension { extension: u16 },
    /// Unsupported cipher suites were dropped, or the native list kept.
    TlsCipherSuites,
    /// The captured offer is preserved, but some advertised suites cannot negotiate.
    TlsCipherNegotiation,
    /// Unsupported groups were dropped, or the native list kept.
    TlsSupportedGroups,
    /// Unsupported signature schemes were dropped, or the native list kept.
    TlsSignatureAlgorithms,
    /// The version list or its order follows native negotiation.
    TlsSupportedVersions,
    /// Key shares follow native selection.
    TlsKeyShares,
    /// EC point formats are sent as native TLS 1.2 offers do.
    TlsEcPointFormats,
    /// The session ticket extension is omitted without a TLS 1.2 offer.
    TlsSessionTicket,
    /// The captured ALPS offer is replaced by the native one.
    TlsAlps,
    /// The captured certificate compression list is replaced by the native one.
    TlsCertificateCompression,
    /// Trust anchors follow the current binding, if any.
    TlsTrustAnchors,
    /// Extended master secret and renegotiation info are sent together.
    TlsLegacyExtensionPair,
    /// The engine's transport-parameter length differs from the capture.
    QuicTransportParametersLength,
    /// The caller's QUIC transport profile was retained.
    CallerQuicProfile,
    /// The caller's HTTP/3 SETTINGS profile was retained.
    CallerHttp3Settings,
    /// The caller's QPACK Base preference was retained.
    CallerQpackBase,
    /// The caller's QPACK field preferences were retained.
    CallerQpackFieldPreferences,
    /// The captured HTTP/3 stream order has no allocated-ID startup equivalent.
    Http3StartupOrder,
    /// The caller's HTTP/3 critical stream startup was retained.
    CallerHttp3Startup,
    /// The caller's initial QPACK encoder preferences were retained.
    CallerQpackEncoding,
    /// The caller's HTTP/3 control frame preferences were retained.
    CallerHttp3Controls,
    /// Captured initial QPACK insertions were dropped; the section uses native encoding.
    Http3InitialInsertions,
    /// The connection was recorded without HTTP/2 SETTINGS; native ones are sent.
    Http2Settings,
    /// The request was sent on a connection the profile connector did not open or
    /// could not emulate; only its request fields follow the profile.
    UnemulatedConnection,
    /// The caller's User-Agent value was kept, as asked by
    /// [`PreserveHeaderUserAgent`](crate::layer::emulate::PreserveHeaderUserAgent).
    CallerUserAgent,
    /// The caller's client hint values were kept, as asked by
    /// [`PreserveClientHints`](crate::layer::emulate::PreserveClientHints).
    CallerClientHints,
    /// The caller's HTTP headers and connection settings were kept, as asked by
    /// [`HttpAgent::Preserve`](crate::HttpAgent::Preserve).
    CallerHttp,
    /// The connection used the caller's own TLS configuration, as asked by
    /// [`TlsAgent::Preserve`](crate::TlsAgent::Preserve).
    CallerTls,
}

#[derive(Debug, Clone, Default, Serialize, Extension)]
#[extension(tags(ua, http))]
/// Ordered differences accumulated while compiling and replaying a profile.
pub struct ProfilePreservationReport {
    pub differences: Box<[ProfilePreservationDifference]>,
}

impl ProfilePreservationReport {
    #[must_use]
    pub fn is_exact(&self) -> bool {
        self.differences.is_empty()
    }

    /// Append later-stage differences while preserving their execution order.
    #[must_use]
    pub fn followed_by(mut self, later: Self) -> Self {
        if self.differences.is_empty() {
            return later;
        }
        if later.differences.is_empty() {
            return self;
        }

        let mut differences = self.differences.into_vec();
        differences.extend(later.differences);
        self.differences = differences.into();
        self
    }

    /// Record one difference; replay continues with the lowered behaviour.
    pub fn push(&mut self, difference: ProfilePreservationDifference) {
        tracing::debug!(
            ?difference,
            "captured profile replay differs from its capture"
        );
        let mut differences = std::mem::take(&mut self.differences).into_vec();
        differences.push(difference);
        self.differences = differences.into();
    }
}

/// Request metadata rebuilt from a selected captured variant.
#[derive(Debug, Clone)]
pub struct ReplayedRequestProfile {
    pub headers: Option<HeaderMap>,
    pub pseudo_headers: Option<PseudoHeaderOrder>,
    /// A section-local QPACK Base rule derived from available field metadata.
    pub qpack_base: Option<FieldSectionBase>,
    /// Native field choices matched to the final emitted occurrences.
    pub qpack_headers: Option<HeaderPreferences>,
    pub report: ProfilePreservationReport,
}

#[derive(Debug)]
/// Failure to replay a selected profile from malformed or unusable captured data.
pub enum ProfileReplayError {
    Data(ProfileDataError),
    /// A registered backend could not prepare its selected native configuration.
    ConnectionCompilation(rama_core::error::BoxError),
    IncompatibleHeaderVersion {
        captured: Version,
        requested: Version,
    },
}

impl fmt::Display for ProfileReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Data(error) => error.fmt(f),
            Self::ConnectionCompilation(error) => {
                write!(f, "compile captured connection: {error}")
            }
            Self::IncompatibleHeaderVersion {
                captured,
                requested,
            } => write!(
                f,
                "captured header version {captured:?} is incompatible with {requested:?}"
            ),
        }
    }
}

impl Error for ProfileReplayError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ConnectionCompilation(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

impl From<ProfileDataError> for ProfileReplayError {
    fn from(value: ProfileDataError) -> Self {
        Self::Data(value)
    }
}

impl RequestSelection {
    /// Rebuild request headers in captured order.
    ///
    /// Caller fields absent from the capture are request-owned and are appended
    /// after the captured sequence in their original relative order. Every
    /// deviation from the capture is recorded in the returned report.
    pub fn replay_request(
        &self,
        original: &HeaderMap,
    ) -> Result<ReplayedRequestProfile, ProfileReplayError> {
        self.replay_with_insertions(original, None)
    }

    pub(crate) fn replay_initial_request(
        &self,
        original: &HeaderMap,
        bootstrap: &H3BootstrapCapture,
        sequence: &H3ClientSequenceCapture,
    ) -> Result<ReplayedRequestProfile, ProfileReplayError> {
        let FlowKey::Http { method, .. } = &self.effective.flow else {
            return Err(ProfileDataError::Invalid("HTTP bootstrap flow").into());
        };
        let insertions = match Insertions::new(bootstrap, sequence, self.variant, method).and_then(
            |insertions| {
                insertions.validate_request(&self.effective.capture)?;
                Ok(insertions)
            },
        ) {
            Ok(insertions) => insertions,
            Err(ProfileDataError::Unsupported(reason)) => {
                return self.replay_without_initial_insertions(original, reason);
            }
            Err(error) => return Err(error.into()),
        };
        match self.replay_with_insertions(original, Some(&insertions)) {
            Err(ProfileReplayError::Data(ProfileDataError::Unsupported(reason))) => {
                self.replay_without_initial_insertions(original, reason)
            }
            result => result,
        }
    }

    fn replay_without_initial_insertions(
        &self,
        original: &HeaderMap,
        reason: &'static str,
    ) -> Result<ReplayedRequestProfile, ProfileReplayError> {
        tracing::debug!(
            reason,
            "HTTP/3 request replay drops captured initial QPACK insertions"
        );
        let mut replayed = self.replay_with_insertions(original, None)?;
        replayed
            .report
            .push(ProfilePreservationDifference::LoweredProfileItem {
                item: LoweredProfileItem::Http3InitialInsertions,
            });
        Ok(replayed)
    }

    fn replay_with_insertions(
        &self,
        original: &HeaderMap,
        insertions: Option<&Insertions<'_>>,
    ) -> Result<ReplayedRequestProfile, ProfileReplayError> {
        let decoded;
        let (plan, table) =
            if let Some(found) = self.effective.plan.as_ref().and_then(|plan| plan.resolve()) {
                found
            } else {
                let mut fields = FieldTableBuilder::default();
                let plan = RequestReplayPlan::decode(&self.effective.capture, &mut fields)?;
                decoded = (plan, fields.finish());
                (&decoded.0, &decoded.1)
            };
        let (version, method) = match &self.effective.flow {
            FlowKey::Http {
                version, method, ..
            } => (*version, method),
            FlowKey::Other { .. } => {
                return Err(ProfileDataError::Invalid("HTTP replay flow").into());
            }
        };
        let mut headers = None;
        let mut pseudo_headers = None;
        let mut qpack_base = None;
        let mut qpack_headers = None;
        let mut report = ProfilePreservationReport::default();
        let mut initial_regular_fields = None;
        let mut initial_pseudo_fields = None;
        for slot in plan.slots.iter() {
            match slot {
                PlannedSlot::Headers(captured) => {
                    if captured.version != version {
                        return Err(ProfileReplayError::IncompatibleHeaderVersion {
                            captured: captured.version,
                            requested: version,
                        });
                    }
                    if version == Version::HTTP_3 {
                        qpack::observe_base(
                            &mut qpack_base,
                            captured
                                .fields
                                .iter()
                                .filter_map(|field| table.get(*field).representation.as_ref()),
                        );
                    }
                    if version == Version::HTTP_3
                        && captured
                            .fields
                            .iter()
                            .any(|field| table.get(*field).representation.is_some())
                    {
                        qpack_headers.get_or_insert_with(HeaderPreferences::default);
                    }
                    headers = Some(replay_headers(
                        captured,
                        table,
                        original,
                        self.effective.cookie_layout,
                        &mut report,
                        qpack_headers.as_mut().map(|choices| &mut choices.headers),
                    )?);
                    if let Some(insertions) = &insertions {
                        let pseudo_count =
                            insertions
                                .fields()
                                .checked_sub(captured.fields.len())
                                .ok_or(ProfileDataError::Invalid("initial QPACK field count"))?;
                        initial_regular_fields = Some(captured.fields.len());
                        let choices = qpack_headers.get_or_insert_with(HeaderPreferences::default);
                        for (index, field) in captured.fields.iter().enumerate() {
                            let insertion = insertions.for_field(
                                pseudo_count + index,
                                table.get(*field).name.as_str().as_bytes(),
                                table.get(*field).representation.as_ref(),
                            )?;
                            if let Some(insertion) = insertion {
                                let Entry::Occupied(mut entry) =
                                    choices.headers.entry(table.get(*field).name.clone())
                                else {
                                    return Err(ProfileDataError::Invalid(
                                        "missing initial QPACK header preference",
                                    )
                                    .into());
                                };
                                let preference = entry
                                    .iter_mut()
                                    .nth(field.occurrence as usize)
                                    .ok_or(ProfileDataError::Invalid(
                                        "missing initial QPACK header occurrence",
                                    ))?;
                                if preference.never_index {
                                    return Err(ProfileDataError::Unsupported(
                                        "sensitive initial QPACK insertion",
                                    )
                                    .into());
                                }
                                preference.insertion = Some(insertion);
                            }
                        }
                    }
                }
                PlannedSlot::PseudoHeaders(captured) => {
                    if captured.version != version {
                        return Err(ProfileReplayError::IncompatibleHeaderVersion {
                            captured: captured.version,
                            requested: version,
                        });
                    }
                    captured.validate_method(method)?;
                    if version == Version::HTTP_3 {
                        qpack::observe_base(
                            &mut qpack_base,
                            captured
                                .fields
                                .iter()
                                .filter_map(|field| field.representation.as_ref()),
                        );
                    }
                    if version == Version::HTTP_3 {
                        initial_pseudo_fields = Some(captured.fields.len());
                        for (index, field) in captured.fields.iter().enumerate() {
                            if let Some(metadata) = &field.representation {
                                let mut preferences = qpack::field_preferences(metadata)?;
                                if let Some(insertions) = &insertions {
                                    preferences.insertion = insertions.for_field(
                                        index,
                                        field.name.as_str().as_bytes(),
                                        Some(metadata),
                                    )?;
                                    if preferences.never_index && preferences.insertion.is_some() {
                                        return Err(ProfileDataError::Unsupported(
                                            "sensitive initial QPACK insertion",
                                        )
                                        .into());
                                    }
                                }
                                qpack_headers
                                    .get_or_insert_with(HeaderPreferences::default)
                                    .pseudo_headers
                                    .insert(field.name, preferences);
                            }
                        }
                    }
                    pseudo_headers = Some(captured.fields.iter().map(|field| field.name).collect());
                }
                PlannedSlot::RuntimeMetadata => {}
            }
        }
        if let Some(insertions) = &insertions
            && initial_regular_fields
                .zip(initial_pseudo_fields)
                .and_then(|(regular, pseudo)| regular.checked_add(pseudo))
                != Some(insertions.fields())
        {
            return Err(ProfileDataError::Invalid("initial QPACK field count").into());
        }
        Ok(ReplayedRequestProfile {
            headers,
            pseudo_headers,
            qpack_base,
            qpack_headers,
            report,
        })
    }
}

fn replay_headers(
    captured: &PlannedHeaders,
    table: &FieldTable,
    original: &HeaderMap,
    cookie_layout: CookieLayoutEvidence,
    report: &mut ProfilePreservationReport,
    mut encoding: Option<&mut HeaderMap<FieldPreferences>>,
) -> Result<HeaderMap, ProfileReplayError> {
    let mut original = original
        .ordered_iter()
        .map(|(name, value)| OriginalHeader {
            name: name.clone(),
            value: value.clone(),
            used: false,
        })
        .collect::<Vec<_>>();
    let cookie_slots = if matches!(captured.version, Version::HTTP_2 | Version::HTTP_3) {
        captured
            .fields
            .iter()
            .filter(|field| {
                table.get(**field).name == COOKIE
                    && matches!(
                        &table.get(**field).value,
                        PlannedValue::Request(RequestBinding::Cookie)
                    )
            })
            .count()
    } else {
        0
    };
    let mut cookies = replay_cookie_values(&mut original, cookie_slots, cookie_layout, report)?;
    let mut cookie_slot = 0;
    let mut output = HeaderMap::with_capacity(captured.fields.len().max(original.len()));
    for field in &captured.fields {
        if table.get(*field).name == COOKIE
            && matches!(
                &table.get(*field).value,
                PlannedValue::Request(RequestBinding::Cookie)
            )
            && let Some(values) = &mut cookies
        {
            cookie_slot += 1;
            // Keep captured positions where possible. Additional caller pairs
            // occupy the final cookie position; fewer pairs leave no empty slots.
            let count = if cookie_slot == cookie_slots {
                values.len()
            } else {
                1
            };
            for _ in 0..count {
                if let Some(mut value) = values.pop_front() {
                    value.set_sensitive(value.is_sensitive() || table.get(*field).sensitive);
                    if let Some(encoding) = &mut encoding {
                        encoding.append(
                            table.get(*field).name.clone(),
                            qpack::optional_preferences(table.get(*field).representation.as_ref())?,
                        );
                    }
                    output.append(table.get(*field).name.clone(), value);
                }
            }
            continue;
        }

        let original_index = occurrence_index(&original, &table.get(*field).name, field.occurrence);
        let original_value = original_index.map(|index| {
            original[index].used = true;
            original[index].value.clone()
        });
        let value = match &table.get(*field).value {
            PlannedValue::Profile(value) => {
                let mut profile = value.clone();
                if original_value.is_some_and(|caller| caller.as_bytes() != profile.as_bytes()) {
                    report.push(ProfilePreservationDifference::CallerValueReplaced {
                        name: table.get(*field).name.clone(),
                        occurrence: field.occurrence,
                    });
                }
                profile.set_sensitive(table.get(*field).sensitive);
                profile
            }
            PlannedValue::Request(binding) => {
                let Some(value) = original_value else {
                    report.push(ProfilePreservationDifference::MissingRequestBinding {
                        name: table.get(*field).name.clone(),
                        occurrence: field.occurrence,
                        binding: *binding,
                    });
                    continue;
                };
                value
            }
        };
        let mut value = value;
        value.set_sensitive(value.is_sensitive() || table.get(*field).sensitive);
        if let Some(encoding) = &mut encoding {
            encoding.append(
                table.get(*field).name.clone(),
                qpack::optional_preferences(table.get(*field).representation.as_ref())?,
            );
        }
        output.append(table.get(*field).name.clone(), value);
    }
    let mut occurrences = ahash::HashMap::<HeaderName, u32>::default();
    for field in original {
        let occurrence = occurrences.entry(field.name.clone()).or_default();
        let current = *occurrence;
        *occurrence += 1;
        if field.used {
            continue;
        }
        report.push(ProfilePreservationDifference::AppendedCallerField {
            name: field.name.clone(),
            occurrence: current,
        });
        output.append(field.name, field.value);
    }
    // Caller-owned fields are the caller's to bound; the HTTP encoder validates them.
    Ok(output)
}

/// RFC 9113 §8.2.3 allows Cookie to be split between fields and joined with
/// "; ". Preserve pair order and bytes; only separator whitespace is normalized
/// when reproducing a split capture. Set-Cookie never takes this path.
fn replay_cookie_values(
    original: &mut [OriginalHeader],
    slots: usize,
    layout: CookieLayoutEvidence,
    report: &mut ProfilePreservationReport,
) -> Result<Option<VecDeque<HeaderValue>>, ProfileReplayError> {
    if slots == 0 || !original.iter().any(|field| field.name == COOKIE) {
        return Ok(None);
    }

    if slots == 1 && layout == CookieLayoutEvidence::Unknown {
        let pairs = original
            .iter()
            .filter(|field| field.name == COOKIE)
            .map(|field| field.value.as_bytes().split(|byte| *byte == b';').count())
            .sum::<usize>();
        if pairs > 1 {
            report.push(ProfilePreservationDifference::UnknownCookieLayout);
        }
        // Keep the caller's boundaries until a captured variant establishes
        // splitting. A single field is never evidence for joining.
        return Ok(Some(
            original
                .iter_mut()
                .filter(|field| field.name == COOKIE)
                .map(|field| {
                    field.used = true;
                    field.value.clone()
                })
                .collect(),
        ));
    }

    let mut joined = Vec::new();
    let mut sensitive = false;
    let mut first = true;
    for field in original.iter_mut().filter(|field| field.name == COOKIE) {
        if !first {
            joined.extend_from_slice(b"; ");
        }
        first = false;
        joined.extend_from_slice(field.value.as_bytes());
        sensitive |= field.value.is_sensitive();
        field.used = true;
    }
    let make_value = |bytes: &[u8]| {
        let mut value = HeaderValue::from_bytes(bytes)
            .map_err(|_error| ProfileDataError::Invalid("request cookie value"))?;
        value.set_sensitive(sensitive);
        Ok::<_, ProfileReplayError>(value)
    };
    let values = joined
        .split(|byte| *byte == b';')
        .map(|pair| make_value(pair.trim_ascii()))
        .collect::<Result<VecDeque<_>, _>>()?;
    Ok(Some(values))
}

struct OriginalHeader {
    name: HeaderName,
    value: HeaderValue,
    used: bool,
}

fn occurrence_index(
    original: &[OriginalHeader],
    name: &HeaderName,
    occurrence: u32,
) -> Option<usize> {
    let occurrence = usize::try_from(occurrence).ok()?;
    original
        .iter()
        .enumerate()
        .filter(|(_index, field)| field.name == *name)
        .nth(occurrence)
        .map(|(index, _field)| index)
}

#[cfg(test)]
mod tests;
