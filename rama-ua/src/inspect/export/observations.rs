use std::time::{Duration, SystemTime};

use rama_http::{Version, inspect::capture::HttpExchangeSummary};
use sha2::{Digest as _, Sha256};

use rama_core::telemetry::tracing;
#[cfg(feature = "tls")]
use rama_tls::server::{EchServerObservation, ServerClientHellos, ServerEchAccepted};

use super::super::protocol::{
    ConnectionFacts, H3ProfileConnection, H3ProfileRequest, connection_slots,
};
#[cfg(feature = "tls")]
use super::super::tls::tls_connection_slots;
use super::*;
#[cfg(feature = "tls")]
use crate::profile::capture::tls::{TlsCaptureLimits, TlsCaptureTransport};
use crate::profile::{
    analysis::profile::ProfileAnalysisLimits,
    capture::{
        CAPTURE_REVISION,
        completeness::ProfileCaptureCompleteness,
        headers::HeaderCapturePolicy,
        http2::{H2Capture, H2CaptureLimits},
        joint::{CaptureLevel, CapturedSlot, CapturedSlotKind, JointCapture},
        observation::ProfileCapture,
        pseudo_headers::PseudoHeaderCapture,
    },
    evidence::{collector::ProfileEvidenceCollector, transaction::CaptureRunId},
    format::{archive::ProfileArchiveEntry, canonical::ProfileDataError},
    model::{
        identity::{ConnectionContext, ConnectionIpFamily, FetchContext, FlowKey, ProfileKey},
        time::profile_utc_day,
    },
};

fn day(summary: &HttpExchangeSummary) -> Result<u32, BoxError> {
    let seconds = u64::try_from(summary.started_at.as_second())?;
    let time = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .ok_or(ProfileDataError::Invalid("capture timestamp"))?;
    Ok(profile_utc_day(time)?)
}

/// The connection facts and request slots of one HTTP/3 exchange.
fn h3_evidence(
    connection: Option<&H3ProfileConnection>,
    metadata: &CaptureMetadata,
) -> Result<(Arc<ConnectionFacts>, Vec<CapturedSlot>), ProfileDataError> {
    let facts = connection
        .ok_or(ProfileDataError::Incomplete("retained H3 connection"))?
        .facts()?;
    let request = metadata
        .exchange
        .get_ref::<H3ProfileRequest>()
        .ok_or(ProfileDataError::Incomplete("retained H3 request"))?
        .0
        .as_ref()
        .map_err(Clone::clone)?
        .to_vec();
    Ok((facts, request))
}

impl ProfileExport {
    /// Export every selected observation through the same bounded counting and
    /// analysis model as fp. Connection facts belong to the first selected
    /// exchange on that connection; request facts count independently. Expired
    /// heads do not contribute. Cancellation leaves the pinned group unchanged.
    pub async fn next_evidence(
        &mut self,
        current_day: u32,
        horizon: u32,
        sampler_seed: [u8; 32],
        limits: ProfileAnalysisLimits,
    ) -> Result<Option<ProfileArchiveEntry>, BoxError> {
        let first_day = limits.window.retention.first_day(current_day, horizon)?;
        loop {
            let Some(header) = self.captures.front().and_then(user_agent) else {
                return Ok(None);
            };
            let parsed = UserAgent::new(header.to_owned());
            let profile = ProfileKey::from_user_agent(&parsed);
            let identity = profile.canonical(limits.metadata_bytes)?;
            let count = self
                .captures
                .iter()
                .take_while(|capture| user_agent(capture) == Some(header))
                .count();
            let mut digest = Sha256::new();
            digest.update(b"rama.profile.selected-captures.v1");
            digest.update(identity.id.0);
            digest.update(sampler_seed);
            for capture in self.captures.iter().take(count) {
                digest.update(capture.id().to_be_bytes());
            }
            let mut nonce = [0; 12];
            nonce.copy_from_slice(&digest.finalize()[..12]);
            let mut collected = ProfileEvidenceCollector::new(
                &profile,
                false,
                CaptureRunId::new(first_day, nonce),
                sampler_seed,
                current_day,
                limits,
            )?;
            let mut skipped_http3 = 0;
            #[cfg(feature = "tls")]
            let mut skipped_tls = 0;
            for capture in self.captures.iter().take(count) {
                let details = capture.summary_details();
                let observed_day = day(&details.summary)?;
                if observed_day < first_day {
                    continue;
                }
                if observed_day > current_day {
                    return Err(ProfileDataError::Invalid("future capture timestamp").into());
                }
                let metadata = capture.metadata();
                let observed = metadata.exchange.get_ref::<UserAgentObservation>().ok_or(
                    ProfileDataError::Incomplete("selected user-agent observation"),
                )?;
                let Some(StoredRecord::RequestHead {
                    method,
                    version,
                    headers,
                    ..
                }) = capture.request_head().await?
                else {
                    return Err(ProfileDataError::Incomplete("selected request head").into());
                };
                let h3 = if version == Version::HTTP_3 {
                    let connection = metadata.connection.get_ref::<H3ProfileConnection>();
                    match h3_evidence(connection, metadata) {
                        Ok(evidence) => Some(evidence),
                        // As for TLS below: evidence that cannot complete, such as a connection
                        // served without QUIC observation, skips this exchange only.
                        Err(ProfileDataError::Incomplete(reason))
                            if !connection
                                .is_some_and(H3ProfileConnection::awaits_first_request) =>
                        {
                            skipped_http3 += 1;
                            tracing::debug!(
                                connection_id = details.summary.connection_id,
                                reason,
                                "profile export skipped exchange with incomplete HTTP/3 evidence"
                            );
                            continue;
                        }
                        Err(err) => return Err(err.into()),
                    }
                } else {
                    None
                };
                let (h3, h3_request) = h3.unzip();
                let h3 = h3.as_deref();
                let connection = ConnectionContext {
                    token_present: h3.map(|facts| facts.token_present),
                    ip_family: details
                        .connection
                        .as_ref()
                        .and_then(|connection| connection.peer_address.as_ref())
                        .map(|address| {
                            if address.ip_addr.is_ipv4() {
                                ConnectionIpFamily::V4
                            } else {
                                ConnectionIpFamily::V6
                            }
                        }),
                    ..ConnectionContext::default()
                };
                let policy = HeaderCapturePolicy {
                    bytes: limits.metadata_bytes,
                    ..HeaderCapturePolicy::default()
                };
                let mut slots = vec![CapturedSlot {
                    kind: CapturedSlotKind::Headers,
                    value: policy
                        .capture(
                            ProfileCaptureCompleteness::Complete,
                            version,
                            &headers,
                            None,
                        )?
                        .canonical(&policy)?,
                }];
                if version == Version::HTTP_2
                    && let Some(order) = observed
                        .h2_settings
                        .as_ref()
                        .and_then(|settings| settings.http_pseudo_headers.as_ref())
                {
                    let pseudo = PseudoHeaderCapture::capture(
                        ProfileCaptureCompleteness::Complete,
                        version,
                        order,
                        None,
                        policy.bytes,
                    )?;
                    pseudo.validate_method(&method)?;
                    slots.push(CapturedSlot {
                        kind: CapturedSlotKind::PseudoHeaders,
                        value: pseudo.canonical(policy.bytes)?,
                    });
                }
                if let Some(request) = h3_request {
                    slots = request;
                }
                let request = ProfileCapture {
                    revision: CAPTURE_REVISION,
                    profile: profile.clone(),
                    flow: Some(FlowKey::Http {
                        version,
                        method,
                        initiator: observed.request_initiator,
                        fetch: FetchContext::from_headers(&headers, policy.bytes)?,
                        connection: connection.clone(),
                    }),
                    connection: connection.clone(),
                    joint: JointCapture {
                        completeness: ProfileCaptureCompleteness::Complete,
                        level: CaptureLevel::Request,
                        slots: slots.into(),
                    },
                };
                collected.observe(observed_day, &request)?;
                if self.connection_owners.get(&details.summary.connection_id) != Some(&capture.id())
                {
                    continue;
                }
                let mut slots = match h3 {
                    Some(facts) => connection_slots(facts, metadata)?,
                    None => Vec::new(),
                };
                if version == Version::HTTP_2
                    && let Some(early) = observed
                        .h2_settings
                        .as_ref()
                        .and_then(|settings| settings.early_frames.as_ref())
                {
                    let bounds = H2CaptureLimits {
                        bytes: policy.bytes,
                        ..H2CaptureLimits::default()
                    };
                    slots.push(CapturedSlot {
                        kind: CapturedSlotKind::Http2EarlyFrames,
                        value: H2Capture::capture(early, bounds)?.canonical(bounds)?,
                    });
                }
                #[cfg(feature = "tls")]
                {
                    let connection = &metadata.connection;
                    let hellos = ServerClientHellos::new(
                        connection
                            .get_ref::<TlsObservation>()
                            .and_then(|tls| tls.client_hello.as_ref()),
                        connection.get_ref::<ServerEchAccepted>().copied(),
                        connection.get_ref::<EchServerObservation>(),
                    );
                    let bounds = TlsCaptureLimits {
                        bytes: policy.bytes,
                        ..TlsCaptureLimits::default()
                    };
                    match tls_connection_slots(
                        &hellos,
                        if version == Version::HTTP_3 {
                            TlsCaptureTransport::Quic
                        } else {
                            TlsCaptureTransport::Tcp
                        },
                        h3.is_none_or(|facts| facts.client_hello_complete),
                        bounds,
                    ) {
                        Ok(tls) => slots.extend(tls),
                        // The outer capture layer is optional. Keep request
                        // evidence already collected above, but do not export
                        // an unmatched or partial hello as a replayable connection.
                        Err(ProfileDataError::Incomplete(reason)) => {
                            skipped_tls += 1;
                            tracing::debug!(
                                connection_id = details.summary.connection_id,
                                reason,
                                "profile export skipped connection with incomplete TLS evidence"
                            );
                            continue;
                        }
                        Err(err) => return Err(err.into()),
                    }
                }
                if !slots.is_empty() {
                    slots.sort_unstable_by_key(|slot| slot.kind);
                    collected.observe(
                        observed_day,
                        &ProfileCapture {
                            revision: CAPTURE_REVISION,
                            profile: profile.clone(),
                            flow: None,
                            connection,
                            joint: JointCapture {
                                completeness: ProfileCaptureCompleteness::Complete,
                                level: CaptureLevel::Connection,
                                slots: slots.into(),
                            },
                        },
                    )?;
                }
            }
            let evidence = collected.finish();
            self.captures.drain(..count);
            self.skipped_http3_exchanges += skipped_http3;
            #[cfg(feature = "tls")]
            {
                self.skipped_tls_connections += skipped_tls;
            }
            if evidence.scopes.is_empty() {
                continue;
            }
            return Ok(Some(ProfileArchiveEntry {
                evidence,
                sampler_seed,
            }));
        }
    }
}
