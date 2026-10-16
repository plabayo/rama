use std::time::{Duration, SystemTime};

use rama_http::{Version, inspect::capture::HttpExchangeSummary};
use sha2::{Digest as _, Sha256};

use super::super::protocol::{H3ProfileConnection, H3ProfileRequest};
use super::*;
#[cfg(feature = "tls")]
use crate::profile::capture::tls::{TlsCapture, TlsCaptureLimits, TlsCaptureTransport};
use crate::profile::{
    analysis::profile::ProfileAnalysisLimits,
    capture::{
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
                    Some(
                        metadata
                            .connection
                            .get_ref::<H3ProfileConnection>()
                            .ok_or(ProfileDataError::Incomplete("retained H3 connection"))?
                            .0
                            .as_ref()
                            .map_err(Clone::clone)?,
                    )
                } else {
                    None
                };
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
                if version == Version::HTTP_3 {
                    slots = metadata
                        .exchange
                        .get_ref::<H3ProfileRequest>()
                        .ok_or(ProfileDataError::Incomplete("retained H3 request"))?
                        .0
                        .as_ref()
                        .map_err(Clone::clone)?
                        .to_vec();
                }
                let request = ProfileCapture {
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
                let mut slots = h3.map(|facts| facts.slots.to_vec()).unwrap_or_default();
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
                if let Some(hello) = metadata
                    .connection
                    .get_ref::<TlsObservation>()
                    .and_then(|tls| tls.client_hello.as_ref())
                {
                    let quic = version == Version::HTTP_3;
                    let bounds = TlsCaptureLimits {
                        bytes: policy.bytes,
                        ..TlsCaptureLimits::default()
                    };
                    let tls = TlsCapture::capture(
                        ProfileCaptureCompleteness::from_complete(
                            h3.is_none_or(|facts| facts.client_hello_complete),
                        ),
                        if quic {
                            TlsCaptureTransport::Quic
                        } else {
                            TlsCaptureTransport::Tcp
                        },
                        hello,
                        bounds,
                    )?;
                    slots.push(CapturedSlot {
                        kind: if quic {
                            CapturedSlotKind::QuicTls
                        } else {
                            CapturedSlotKind::TcpTls
                        },
                        value: tls.canonical(bounds)?,
                    });
                }
                if !slots.is_empty() {
                    slots.sort_unstable_by_key(|slot| slot.kind);
                    collected.observe(
                        observed_day,
                        &ProfileCapture {
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
