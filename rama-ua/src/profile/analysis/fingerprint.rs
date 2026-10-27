//! Fingerprints of recorded variants, cached per User-Agent independently of request volume.

use std::{collections::BTreeMap, sync::OnceLock};

use rama_http::fingerprint::{HttpRequestInput, Ja4H};
#[cfg(feature = "tls")]
use rama_tls::fingerprint::{Ja3, Ja4, PeetPrint};

use crate::{UserAgentKind, profile::selection::database::UserAgentDatabase};

/// Recorded fingerprints per User-Agent of one database, each computed on first use.
#[derive(Debug)]
pub struct RecordedFingerprintCache(BTreeMap<Box<str>, OnceLock<Option<RecordedFingerprints>>>);

/// Fingerprints of every variant recorded for one User-Agent.
#[derive(Debug)]
pub struct RecordedFingerprints {
    pub kind: Option<UserAgentKind>,
    pub version: Option<usize>,
    /// One entry per distinct captured TCP TLS shape.
    #[cfg(feature = "tls")]
    pub tls: Box<[RecordedTlsFingerprint]>,
    /// One entry per distinct captured TLS-over-QUIC shape.
    #[cfg(feature = "tls")]
    pub tls_quic: Box<[RecordedTlsFingerprint]>,
    /// One entry per distinct captured request shape; each carries its own method and version.
    pub http: Box<[Ja4H]>,
}

#[cfg(feature = "tls")]
#[derive(Debug)]
pub struct RecordedTlsFingerprint {
    pub ja3: Option<Ja3>,
    pub ja4: Option<Ja4>,
    pub peetprint: Option<PeetPrint>,
}

impl RecordedFingerprintCache {
    #[must_use]
    pub fn new(database: &UserAgentDatabase) -> Self {
        Self(
            database
                .iter_ua_str()
                .map(|ua| (ua.into(), OnceLock::new()))
                .collect(),
        )
    }

    /// Fingerprints recorded for `ua`; `database` must be the one this cache was built from.
    #[must_use]
    pub fn get(&self, database: &UserAgentDatabase, ua: &str) -> Option<&RecordedFingerprints> {
        self.0
            .get(ua)?
            .get_or_init(|| RecordedFingerprints::compute(database, ua))
            .as_ref()
    }
}

impl RecordedFingerprints {
    /// The first recorded request shape matching `actual`, ignoring site- and user-specific parts.
    #[must_use]
    pub fn matching_http(&self, actual: &Ja4H) -> Option<&Ja4H> {
        self.http
            .iter()
            .find(|expected| expected.matches_client_shape(actual))
    }

    fn compute(database: &UserAgentDatabase, ua: &str) -> Option<Self> {
        let mut profiles = database.get_exact_header_str(ua).peekable();
        let first = profiles.peek()?;
        let kind = first.ua_kind;
        let version = first.ua_version;
        #[cfg(feature = "tls")]
        let (mut tls, mut tls_quic) = (Vec::new(), Vec::new());
        let mut http: Vec<Ja4H> = Vec::new();
        for profile in profiles {
            #[cfg(feature = "tls")]
            {
                tls.extend(profile.recorded_tcp_client_hellos().iter().map(fingerprint));
                tls_quic.extend(
                    profile
                        .recorded_quic_client_hellos()
                        .iter()
                        .map(fingerprint),
                );
            }
            for recorded in profile.recorded_request_headers() {
                if let Ok(ja4h) = Ja4H::compute(HttpRequestInput {
                    header_map: recorded.headers,
                    http_method: recorded.method,
                    version: recorded.version,
                }) && !http.iter().any(|known| known.matches_client_shape(&ja4h))
                {
                    http.push(ja4h);
                }
            }
        }
        Some(Self {
            kind,
            version,
            #[cfg(feature = "tls")]
            tls: tls.into(),
            #[cfg(feature = "tls")]
            tls_quic: tls_quic.into(),
            http: http.into(),
        })
    }
}

#[cfg(feature = "tls")]
fn fingerprint(hello: &rama_tls::client::ClientHello) -> RecordedTlsFingerprint {
    RecordedTlsFingerprint {
        ja3: Ja3::compute_from_client_hello(hello).ok(),
        ja4: Ja4::compute_from_client_hello(hello).ok(),
        peetprint: PeetPrint::compute_from_client_hello(hello).ok(),
    }
}
