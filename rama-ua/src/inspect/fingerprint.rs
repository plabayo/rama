//! Cache database-derived values independently of attacker-controlled request cardinality.

use std::{collections::BTreeMap, sync::OnceLock};

use rama_http::{
    Version,
    fingerprint::{HttpRequestInput, Ja4H},
    inspect::capture::CaptureMetadata,
};
#[cfg(feature = "tls")]
use rama_tls::{
    fingerprint::{Ja3, Ja4, PeetPrint},
    inspect::TlsObservation,
};

use super::{KnownFingerprint, UserAgentDatabase};
use crate::UserAgentKind;

#[derive(Debug)]
pub(super) struct FingerprintCache(BTreeMap<Box<str>, OnceLock<Option<Expected>>>);

/// Fingerprints of every variant recorded for one User-Agent, computed on first use.
#[derive(Debug)]
struct Expected {
    kind: UserAgentKind,
    version: Option<usize>,
    #[cfg(feature = "tls")]
    tls: Box<[(Option<Ja3>, Option<Ja4>, Option<PeetPrint>)]>,
    // Each recorded flow carries its own method, so request methods never add entries.
    http: Box<[(bool, Ja4H)]>,
}

impl FingerprintCache {
    pub(super) fn new(database: &UserAgentDatabase) -> Self {
        Self(
            database
                .iter_ua_str()
                .map(|ua| (ua.into(), OnceLock::new()))
                .collect(),
        )
    }

    pub(super) fn match_request(
        &self,
        database: &UserAgentDatabase,
        user_agent: Option<&str>,
        parts: &rama_http::request::Parts,
        metadata: &CaptureMetadata,
    ) -> Option<KnownFingerprint> {
        if parts.version == Version::HTTP_3 {
            return None; // QUIC/H3 observations must not match TCP/H1 components.
        }
        let ua = user_agent?;
        let expected = self
            .0
            .get(ua)?
            .get_or_init(|| Expected::compute(database, ua))
            .as_ref()?;
        let known = KnownFingerprint {
            kind: expected.kind,
            version: expected.version,
        };
        #[cfg(feature = "tls")]
        if metadata
            .connection
            .get_ref::<TlsObservation>()
            .is_some_and(|tls| {
                expected.tls.iter().any(|(ja3, ja4, peet)| {
                    tls.ja3
                        .as_ref()
                        .is_some_and(|actual| Some(actual) == ja3.as_ref())
                        || tls
                            .ja4
                            .as_ref()
                            .is_some_and(|actual| Some(actual) == ja4.as_ref())
                        || tls
                            .peetprint
                            .as_ref()
                            .is_some_and(|actual| Some(actual) == peet.as_ref())
                })
            })
        {
            return Some(known);
        }
        let actual = metadata.request_fingerprint(parts)?;
        let h2 = parts.version == Version::HTTP_2;
        expected
            .http
            .iter()
            .any(|(expected_h2, expected)| *expected_h2 == h2 && expected == actual.as_ref())
            .then_some(known)
    }
}

impl Expected {
    fn compute(database: &UserAgentDatabase, ua: &str) -> Option<Self> {
        let mut profiles = database.get_exact_header_str(ua).peekable();
        let first = profiles.peek()?;
        let kind = first.ua_kind?;
        let version = first.ua_version;
        #[cfg(feature = "tls")]
        let mut tls = Vec::new();
        let mut http = Vec::new();
        for profile in profiles {
            #[cfg(feature = "tls")]
            tls.extend(profile.recorded_tcp_client_hellos().iter().map(|hello| {
                (
                    Ja3::compute_from_client_hello(hello).ok(),
                    Ja4::compute_from_client_hello(hello).ok(),
                    PeetPrint::compute_from_client_hello(hello).ok(),
                )
            }));
            for recorded in profile.recorded_request_headers() {
                let h2 = match recorded.version {
                    Version::HTTP_2 => true,
                    Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 => false,
                    Version::HTTP_3 => continue,
                };
                if let Ok(ja4h) = Ja4H::compute(HttpRequestInput {
                    header_map: recorded.headers,
                    http_method: recorded.method,
                    version: recorded.version,
                }) && !http.contains(&(h2, ja4h.clone()))
                {
                    http.push((h2, ja4h));
                }
            }
        }
        Some(Self {
            kind,
            version,
            #[cfg(feature = "tls")]
            tls: tls.into(),
            http: http.into(),
        })
    }
}

#[cfg(all(test, feature = "embed-profiles"))]
mod tests {
    use super::*;
    #[cfg(feature = "tls")]
    use crate::profile::format::input::UserAgentProfileInput;
    use rama_http::Request;
    #[cfg(feature = "tls")]
    use rama_tls::{
        CipherSuite, CompressionAlgorithm, ProtocolVersion, SecureTransport, client::ClientHello,
    };

    #[test]
    fn recorded_request_headers_match_their_own_fingerprint() {
        let database = UserAgentDatabase::try_embedded().unwrap();
        let cache = FingerprintCache::new(&database);
        let profile = database
            .iter()
            .find(|profile| profile.ua_kind == Some(UserAgentKind::Firefox))
            .unwrap();
        let ua = profile.ua_str().unwrap();
        let recorded = profile
            .recorded_request_headers()
            .into_iter()
            .find(|recorded| recorded.version == Version::HTTP_2)
            .unwrap();
        let mut builder = Request::builder()
            .method(recorded.method.clone())
            .version(recorded.version);
        for (name, value) in recorded.headers.iter() {
            builder = builder.header(name, value);
        }
        let (parts, ()) = builder.body(()).unwrap().into_parts();
        let known = cache
            .match_request(&database, Some(ua), &parts, &CaptureMetadata::default())
            .unwrap();
        assert_eq!(known.kind, UserAgentKind::Firefox);
        let (parts, ()) = Request::builder()
            .method("CUSTOM")
            .version(Version::HTTP_2)
            .body(())
            .unwrap()
            .into_parts();
        assert!(
            cache
                .match_request(&database, Some(ua), &parts, &CaptureMetadata::default())
                .is_none()
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn h3_observation_does_not_match_a_tcp_tls_fingerprint() {
        let ua = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0";
        let hello = ClientHello::new(
            ProtocolVersion::TLSv1_2,
            vec![CipherSuite::from(0x1301)],
            vec![CompressionAlgorithm::from(0)],
            Vec::new(),
        );
        let mut row = UserAgentProfileInput::new(ua);
        row.tls_client_hello = Some(hello.clone());
        let database: UserAgentDatabase = [row.try_into_profile().unwrap()].into_iter().collect();
        let cache = FingerprintCache::new(&database);
        let (parts, ()) = Request::builder()
            .version(Version::HTTP_3)
            .header("user-agent", ua)
            .extension(SecureTransport::with_client_hello(hello))
            .body(())
            .unwrap()
            .into_parts();
        let metadata = CaptureMetadata::default();
        TlsObservation::capture(&parts.extensions, &metadata.connection);
        assert!(
            cache
                .match_request(&database, Some(ua), &parts, &metadata)
                .is_none()
        );
    }
}
