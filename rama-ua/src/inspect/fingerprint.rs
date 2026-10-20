//! Cache database-derived values independently of attacker-controlled request cardinality.

use rama_http::{Version, inspect::capture::CaptureMetadata, request::Parts};
#[cfg(feature = "tls")]
use rama_tls::inspect::TlsObservation;

use super::{KnownFingerprint, UserAgentDatabase};
use crate::profile::analysis::fingerprint::RecordedFingerprintCache;

#[derive(Debug)]
pub(super) struct FingerprintCache(RecordedFingerprintCache);

impl FingerprintCache {
    pub(super) fn new(database: &UserAgentDatabase) -> Self {
        Self(RecordedFingerprintCache::new(database))
    }

    pub(super) fn match_request(
        &self,
        database: &UserAgentDatabase,
        user_agent: Option<&str>,
        parts: &Parts,
        metadata: &CaptureMetadata,
    ) -> Option<KnownFingerprint> {
        if parts.version == Version::HTTP_3 {
            return None; // QUIC/H3 observations must not match TCP/H1 components.
        }
        let expected = self.0.get(database, user_agent?)?;
        let known = KnownFingerprint {
            kind: expected.kind?,
            version: expected.version,
        };
        #[cfg(feature = "tls")]
        if metadata
            .connection
            .get_ref::<TlsObservation>()
            .is_some_and(|tls| {
                expected.tls.iter().any(|recorded| {
                    tls.ja3
                        .as_ref()
                        .is_some_and(|actual| Some(actual) == recorded.ja3.as_ref())
                        || tls
                            .ja4
                            .as_ref()
                            .is_some_and(|actual| Some(actual) == recorded.ja4.as_ref())
                        || tls
                            .peetprint
                            .as_ref()
                            .is_some_and(|actual| Some(actual) == recorded.peetprint.as_ref())
                })
            })
        {
            return Some(known);
        }
        let actual = metadata.request_fingerprint(parts)?;
        expected.matching_http(&actual).map(|_| known)
    }
}

#[cfg(all(test, feature = "embed-profiles"))]
mod tests {
    // Fixture helpers fail immediately when embedded data lacks a shape.
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;
    #[cfg(feature = "tls")]
    use crate::profile::format::input::UserAgentProfileInput;
    use crate::{
        UserAgentKind,
        profile::{
            analysis::recorded::RecordedRequestHeaders, model::runtime_hints::RequestInitiator,
        },
    };
    use rama_http::Request;
    #[cfg(feature = "tls")]
    use rama_tls::{
        CipherSuite, CompressionAlgorithm, ProtocolVersion, SecureTransport, client::ClientHello,
    };

    fn recorded_shape(
        database: &UserAgentDatabase,
        kind: UserAgentKind,
        version: Version,
        initiator: RequestInitiator,
        names: &[&str],
    ) -> (Box<str>, RecordedRequestHeaders) {
        database
            .iter()
            .filter(|profile| profile.ua_kind == Some(kind))
            .find_map(|profile| {
                let recorded = profile
                    .recorded_request_headers()
                    .into_iter()
                    .find(|recorded| {
                        recorded.version == version
                            && recorded.initiator == Some(initiator)
                            && names
                                .iter()
                                .all(|name| recorded.headers.contains_key(*name))
                    })?;
                Some((profile.ua_str()?.into(), recorded))
            })
            .unwrap_or_else(|| {
                panic!("no recorded {kind} {version:?} {initiator:?} with {names:?}")
            })
    }

    /// A live request in the recorded shape with this site's request-owned values.
    fn live_request(recorded: &RecordedRequestHeaders, extra: &[(&str, &str)]) -> Parts {
        let mut builder = Request::builder()
            .method(recorded.method.clone())
            .version(recorded.version);
        for (name, value) in recorded.headers.ordered_iter() {
            let value = match name.as_str().to_ascii_lowercase().as_str() {
                "host" => "shop.example",
                "connection" => "keep-alive",
                "cookie" => "session=4f2a; theme=dark",
                "origin" => "https://shop.example",
                "referer" => "https://shop.example/cart",
                "content-type" => "application/json",
                "content-length" => "2",
                "accept-language" => "nl-BE,nl;q=0.9",
                _ if value.is_empty() => "x",
                _ => value.to_str().unwrap(),
            };
            builder = builder.header(name, value);
        }
        for (name, value) in extra {
            builder = builder.header(*name, *value);
        }
        builder.body(()).unwrap().into_parts().0
    }

    fn matched(database: &UserAgentDatabase, ua: &str, parts: &Parts) -> Option<UserAgentKind> {
        FingerprintCache::new(database)
            .match_request(database, Some(ua), parts, &CaptureMetadata::default())
            .map(|known| known.kind)
    }

    #[test]
    fn http1_navigation_with_site_values_matches_its_recorded_shape() {
        let database = UserAgentDatabase::try_embedded().unwrap();
        let (ua, recorded) = recorded_shape(
            &database,
            UserAgentKind::Firefox,
            Version::HTTP_11,
            RequestInitiator::Navigate,
            &["host", "connection"],
        );
        let parts = live_request(&recorded, &[]);
        assert_eq!(
            matched(&database, &ua, &parts),
            Some(UserAgentKind::Firefox)
        );
        // A site with cookies only flips the JA4H cookie flag.
        let with_cookie = if recorded.headers.contains_key("cookie") {
            parts
        } else {
            live_request(&recorded, &[("Cookie", "session=4f2a")])
        };
        assert_eq!(
            matched(&database, &ua, &with_cookie),
            Some(UserAgentKind::Firefox)
        );
    }

    #[test]
    fn h2_fetch_with_origin_and_content_type_matches_its_recorded_shape() {
        let database = UserAgentDatabase::try_embedded().unwrap();
        let (ua, recorded) = recorded_shape(
            &database,
            UserAgentKind::Chromium,
            Version::HTTP_2,
            RequestInitiator::Fetch,
            &["origin", "content-type"],
        );
        let parts = live_request(&recorded, &[]);
        assert_eq!(
            matched(&database, &ua, &parts),
            Some(UserAgentKind::Chromium)
        );
    }

    #[test]
    fn another_browsers_shape_does_not_match() {
        let database = UserAgentDatabase::try_embedded().unwrap();
        let (firefox, _) = recorded_shape(
            &database,
            UserAgentKind::Firefox,
            Version::HTTP_2,
            RequestInitiator::Navigate,
            &[],
        );
        let (_, chromium) = recorded_shape(
            &database,
            UserAgentKind::Chromium,
            Version::HTTP_2,
            RequestInitiator::Navigate,
            &[],
        );
        let parts = live_request(&chromium, &[]);
        assert_eq!(matched(&database, &firefox, &parts), None);
        let (parts, ()) = Request::builder()
            .method("CUSTOM")
            .version(Version::HTTP_2)
            .body(())
            .unwrap()
            .into_parts();
        assert_eq!(matched(&database, &firefox, &parts), None);
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
