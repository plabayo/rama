//! Cache database-derived values independently of attacker-controlled request cardinality.

use std::collections::BTreeMap;
#[cfg(feature = "tls")]
use std::sync::OnceLock;

use parking_lot::Mutex;
use rama_http::{Method, Version, fingerprint::Ja4H, inspect::capture::CaptureMetadata};
#[cfg(feature = "tls")]
use rama_tls::{
    fingerprint::{Ja3, Ja4, PeetPrint},
    inspect::TlsObservation,
};

use super::{KnownFingerprint, UserAgentDatabase};
use crate::profile::UserAgentProfile;

#[derive(Debug)]
pub(super) struct FingerprintCache(BTreeMap<String, Expected>);
#[derive(Debug, Default)]
struct Expected {
    #[cfg(feature = "tls")]
    tls: OnceLock<Box<(Option<Ja3>, Option<Ja4>, Option<PeetPrint>)>>,
    // Nine standard methods, HTTP/1 and HTTP/2. Unknown methods are never retained.
    http: Mutex<BTreeMap<(bool, usize), [Option<Ja4H>; 4]>>,
}

impl FingerprintCache {
    pub(super) fn new(database: &UserAgentDatabase) -> Self {
        Self(
            database
                .iter_ua_str()
                .map(|ua| (ua.to_owned(), Expected::default()))
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
        let ua = user_agent?;
        let expected = self.0.get(ua)?;
        let profile = database.get_exact_header_str(ua)?;
        #[cfg(feature = "tls")]
        if metadata
            .connection
            .get_ref::<TlsObservation>()
            .is_some_and(|tls| {
                let (ja3, ja4, peet) = expected
                    .tls
                    .get_or_init(|| {
                        Box::new((
                            profile.tls.compute_ja3(None).ok(),
                            profile.tls.compute_ja4(None).ok(),
                            profile.tls.compute_peet().ok(),
                        ))
                    })
                    .as_ref();
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
        {
            return Some(KnownFingerprint {
                kind: profile.ua_kind,
                version: profile.ua_version,
            });
        }
        let actual = metadata.request_fingerprint(parts)?;
        let h2 = parts.version == Version::HTTP_2;
        let method_index = [
            Method::GET,
            Method::HEAD,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::CONNECT,
            Method::OPTIONS,
            Method::TRACE,
            Method::PATCH,
        ]
        .iter()
        .position(|method| method == parts.method);
        let matches = |fingerprints: &[Option<Ja4H>; 4]| {
            fingerprints
                .iter()
                .flatten()
                .any(|expected| expected == actual.as_ref())
        };
        let matched = if let Some(index) = method_index {
            matches(
                expected
                    .http
                    .lock()
                    .entry((h2, index))
                    .or_insert_with(|| http(profile, parts.method.clone(), h2)),
            )
        } else {
            // Custom methods are intentionally uncached; computing them needs no
            // access to the shared cache and must not serialize unrelated requests.
            matches(&http(profile, parts.method.clone(), h2))
        };
        matched.then_some(KnownFingerprint {
            kind: profile.ua_kind,
            version: profile.ua_version,
        })
    }
}

fn http(profile: &UserAgentProfile, method: Method, h2: bool) -> [Option<Ja4H>; 4] {
    let method = Some(method);
    let values = if h2 {
        [
            Some(profile.http.ja4h_h2_navigate(method.clone())),
            profile.http.ja4h_h2_fetch(method.clone()),
            profile.http.ja4h_h2_xhr(method.clone()),
            profile.http.ja4h_h2_form(method),
        ]
    } else {
        [
            Some(profile.http.ja4h_h1_navigate(method.clone())),
            profile.http.ja4h_h1_fetch(method.clone()),
            profile.http.ja4h_h1_xhr(method.clone()),
            profile.http.ja4h_h1_form(method),
        ]
    };
    values.map(|value| value.and_then(Result::ok))
}

#[cfg(all(test, feature = "embed-profiles"))]
mod tests {
    use super::*;
    #[test]
    fn custom_methods_do_not_wait_for_the_shared_cache_lock() {
        let database = UserAgentDatabase::try_embedded().unwrap();
        let cache = FingerprintCache::new(&database);
        let ua = database.iter_ua_str().next().unwrap();
        let (parts, ()) = rama_http::Request::builder()
            .method("Custom-Method")
            .header("user-agent", ua)
            .body(())
            .unwrap()
            .into_parts();
        let guard = cache.0[ua].http.lock();
        let (send, receive) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                cache.match_request(&database, Some(ua), &parts, &CaptureMetadata::default());
                send.send(()).unwrap();
            });
            let result = receive.recv_timeout(std::time::Duration::from_secs(2));
            // Release before joining even on failure, so a regression cannot hang.
            drop(guard);
            worker.join().unwrap();
            result.unwrap();
        });
        assert!(cache.0[ua].http.lock().is_empty());
    }

    #[test]
    fn repeated_and_custom_methods_keep_the_expected_cache_bounded() {
        let database = UserAgentDatabase::try_embedded().unwrap();
        let cache = FingerprintCache::new(&database);
        let ua = database.iter_ua_str().next().unwrap();
        for index in 0..128 {
            let (parts, ()) = rama_http::Request::builder()
                .header("user-agent", ua)
                .body(())
                .unwrap()
                .into_parts();
            cache.match_request(&database, Some(ua), &parts, &CaptureMetadata::default());
            let method: Method = format!("CUSTOM{index}").parse().unwrap();
            let (parts, ()) = rama_http::Request::builder()
                .method(method)
                .header("user-agent", ua)
                .body(())
                .unwrap()
                .into_parts();
            cache.match_request(&database, Some(ua), &parts, &CaptureMetadata::default());
        }
        assert_eq!(cache.0[ua].http.lock().len(), 1);
    }
}
