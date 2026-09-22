//! Learn connection-local frame hints through an opt-in typed observer.

use super::AltSvcCache;
use crate::layer::http_service::authenticates;
use rama_core::extensions::Extensions;
use rama_http_types::{
    conn::HttpOrigin,
    proto::h2::alt_svc::{
        AltSvcEvent, AltSvcObserver, AltSvcObserverExtension, AltSvcOrigin, AltSvcReceivedAt,
    },
};
use rama_net::{
    Protocol,
    address::{HostWithPort, OptPort},
    uri::AbsoluteUriRef,
};

use std::sync::Arc;

impl AltSvcCache {
    pub(crate) fn frame_observer(&self, origin: HttpOrigin) -> Arc<AltSvcObserverExtension> {
        if let Some(observer) = self
            .observers
            .get(&origin)
            .and_then(|observer| observer.upgrade())
        {
            return observer;
        }
        let observer = Arc::new(AltSvcObserverExtension::new(FrameObserver {
            cache: self.clone(),
            origin: origin.clone(),
        }));
        // Weak storage avoids a cycle through the observer's cache handle.
        // Racing first connections may each create an observer; both are valid.
        self.observers.insert(origin, Arc::downgrade(&observer));
        observer
    }
}

struct FrameObserver {
    cache: AltSvcCache,
    origin: HttpOrigin,
}

impl AltSvcObserver for FrameObserver {
    fn observe(&self, event: AltSvcEvent, connection: &Extensions) {
        self.record(event, authenticates(connection, &self.origin));
    }
}

impl FrameObserver {
    fn record(&self, event: AltSvcEvent, authenticated: bool) {
        let origin = match event.origin {
            // Stream zero cannot derive authority from a request. Only the
            // authenticated logical origin of this connection is accepted;
            // a received certificate does not authorize arbitrary coalescing.
            AltSvcOrigin::Explicit(bytes) if authenticated => parse_origin(&bytes),
            AltSvcOrigin::Request(origin) if authenticated || !origin.is_secure() => Some(origin),
            _ => None,
        };
        if origin.as_ref() == Some(&self.origin) {
            self.cache.record_frame_received(
                &self.origin,
                event.field_value,
                AltSvcReceivedAt {
                    instant: event.received_at.into_std(),
                    sequence: event.sequence,
                    ..AltSvcReceivedAt::now()
                },
            );
        }
    }
}

fn parse_origin(bytes: &[u8]) -> Option<HttpOrigin> {
    if !bytes.is_ascii() {
        return None;
    }
    let uri = AbsoluteUriRef::parse_strict(bytes).ok()?;
    if !uri.path_str().is_empty() || uri.query().is_some() || uri.fragment().is_some() {
        return None;
    }
    let protocol = Protocol::try_from(uri.scheme()).ok()?;
    let authority = uri.authority_ref()?;
    if authority.userinfo().is_some() {
        return None;
    }
    let port = match authority.port() {
        OptPort::Unset => protocol.default_port()?,
        OptPort::Set(port) => port,
        OptPort::Empty => return None,
    };
    HttpOrigin::new(
        protocol,
        HostWithPort::new(authority.host().into_owned(), port),
    )
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::bytes::Bytes;
    #[cfg(feature = "tls")]
    use rama_tls::client::TlsServerAuthentication;
    use tokio::time::Instant;

    fn origin() -> HttpOrigin {
        HttpOrigin::new(Protocol::HTTPS, "example.com:443".parse().unwrap()).unwrap()
    }

    fn event(origin: AltSvcOrigin, field: &'static [u8]) -> AltSvcEvent {
        AltSvcEvent {
            origin,
            field_value: Bytes::from_static(field),
            received_at: Instant::now(),
            sequence: AltSvcReceivedAt::now().sequence,
        }
    }

    #[test]
    fn explicit_origins_require_strict_ascii_origin_syntax() {
        for value in [
            b"https://example.com".as_slice(),
            b"https://EXAMPLE.COM:443",
        ] {
            assert_eq!(parse_origin(value), Some(origin()));
        }
        for value in [
            b"null".as_slice(),
            b"https://example.com/",
            b"https://example.com/path",
            b"https://example.com?",
            b"https://example.com#",
            b"https://user@example.com",
            b"https://example.com:",
            b"https://example.com:0",
            b"ftp://example.com",
            b"https://example.com https://other.example",
            b"https://\xff.example",
        ] {
            assert!(parse_origin(value).is_none(), "accepted {value:?}");
        }
    }

    #[test]
    fn frame_origin_authorization_is_scoped_to_the_established_connection() {
        for authenticated in [false, true] {
            let cache = AltSvcCache::default();
            let consumer = FrameObserver {
                cache: cache.clone(),
                origin: origin(),
            };
            for source in [
                AltSvcOrigin::Request(origin()),
                AltSvcOrigin::Explicit(Bytes::from_static(b"https://example.com")),
            ] {
                consumer.record(event(source, b"h3=\":443\""), authenticated);
                assert_eq!(cache.lookup(&origin()).is_some(), authenticated);
                cache.clear(&origin());
            }
            let other =
                HttpOrigin::new(Protocol::HTTPS, "other.example:443".parse().unwrap()).unwrap();
            for source in [
                AltSvcOrigin::Request(other.clone()),
                AltSvcOrigin::Explicit(Bytes::from_static(b"https://other.example")),
            ] {
                consumer.record(event(source, b"h3=\":443\""), authenticated);
                assert!(cache.lookup(&origin()).is_none());
                assert!(cache.lookup(&other).is_none());
            }
        }
    }

    #[test]
    fn plaintext_request_frames_remain_hints_but_stream_zero_requires_authority() {
        let origin = HttpOrigin::new(Protocol::HTTP, "example.com:80".parse().unwrap()).unwrap();
        let cache = AltSvcCache::default();
        let consumer = FrameObserver {
            cache: cache.clone(),
            origin: origin.clone(),
        };
        consumer.record(
            event(
                AltSvcOrigin::Explicit(Bytes::from_static(b"http://example.com")),
                b"h3=\":443\"",
            ),
            false,
        );
        assert!(cache.lookup(&origin).is_none());
        consumer.record(
            event(AltSvcOrigin::Request(origin.clone()), b"h3=\":443\""),
            false,
        );
        assert!(cache.lookup(&origin).is_some());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn observer_checks_live_connection_authentication_before_immediate_learning() {
        let cache = AltSvcCache::default();
        let observer = cache.frame_observer(origin());
        let connection = Extensions::new();
        for identity in [None, Some("other.example"), Some("example.com")] {
            connection.insert(TlsServerAuthentication(
                identity.map(|host| host.parse().unwrap()),
            ));
            observer.observe(
                event(
                    AltSvcOrigin::Explicit(Bytes::from_static(b"https://example.com")),
                    b"h3=\":443\"",
                ),
                &connection,
            );
            assert_eq!(
                cache.lookup(&origin()).is_some(),
                identity == Some("example.com")
            );
        }
        observer.observe(
            event(AltSvcOrigin::Request(origin()), b"clear"),
            &connection,
        );
        assert!(cache.lookup(&origin()).is_none());
    }
    #[test]
    fn observers_share_per_origin_without_retaining_themselves() {
        let cache = AltSvcCache::default();
        let first = cache.frame_observer(origin());
        let second = cache.frame_observer(origin());
        assert!(Arc::ptr_eq(&first, &second));
        let weak = Arc::downgrade(&first);
        drop(first);
        drop(second);
        assert!(weak.upgrade().is_none());
    }
}
