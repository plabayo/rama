//! Which fields a trailer section carries (RFC 9110 §6.5).
//!
//! An outgoing trailer section sends a field when its definition allows trailers
//! ([`HeaderName::is_allowed_in_trailers`]), or when the message's [`ForbiddenTrailers`]
//! allows it anyway, as a relay forwarding what it received does. A field that frames or
//! routes a message, or belongs to one connection, is never sent nor kept on receipt: HTTP/2
//! and HTTP/3 treat it as malformed, and over HTTP/1.1 it could smuggle framing past a
//! recipient that merges trailers into headers. HTTP/1.1, HTTP/2 and HTTP/3 share these
//! rules: their RFCs give no reason to differ.

use rama_core::{extensions::Extension, telemetry::tracing};

use crate::{
    HeaderMap,
    header::{self, HeaderName, hop_by_hop::CONNECTION_SPECIFIC_HEADERS},
};

/// Which fields a message's trailer section sends although their definitions do not allow
/// them in trailers.
///
/// Insert it into a message's extensions; without one, [`Self::DenyAll`] applies. A response
/// inherits it from its request, so a relay inserts it once into the request it forwards, and
/// a message can override what it inherits. Fields that [`is_never_a_trailer`] names are never
/// sent, whatever it allows.
#[derive(Debug, Clone, Default, Extension)]
#[extension(tags(http))]
pub enum ForbiddenTrailers {
    /// None of them: only fields whose definitions allow trailers are sent.
    #[default]
    DenyAll,
    /// All of them, as a relay forwarding what it received does.
    AllowAll,
    /// These only.
    AllowSome(Box<[HeaderName]>),
    /// All but these.
    DenySome(Box<[HeaderName]>),
}

impl ForbiddenTrailers {
    fn allows(&self, name: &HeaderName) -> bool {
        match self {
            Self::DenyAll => false,
            Self::AllowAll => true,
            Self::AllowSome(names) => names.contains(name),
            Self::DenySome(names) => !names.contains(name),
        }
    }
}

/// Whether an outgoing trailer section sends `name`, given what its message `allowed`; `None`
/// is [`ForbiddenTrailers::DenyAll`].
#[must_use]
pub fn is_sent_in_trailers(name: &HeaderName, allowed: Option<&ForbiddenTrailers>) -> bool {
    // RFC 8470 §5.1 prohibits sending this field in trailers, but does not
    // require rejecting a peer that sends it. Keep receive validation lenient.
    name != header::EARLY_DATA
        && !is_never_a_trailer(name)
        && (name.is_allowed_in_trailers() || allowed.is_some_and(|allowed| allowed.allows(name)))
}

/// Whether `name` frames or routes a message, or belongs to one connection: no trailer section
/// carries it, sent or received.
#[must_use]
pub fn is_never_a_trailer(name: &HeaderName) -> bool {
    CONNECTION_SPECIFIC_HEADERS.contains(&name)
        || [header::TE, header::CONTENT_LENGTH, header::HOST].contains(name)
}

/// Remove the received fields that [`is_never_a_trailer`] names, keeping the rest of the section.
pub fn drop_never_trailers(trailers: &mut HeaderMap) {
    if !trailers.keys().any(is_never_a_trailer) {
        return;
    }
    let names: Vec<HeaderName> = trailers
        .keys()
        .filter(|name| is_never_a_trailer(name))
        .cloned()
        .collect();
    for name in names {
        tracing::debug!("dropping trailer field that frames or routes the message: {name:?}");
        trailers.remove(&name);
    }
}

/// Merge a `later` trailer section into `trailers`: a name `later` carries replaces its earlier
/// values, and every line keeps its own position and spelling.
pub(crate) fn merge_trailers(trailers: &mut HeaderMap, later: HeaderMap) {
    if let Err(err) = trailers.try_insert_map(later) {
        tracing::debug!(%err, "trailer section past the map's capacity: keeping the lines that fit");
    }
}

/// Trailer sections for the tests of each place that merges them.
#[cfg(test)]
pub(crate) mod merge_fixture {
    use crate::{HeaderMap, HeaderName, HeaderValue};

    /// Two sections to merge: the later one replaces a name in place and repeats another,
    /// split by a third, in mixed casing.
    pub(crate) fn sections() -> (HeaderMap, HeaderMap) {
        let section = |lines: &[(&'static str, &'static str)]| {
            let mut map = HeaderMap::new();
            for &(name, value) in lines {
                map.append(
                    HeaderName::from_static(name),
                    HeaderValue::from_static(value),
                );
            }
            map
        };
        (
            section(&[("X-Kept", "1"), ("x-Replaced", "old"), ("X-Kept", "2")]),
            section(&[("X-Twice", "a"), ("X-REPLACED", "new"), ("x-twice", "b")]),
        )
    }

    /// The lines of [`sections`] merged.
    pub(crate) const MERGED: &str =
        "X-Kept: 1\nX-REPLACED: new\nX-Kept: 2\nX-Twice: a\nx-twice: b\n";

    /// The lines of `trailers` in order, each in its own spelling.
    pub(crate) fn lines(trailers: &HeaderMap) -> String {
        trailers
            .ordered_iter()
            .map(|(name, value)| {
                format!("{}: {}\n", name.display_original(), value.to_str().unwrap())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merging_trailers_keeps_each_line_in_place_and_in_its_spelling() {
        let (mut trailers, later) = merge_fixture::sections();
        merge_trailers(&mut trailers, later);
        assert_eq!(merge_fixture::lines(&trailers), merge_fixture::MERGED);
    }

    #[test]
    fn early_data_is_tolerated_on_receipt_but_never_sent_in_trailers() {
        assert!(!is_never_a_trailer(&header::EARLY_DATA));
        assert!(!header::EARLY_DATA.is_allowed_in_trailers());
        for allowed in [
            None,
            Some(ForbiddenTrailers::AllowAll),
            Some(ForbiddenTrailers::AllowSome([header::EARLY_DATA].into())),
        ] {
            assert!(!is_sent_in_trailers(&header::EARLY_DATA, allowed.as_ref()));
        }
    }

    #[test]
    fn trailers_send_allowed_fields_and_opted_in_ones_but_never_framing() {
        let allow_some = ForbiddenTrailers::AllowSome([header::SET_COOKIE].into());
        let deny_some = ForbiddenTrailers::DenySome([header::SET_COOKIE].into());
        // name, none, DenyAll, AllowAll, AllowSome(set-cookie), DenySome(set-cookie)
        for (name, expected) in [
            ("x-checksum", [true; 5]),
            ("grpc-status", [true; 5]),
            ("etag", [true; 5]),
            ("set-cookie", [false, false, true, true, false]),
            ("cookie", [false, false, true, false, true]),
            ("content-type", [false, false, true, false, true]),
            ("content-length", [false; 5]),
            ("host", [false; 5]),
            ("te", [false; 5]),
            ("transfer-encoding", [false; 5]),
            ("connection", [false; 5]),
            ("keep-alive", [false; 5]),
            ("proxy-connection", [false; 5]),
            ("upgrade", [false; 5]),
        ] {
            let name = HeaderName::from_static(name);
            let sent = [
                None,
                Some(&ForbiddenTrailers::DenyAll),
                Some(&ForbiddenTrailers::AllowAll),
                Some(&allow_some),
                Some(&deny_some),
            ]
            .map(|allowed| is_sent_in_trailers(&name, allowed));
            assert_eq!(sent, expected, "{name}");
        }
    }
}
