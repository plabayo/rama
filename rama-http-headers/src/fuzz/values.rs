//! Value-level parsers that are not a typed header of their own.

use std::net::IpAddr;

use rama_http_types::{HeaderMap, HeaderName, HeaderValue, header};

use crate::{
    AccessControlAllowOrigin, ClientHint, ETag, Origin, Priority, SecWebSocketExtensions,
    encoding::AcceptEncoding,
    fuzz::{
        ValuesExercise,
        parts::{client_hint, encodings, header_value_string, origin, robots_tag, seconds_value},
        probes::etag_preconditions,
        support::{roundtrip, sink},
    },
    util::{HeaderValueString, Seconds, csv},
    x_robots_tag::robots_tag_parse_iter,
};

pub(super) const VALUES: &[ValuesExercise] = &[
    (
        "SecWebSocketExtensions::decode_offers",
        |values: &[HeaderValue]| {
            if let Some(offers) = SecWebSocketExtensions::decode_offers(values) {
                roundtrip(&offers);
            }
        },
    ),
    ("encoding", |values: &[HeaderValue]| {
        let mut map = HeaderMap::new();
        for value in values {
            map.append(header::ACCEPT_ENCODING, value.clone());
            map.append(header::CONTENT_ENCODING, value.clone());
        }
        encodings(&map, true);
        encodings(&map, false);
        encodings(&map, AcceptEncoding::default());
        encodings(&map, AcceptEncoding::new_gzip());
    }),
    ("csv::from_comma_delimited", |values: &[HeaderValue]| {
        sink(csv::from_comma_delimited::<_, IpAddr, Vec<_>>(
            &mut values.iter(),
        ));
        sink(csv::from_comma_delimited::<_, u64, Vec<_>>(
            &mut values.iter(),
        ));
        sink(csv::from_comma_delimited::<_, String, Vec<_>>(
            &mut values.iter(),
        ));
        if let Ok(tags) = csv::from_comma_delimited::<_, ETag, Vec<_>>(&mut values.iter()) {
            for tag in &tags {
                etag_preconditions(tag);
            }
        }
    }),
    ("Seconds::try_from_val", |values: &[HeaderValue]| {
        for value in values {
            if let Some(seconds) = Seconds::try_from_val(value) {
                seconds_value(seconds);
            }
        }
    }),
    ("HeaderValueString::from_val", |values: &[HeaderValue]| {
        for value in values {
            if let Ok(s) = HeaderValueString::from_val(value) {
                header_value_string(&s);
            }
        }
    }),
    (
        "Origin::try_from_header_value",
        |values: &[HeaderValue]| {
            for value in values {
                if let Some(value) = Origin::try_from_header_value(value) {
                    origin(&value);
                    roundtrip(&value);
                }
                if let Some(allow) = AccessControlAllowOrigin::try_from_origin_header_value(value) {
                    roundtrip(&allow);
                }
            }
        },
    ),
    ("Priority::parse", |values: &[HeaderValue]| {
        for value in values {
            if let Ok(priority) = Priority::parse(value.as_bytes()) {
                roundtrip(&priority);
            }
        }
    }),
    ("robots_tag_parse_iter", |values: &[HeaderValue]| {
        for value in values {
            for tag in robots_tag_parse_iter(value.as_bytes()).take(64).flatten() {
                robots_tag(&tag);
            }
        }
    }),
    (
        "ClientHint::match_header_name",
        |values: &[HeaderValue]| {
            for value in values {
                if let Ok(name) = HeaderName::from_bytes(value.as_bytes())
                    && let Some(hint) = ClientHint::match_header_name(&name)
                {
                    client_hint(hint);
                }
            }
        },
    ),
];
