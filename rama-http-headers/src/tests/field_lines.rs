//! A singleton field refuses a second line, even an equal one; a list field reads every line
//! as their comma-joined value (RFC 9110 §5.3).

use rama_http_types::HeaderValue;
use rama_net::user::{Basic, Bearer};

use crate::forwarded::{
    CFConnectingIp, ClientIp, TrueClientIp, Via, XClientIp, XForwardedFor, XForwardedHost,
    XForwardedProto, XRealIp,
};
use crate::{
    AccessControlAllowHeaders, Allow, AltUsed, Authorization, CapsuleProtocol, Connection, Date,
    HeaderDecode, HeaderEncode, Host, Origin, ProxyAuthorization, SecFetchSite, SecWebSocketAccept,
    SecWebSocketExtensions, SecWebSocketKey, SecWebSocketProtocol, SecWebSocketVersion, Upgrade,
    Vary,
};

fn values(lines: &[&str]) -> Vec<HeaderValue> {
    lines
        .iter()
        .map(|line| HeaderValue::from_str(line).unwrap())
        .collect()
}

/// The values a decode of `lines` encodes back to, if it decodes.
fn decoded<H: HeaderDecode + HeaderEncode>(lines: &[&str]) -> Option<Vec<HeaderValue>> {
    let header = H::decode(&mut values(lines).iter()).ok()?;
    let mut encoded = Vec::new();
    header.encode(&mut encoded);
    Some(encoded)
}

type Decoded = fn(&[&str]) -> Option<Vec<HeaderValue>>;

macro_rules! fields {
    ($($ty:ty => $first:literal, $second:literal),+ $(,)?) => {
        [$((stringify!($ty), decoded::<$ty> as Decoded, $first, $second)),+]
    };
}

#[test]
fn singleton_fields_refuse_a_second_line() {
    for (name, decoded, first, second) in fields![
        Authorization<Basic> => "Basic dXNlcjpwYXNz", "Basic b3RoZXI6cGFzcw==",
        Authorization<Bearer> => "Bearer token", "Bearer other",
        ProxyAuthorization<Basic> => "Basic dXNlcjpwYXNz", "Basic b3RoZXI6cGFzcw==",
        Host => "example.com", "attacker.example",
        Origin => "https://example.com", "https://attacker.example",
        SecFetchSite => "same-origin", "cross-site",
        SecWebSocketKey => "dGhlIHNhbXBsZSBub25jZQ==", "AQIDBAUGBwgJCgsMDQ4PEA==",
        SecWebSocketAccept => "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        SecWebSocketVersion => "13", "13",
        AltUsed => "example.com", "example.net",
        CapsuleProtocol => "?1", "?0",
        Date => "Sun, 06 Nov 1994 08:49:37 GMT", "Mon, 07 Nov 1994 08:49:37 GMT",
        XRealIp => "203.0.113.5", "198.51.100.7",
        XClientIp => "203.0.113.5", "198.51.100.7",
        ClientIp => "203.0.113.5", "198.51.100.7",
        CFConnectingIp => "203.0.113.5", "198.51.100.7",
        TrueClientIp => "203.0.113.5", "198.51.100.7",
    ] {
        assert!(decoded(&[first]).is_some(), "{name}: one line");
        assert!(decoded(&[second]).is_some(), "{name}: the other line");
        for lines in [[first, first], [first, second], [second, first]] {
            assert_eq!(decoded(&lines), None, "{name}: {lines:?}");
        }
    }
}

#[test]
fn list_fields_read_every_line() {
    for (name, decoded, first, second) in fields![
        Upgrade => "websocket", "h2c",
        Connection => "keep-alive", "upgrade",
        Vary => "accept", "origin",
        Allow => "GET", "POST",
        AccessControlAllowHeaders => "x-a", "x-b",
        SecWebSocketProtocol => "chat", "superchat",
        SecWebSocketExtensions => "permessage-deflate", "x-other",
        XForwardedFor => "203.0.113.5", "198.51.100.7",
        XForwardedHost => "example.com", "example.net",
        XForwardedProto => "https", "http",
        Via => "1.1 proxy-a", "1.1 proxy-b",
    ] {
        let joined = format!("{first}, {second}");
        let expected = decoded(&[&joined]);
        assert!(expected.is_some(), "{name}: {joined}");
        assert_eq!(decoded(&[first, second]), expected, "{name}");
    }
}
