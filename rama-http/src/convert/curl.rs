//! Convert http requests with or without its payload
//! into a valid curl command.

use std::borrow::Cow;
use std::fmt::{self, Write};
use std::process::Command;

use crate::header::ACCEPT_ENCODING;
use crate::headers::{HeaderEncode, ProxyAuthorization};
use crate::proto::h1::headers::original::OriginalHttp1Headers;
use crate::proto::h1::{Http1HeaderMap, Http1HeaderName};
use crate::{Method, Uri, Version, request};

use rama_core::bytes::Bytes;
use rama_http_types::HttpRequestParts;
use rama_net::address::ProxyAddress;
use rama_net::http::{RequestContext, try_request_ctx_from_http_parts};
use rama_net::mode::{ConnectIpMode, DnsResolveIpMode};
use rama_net::user::ProxyCredential;

/// Create a `curl` command string for the given [`HttpRequestParts`].
pub fn cmd_string_for_request_parts(parts: &impl HttpRequestParts) -> String {
    let mut cmd = "curl".to_owned();
    write_curl_command_for_request_parts(&mut cmd, parts, None);
    cmd
}

/// Create a `curl` command string for the given [`HttpRequestParts`] and payload bytes.
pub fn cmd_string_for_request_parts_and_payload(parts: &request::Parts, payload: &Bytes) -> String {
    let mut cmd = "curl".to_owned();
    write_curl_command_for_request_parts(&mut cmd, parts, Some(payload));
    cmd
}

/// Create a `curl` [`Command`] for the given [`HttpRequestParts`].
pub fn cmd_for_request_parts(parts: &impl HttpRequestParts) -> Command {
    let mut cmd = Command::new("curl");
    write_curl_command_for_request_parts(&mut cmd, parts, None);
    cmd
}

/// Create a `curl` [`Command`] for the given [`HttpRequestParts`] and payload bytes.
pub fn cmd_for_request_parts_and_payload(parts: &request::Parts, payload: &Bytes) -> Command {
    let mut cmd = Command::new("curl");
    write_curl_command_for_request_parts(&mut cmd, parts, Some(payload));
    cmd
}

trait CurlCommandWriter {
    fn write_uri(&mut self, uri: Uri) -> &mut Self;
    fn write_single(&mut self, one: impl fmt::Display) -> &mut Self;
    fn write_tuple(
        &mut self,
        one: impl fmt::Display,
        two: impl fmt::Display,
        quote_value: bool,
    ) -> &mut Self;
    fn write_header(&mut self, key: Http1HeaderName, value: Cow<'_, str>) -> &mut Self;
}

impl CurlCommandWriter for Command {
    fn write_uri(&mut self, uri: Uri) -> &mut Self {
        self.arg(format!("'{uri}'"))
    }

    fn write_single(&mut self, one: impl fmt::Display) -> &mut Self {
        self.arg(one.to_string())
    }

    fn write_tuple(
        &mut self,
        one: impl fmt::Display,
        two: impl fmt::Display,
        quote_value: bool,
    ) -> &mut Self {
        self.arg(one.to_string()).arg(if quote_value {
            format!("'{two}'")
        } else {
            two.to_string()
        })
    }

    fn write_header(&mut self, key: Http1HeaderName, value: Cow<'_, str>) -> &mut Self {
        self.arg("-H").arg(format!("'{key}: {value}'"))
    }
}

impl CurlCommandWriter for String {
    fn write_uri(&mut self, uri: Uri) -> &mut Self {
        let _ = write!(self, " '{uri}'");
        self
    }

    fn write_single(&mut self, one: impl fmt::Display) -> &mut Self {
        let _ = write!(self, " \\{}  {one}", rama_utils::str::NATIVE_NEWLINE);
        self
    }

    fn write_tuple(
        &mut self,
        one: impl fmt::Display,
        two: impl fmt::Display,
        quote_value: bool,
    ) -> &mut Self {
        let quote = if quote_value { "'" } else { "" };
        let _ = write!(
            self,
            " \\{}  {one} {quote}{two}{quote}",
            rama_utils::str::NATIVE_NEWLINE
        );
        self
    }

    fn write_header(&mut self, key: Http1HeaderName, value: Cow<'_, str>) -> &mut Self {
        let _ = write!(
            self,
            " \\{}  -H '{key}: {value}'",
            rama_utils::str::NATIVE_NEWLINE
        );
        self
    }
}

fn write_curl_command_for_request_parts(
    writer: &mut impl CurlCommandWriter,
    parts: &impl HttpRequestParts,
    payload: Option<&Bytes>,
) {
    let mut uri_parts = parts.uri().clone().into_parts();
    if let Some((authority, protocol)) = parts
        .extensions()
        .get::<RequestContext>()
        .map(|rc| {
            (
                if rc.authority_has_default_port() {
                    rc.authority.host.to_string()
                } else {
                    rc.authority.to_string()
                },
                rc.protocol.clone(),
            )
        })
        .or_else(|| {
            try_request_ctx_from_http_parts(parts).ok().map(|rc| {
                (
                    if rc.authority_has_default_port() {
                        rc.authority.host.to_string()
                    } else {
                        rc.authority.to_string()
                    },
                    rc.protocol,
                )
            })
        })
        .and_then(|(authority, protocol)| authority.parse().ok().map(|auth| (auth, protocol)))
    {
        uri_parts.authority = Some(authority);
        if uri_parts.scheme.is_none() {
            uri_parts.scheme = Some(protocol.as_str().try_into().unwrap_or(crate::Scheme::HTTP));
        }
    }
    writer.write_uri(Uri::from_parts(uri_parts).unwrap_or_else(|_| parts.uri().clone()));

    if parts.headers().contains_key(ACCEPT_ENCODING) {
        writer.write_single("--compressed");
    }

    if parts.method() != Method::GET {
        writer.write_tuple("-X", parts.method(), false);
    }

    match parts.version() {
        Version::HTTP_09 => {
            writer.write_single("--http0.9");
        }
        Version::HTTP_10 => {
            writer.write_single("--http1.0");
        }
        Version::HTTP_11 => {
            writer.write_single("--http1.1");
        }
        Version::HTTP_2 => {
            writer.write_single("--http2");
        }
        Version::HTTP_3 => {
            writer.write_single("--http3");
        }
        _ => (), // ignore
    }

    if let Some(proxy_addr) = parts
        .extensions()
        .get::<ProxyAddress>()
        .or_else(|| parts.extensions().get())
    {
        writer.write_tuple("-x", proxy_addr, true);
        if let Some(ProxyCredential::Bearer(bearer)) = &proxy_addr.credential
            && let Some(value) = ProxyAuthorization(bearer.clone()).encode_to_value()
        {
            let s_value = String::from_utf8_lossy(value.as_bytes());
            writer.write_header(
                Http1HeaderName::from(crate::header::PROXY_AUTHORIZATION),
                s_value,
            );
        }
    }

    match (
        parts.extensions().get::<DnsResolveIpMode>(),
        parts.extensions().get::<ConnectIpMode>(),
    ) {
        (Some(DnsResolveIpMode::SingleIpV4), _)
        | (
            None | Some(DnsResolveIpMode::DualPreferIpV4 | DnsResolveIpMode::Dual),
            Some(ConnectIpMode::Ipv4),
        ) => {
            // force ipv4
            writer.write_single("-4");
        }
        (Some(DnsResolveIpMode::SingleIpV6), _)
        | (
            None | Some(DnsResolveIpMode::DualPreferIpV4 | DnsResolveIpMode::Dual),
            Some(ConnectIpMode::Ipv6),
        ) => {
            // force ipv6
            writer.write_single("-6");
        }
        _ => (), // nothing that can be done
    }

    let original_http_headers = parts
        .extensions()
        .get::<OriginalHttp1Headers>()
        .or_else(|| parts.extensions().get())
        .cloned()
        .unwrap_or_default();
    for (key, value) in Http1HeaderMap::from_parts(parts.headers().clone(), original_http_headers) {
        if matches!(
            key.header_name(),
            &crate::header::HOST
                | &crate::header::CONTENT_LENGTH
                | &crate::header::TRANSFER_ENCODING
        ) {
            // ignore content headers as we are not sending a payload
            continue;
        }

        let s_value = String::from_utf8_lossy(value.as_bytes());
        writer.write_header(key, s_value);
    }

    if let Some(payload) = payload
        && !payload.is_empty()
    {
        writer.write_tuple(
            "--data-raw",
            String::from_utf8_lossy(payload.as_ref()),
            true,
        );
    }
}

#[cfg(test)]
mod tests {
    use rama_net::Protocol;
    use rama_net::address::HostWithPort;
    use rama_net::user::credentials::{basic, bearer};

    use crate::body::util::BodyExt;
    use crate::layer::har;

    use super::*;

    #[tokio::test]
    async fn test_cmd_string_for_request_parts_from_har() {
        struct TestCase {
            description: &'static str,
            input_har_request: &'static str,
            expected_cmd_string: String,
        }

        for test_case in [
            TestCase {
                description: "GET example.com",
                input_har_request: r##"{
    "bodySize": 0,
    "method": "GET",
    "url": "https://example.com/",
    "httpVersion": "HTTP/2",
    "headers": [
        {
            "name": "Host",
            "value": "example.com"
        },
        {
            "name": "User-Agent",
            "value": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0"
        },
        {
            "name": "Accept",
            "value": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        },
        {
            "name": "Accept-Language",
            "value": "en-US,en;q=0.5"
        },
        {
            "name": "Accept-Encoding",
            "value": "gzip, deflate, br, zstd"
        },
        {
            "name": "Sec-GPC",
            "value": "1"
        },
        {
            "name": "Upgrade-Insecure-Requests",
            "value": "1"
        },
        {
            "name": "Connection",
            "value": "keep-alive"
        },
        {
            "name": "Sec-Fetch-Dest",
            "value": "document"
        },
        {
            "name": "Sec-Fetch-Mode",
            "value": "navigate"
        },
        {
            "name": "Sec-Fetch-Site",
            "value": "none"
        },
        {
            "name": "Sec-Fetch-User",
            "value": "?1"
        },
        {
            "name": "Priority",
            "value": "u=0, i"
        },
        {
            "name": "Pragma",
            "value": "no-cache"
        },
        {
            "name": "Cache-Control",
            "value": "no-cache"
        }
    ],
    "cookies": [],
    "queryString": [],
    "headersSize": 504
}"##,
                expected_cmd_string: format!(
                    r##"curl 'https://example.com/' \{NL}  --compressed \{NL}  --http2 \{NL}  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0' \{NL}  -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \{NL}  -H 'Accept-Language: en-US,en;q=0.5' \{NL}  -H 'Accept-Encoding: gzip, deflate, br, zstd' \{NL}  -H 'Sec-GPC: 1' \{NL}  -H 'Upgrade-Insecure-Requests: 1' \{NL}  -H 'Connection: keep-alive' \{NL}  -H 'Sec-Fetch-Dest: document' \{NL}  -H 'Sec-Fetch-Mode: navigate' \{NL}  -H 'Sec-Fetch-Site: none' \{NL}  -H 'Sec-Fetch-User: ?1' \{NL}  -H 'Priority: u=0, i' \{NL}  -H 'Pragma: no-cache' \{NL}  -H 'Cache-Control: no-cache'"##,
                    NL = rama_utils::str::NATIVE_NEWLINE
                ),
            },
            TestCase {
                description: "POST form request for ramaproxy FP",
                input_har_request: r##"{
    "bodySize": 19,
    "method": "POST",
    "url": "https://fp.ramaproxy.org/form",
    "httpVersion": "HTTP/2",
    "headers": [
    {
        "name": "Host",
        "value": "fp.ramaproxy.org"
    },
    {
        "name": "User-Agent",
        "value": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0"
    },
    {
        "name": "Accept",
        "value": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    },
    {
        "name": "Accept-Language",
        "value": "en-US,en;q=0.5"
    },
    {
        "name": "Accept-Encoding",
        "value": "gzip, deflate, br, zstd"
    },
    {
        "name": "Content-Type",
        "value": "application/x-www-form-urlencoded"
    },
    {
        "name": "Content-Length",
        "value": "19"
    },
    {
        "name": "Origin",
        "value": "https://fp.ramaproxy.org"
    },
    {
        "name": "Sec-GPC",
        "value": "1"
    },
    {
        "name": "Connection",
        "value": "keep-alive"
    },
    {
        "name": "Referer",
        "value": "https://fp.ramaproxy.org/report"
    },
    {
        "name": "Cookie",
        "value": "rama-fp=ready"
    },
    {
        "name": "Upgrade-Insecure-Requests",
        "value": "1"
    },
    {
        "name": "Sec-Fetch-Dest",
        "value": "document"
    },
    {
        "name": "Sec-Fetch-Mode",
        "value": "navigate"
    },
    {
        "name": "Sec-Fetch-Site",
        "value": "same-origin"
    },
    {
        "name": "Sec-Fetch-User",
        "value": "?1"
    },
    {
        "name": "Priority",
        "value": "u=0, i"
    },
    {
        "name": "Pragma",
        "value": "no-cache"
    },
    {
        "name": "Cache-Control",
        "value": "no-cache"
    },
    {
        "name": "TE",
        "value": "trailers"
    }
    ],
    "cookies": [
    {
        "name": "rama-fp",
        "value": "ready"
    }
    ],
    "queryString": [],
    "headersSize": 689,
    "postData": {
    "mimeType": "application/x-www-form-urlencoded",
    "params": [
        {
        "name": "source",
        "value": "web"
        },
        {
        "name": "rating",
        "value": "3"
        }
    ],
    "text": "source=web&rating=3"
    }
}"##,
                expected_cmd_string: format!(
                    r##"curl 'https://fp.ramaproxy.org/form' \{NL}  --compressed \{NL}  -X POST \{NL}  --http2 \{NL}  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0' \{NL}  -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \{NL}  -H 'Accept-Language: en-US,en;q=0.5' \{NL}  -H 'Accept-Encoding: gzip, deflate, br, zstd' \{NL}  -H 'Content-Type: application/x-www-form-urlencoded' \{NL}  -H 'Origin: https://fp.ramaproxy.org' \{NL}  -H 'Sec-GPC: 1' \{NL}  -H 'Connection: keep-alive' \{NL}  -H 'Referer: https://fp.ramaproxy.org/report' \{NL}  -H 'Cookie: rama-fp=ready' \{NL}  -H 'Upgrade-Insecure-Requests: 1' \{NL}  -H 'Sec-Fetch-Dest: document' \{NL}  -H 'Sec-Fetch-Mode: navigate' \{NL}  -H 'Sec-Fetch-Site: same-origin' \{NL}  -H 'Sec-Fetch-User: ?1' \{NL}  -H 'Priority: u=0, i' \{NL}  -H 'Pragma: no-cache' \{NL}  -H 'Cache-Control: no-cache' \{NL}  -H 'TE: trailers' \{NL}  --data-raw 'source=web&rating=3'"##,
                    NL = rama_utils::str::NATIVE_NEWLINE
                ),
            },
        ] {
            // put input together
            let har_request: har::spec::Request = serde_json::from_str(test_case.input_har_request)
                .unwrap_or_else(|err| {
                    panic!(
                        "expect testcase '{}' har request to deserialize: {err}",
                        test_case.description
                    )
                });
            let request: crate::Request = har_request.try_into().unwrap_or_else(|err| {
                panic!(
                    "expect testcase '{}' har request to convert into a http request: {err}",
                    test_case.description
                )
            });

            let (parts, body) = request.into_parts();
            let payload = body.collect().await.unwrap().to_bytes();

            let cmd_string = if payload.is_empty() {
                cmd_string_for_request_parts(&parts)
            } else {
                cmd_string_for_request_parts_and_payload(&parts, &payload)
            };

            assert_eq!(
                test_case.expected_cmd_string, cmd_string,
                "testcase '{}'",
                test_case.description
            );
        }
    }

    #[test]
    fn test_cmd_string_for_request_with_http_proxy_no_auth() {
        let (mut parts, _) = crate::Request::builder()
            .uri("example.com")
            .body(())
            .unwrap()
            .into_parts();

        parts.extensions.insert(ProxyAddress {
            protocol: None,
            address: HostWithPort::local_ipv4(8080),
            credential: None,
        });

        let s = cmd_string_for_request_parts(&&parts);
        assert_eq!(
            s,
            format!(
                r##"curl 'example.com' \{NL}  --http1.1 \{NL}  -x '127.0.0.1:8080'"##,
                NL = rama_utils::str::NATIVE_NEWLINE
            ),
        );
    }

    #[test]
    fn test_cmd_string_for_request_with_ipv4_preference() {
        let (mut parts, _) = crate::Request::builder()
            .uri("example.com")
            .body(())
            .unwrap()
            .into_parts();

        parts.extensions.insert(DnsResolveIpMode::SingleIpV4);

        let s = cmd_string_for_request_parts(&&parts);
        assert_eq!(
            s,
            format!(
                r##"curl 'example.com' \{NL}  --http1.1 \{NL}  -4"##,
                NL = rama_utils::str::NATIVE_NEWLINE
            ),
        );
    }

    #[test]
    fn test_cmd_string_for_request_with_ipv6_preference() {
        let (mut parts, _) = crate::Request::builder()
            .uri("example.com")
            .body(())
            .unwrap()
            .into_parts();

        parts.extensions.insert(DnsResolveIpMode::SingleIpV6);

        let s = cmd_string_for_request_parts(&&parts);
        assert_eq!(
            s,
            format!(
                r##"curl 'example.com' \{NL}  --http1.1 \{NL}  -6"##,
                NL = rama_utils::str::NATIVE_NEWLINE
            ),
        );
    }

    #[test]
    fn test_cmd_string_for_request_with_http_proxy_with_auth_basic_only_username() {
        let (mut parts, _) = crate::Request::builder()
            .uri("example.com")
            .body(())
            .unwrap()
            .into_parts();

        parts.extensions.insert(ProxyAddress {
            protocol: None,
            address: HostWithPort::local_ipv4(8080),
            credential: Some(ProxyCredential::Basic(basic!("john"))),
        });

        let s = cmd_string_for_request_parts(&&parts);
        assert_eq!(
            s,
            format!(
                r##"curl 'example.com' \{NL}  --http1.1 \{NL}  -x 'john@127.0.0.1:8080'"##,
                NL = rama_utils::str::NATIVE_NEWLINE
            ),
        );
    }

    #[test]
    fn test_cmd_string_for_request_with_http_proxy_with_auth_basic() {
        let (mut parts, _) = crate::Request::builder()
            .uri("example.com")
            .body(())
            .unwrap()
            .into_parts();

        parts.extensions.insert(ProxyAddress {
            protocol: None,
            address: HostWithPort::local_ipv4(8080),
            credential: Some(ProxyCredential::Basic(basic!("john", "secret"))),
        });

        let s = cmd_string_for_request_parts(&&parts);
        assert_eq!(
            s,
            format!(
                r##"curl 'example.com' \{NL}  --http1.1 \{NL}  -x 'john:secret@127.0.0.1:8080'"##,
                NL = rama_utils::str::NATIVE_NEWLINE
            ),
        )
    }

    #[test]
    fn test_cmd_string_for_request_with_http_proxy_with_auth_bearer() {
        let (mut parts, _) = crate::Request::builder()
            .uri("example.com")
            .body(())
            .unwrap()
            .into_parts();

        parts.extensions.insert(ProxyAddress {
            protocol: None,
            address: HostWithPort::local_ipv4(8080),
            credential: Some(ProxyCredential::Bearer(bearer!("abc123"))),
        });

        let s = cmd_string_for_request_parts(&&parts);
        assert_eq!(
            s,
            format!(
                r##"curl 'example.com' \{NL}  --http1.1 \{NL}  -x '127.0.0.1:8080' \{NL}  -H 'proxy-authorization: Bearer abc123'"##,
                NL = rama_utils::str::NATIVE_NEWLINE
            ),
        );
    }

    #[test]
    fn test_cmd_string_for_request_with_socks5_proxy() {
        let (mut parts, _) = crate::Request::builder()
            .version(Version::HTTP_3)
            .uri("example.com")
            .body(())
            .unwrap()
            .into_parts();

        parts.extensions.insert(ProxyAddress {
            protocol: Some(Protocol::SOCKS5),
            address: HostWithPort::local_ipv4(8080),
            credential: Some(ProxyCredential::Basic(basic!("user", "pass"))),
        });

        let s = cmd_string_for_request_parts(&&parts);
        assert_eq!(
            s,
            format!(
                r##"curl 'example.com' \{NL}  --http3 \{NL}  -x 'socks5://user:pass@127.0.0.1:8080'"##,
                NL = rama_utils::str::NATIVE_NEWLINE
            ),
        );
    }
}
