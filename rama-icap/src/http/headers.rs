use rama_http_types::{
    HeaderMap,
    header::{self as http_header, HeaderName, HeaderValue},
};

use crate::proto::header;

#[derive(Clone)]
pub(super) struct ForwardedIcapHeader {
    pub(super) name: &'static str,
    pub(super) value: HeaderValue,
}

pub(super) fn sanitize_http_headers(headers: &mut HeaderMap) -> Vec<ForwardedIcapHeader> {
    let mut forwarded = Vec::new();
    for (name, icap_name) in [
        (&http_header::PROXY_AUTHENTICATE, header::PROXY_AUTHENTICATE),
        (
            &http_header::PROXY_AUTHORIZATION,
            header::PROXY_AUTHORIZATION,
        ),
    ] {
        forwarded.extend(headers.get_all(name).iter().cloned().map(|mut value| {
            if name.is_sensitive() {
                value.set_sensitive(true);
            }
            ForwardedIcapHeader {
                name: icap_name,
                value,
            }
        }));
        headers.remove(name);
    }

    let nominated = headers
        .get_all(http_header::CONNECTION)
        .iter()
        .flat_map(|value| value.as_bytes().split(|byte| *byte == b','))
        .filter_map(|token| {
            let token = token.trim_ascii();
            if token.is_empty() {
                None
            } else {
                HeaderName::from_bytes(token).ok()
            }
        })
        .collect::<Vec<_>>();
    for name in [
        &http_header::CONNECTION,
        &http_header::KEEP_ALIVE,
        &http_header::PROXY_CONNECTION,
        &http_header::TE,
        &http_header::TRAILER,
        &http_header::TRANSFER_ENCODING,
        &http_header::UPGRADE,
    ] {
        headers.remove(name);
    }
    for name in nominated {
        headers.remove(name);
    }
    forwarded
}
