use std::sync::Arc;

use rama_http_types::proto::h1::Http1HeaderMap;
use serde::Deserialize;

use crate::*;

/// Load the profiles embedded with the rama-ua crate.
///
/// This function is only available if the `embed-profiles` feature is enabled.
pub fn load_embedded_profiles() -> impl Iterator<Item = UserAgentProfile> {
    let profiles: Vec<UserAgentProfileRow> =
        serde_json::from_str(include_str!("embed_profiles.json"))
            .expect("Failed to deserialize embedded profiles");
    profiles.into_iter().filter_map(|row| {
        let ua = UserAgent::new(row.uastr);
        Some(UserAgentProfile {
            ua_kind: ua.ua_kind()?,
            ua_version: ua.ua_version(),
            platform: ua.platform(),
            http: HttpProfile {
                h1: Arc::new(Http1Profile {
                    settings: row.h1_settings?,
                    headers: HttpHeadersProfile {
                        navigate: row.h1_headers_navigate?,
                        fetch: row.h1_headers_fetch,
                        xhr: row.h1_headers_xhr,
                        form: row.h1_headers_form,
                    },
                }),
                h2: Arc::new(Http2Profile {
                    settings: row.h2_settings?,
                    headers: HttpHeadersProfile {
                        navigate: row.h2_headers_navigate?,
                        fetch: row.h2_headers_fetch,
                        xhr: row.h2_headers_xhr,
                        form: row.h2_headers_form,
                    },
                }),
            },
            #[cfg(feature = "tls")]
            tls: TlsProfile {
                client_config: std::sync::Arc::new(
                    row.tls_client_hello
                        .map(rama_net::tls::client::ClientConfig::from)?,
                ),
            },
        })
    })
}

#[derive(Debug, Deserialize)]
struct UserAgentProfileRow {
    uastr: String,
    h1_settings: Option<Http1Settings>,
    h1_headers_navigate: Option<Http1HeaderMap>,
    h1_headers_fetch: Option<Http1HeaderMap>,
    h1_headers_xhr: Option<Http1HeaderMap>,
    h1_headers_form: Option<Http1HeaderMap>,
    h2_settings: Option<Http2Settings>,
    h2_headers_navigate: Option<Http1HeaderMap>,
    h2_headers_fetch: Option<Http1HeaderMap>,
    h2_headers_xhr: Option<Http1HeaderMap>,
    h2_headers_form: Option<Http1HeaderMap>,
    #[cfg(feature = "tls")]
    tls_client_hello: Option<rama_net::tls::client::ClientHello>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_embedded_profiles() {
        let profiles: Vec<_> = load_embedded_profiles().collect();
        assert!(!profiles.is_empty());
    }
}
