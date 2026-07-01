use std::sync::Arc;

use rama_core::error::{BoxError, ErrorContext as _};
use rama_http::HeaderMap;
use serde::Deserialize;

use crate::profile::*;
use crate::*;

/// Load the profiles embedded with the rama-ua crate.
///
/// This function is only available if the `embed-profiles` feature is enabled.
pub fn try_load_embedded_profiles() -> Result<impl Iterator<Item = UserAgentProfile>, BoxError> {
    let profiles: Vec<UserAgentProfileRow> =
        serde_json::from_str(include_str!("embed_profiles.json"))
            .context("deserialize embedded profiles")?;
    Ok(profiles.into_iter().filter_map(|row| {
        let ua = UserAgent::new(row.uastr);
        Some(UserAgentProfile {
            ua_kind: ua.ua_kind()?,
            ua_version: ua.ua_version(),
            platform: ua.platform(),
            http: Arc::new(HttpProfile {
                h1: Http1Profile {
                    settings: row.h1_settings?,
                    headers: HttpHeadersProfile {
                        navigate: row.h1_headers_navigate?,
                        fetch: row.h1_headers_fetch,
                        xhr: row.h1_headers_xhr,
                        form: row.h1_headers_form,
                        ws: row.h1_headers_ws,
                    },
                },
                h2: Http2Profile {
                    settings: row.h2_settings?,
                    headers: HttpHeadersProfile {
                        navigate: row.h2_headers_navigate?,
                        fetch: row.h2_headers_fetch,
                        xhr: row.h2_headers_xhr,
                        form: row.h2_headers_form,
                        ws: row.h2_headers_ws,
                    },
                },
            }),
            #[cfg(feature = "tls")]
            tls: Arc::new(TlsProfile {
                client_hello: row.tls_client_hello?,
                ws_client_config_overwrites: row.tls_ws_client_config_overwrites,
            }),
            runtime: match (&row.js_web_apis, &row.source_info) {
                (Some(_), _) | (_, Some(_)) => Some(Arc::new(UserAgentRuntimeProfile {
                    js_info: row.js_web_apis.map(|web_apis| JsProfile {
                        web_apis: Some(web_apis),
                    }),
                    source_info: row.source_info,
                })),
                _ => None,
            },
        })
    }))
}

#[derive(Debug, Deserialize)]
struct UserAgentProfileRow {
    uastr: String,
    h1_settings: Option<Http1Settings>,
    h1_headers_navigate: Option<HeaderMap>,
    h1_headers_fetch: Option<HeaderMap>,
    h1_headers_xhr: Option<HeaderMap>,
    h1_headers_form: Option<HeaderMap>,
    h1_headers_ws: Option<HeaderMap>,
    h2_settings: Option<Http2Settings>,
    h2_headers_navigate: Option<HeaderMap>,
    h2_headers_fetch: Option<HeaderMap>,
    h2_headers_xhr: Option<HeaderMap>,
    h2_headers_form: Option<HeaderMap>,
    h2_headers_ws: Option<HeaderMap>,
    #[cfg(feature = "tls")]
    tls_client_hello: Option<rama_tls::client::ClientHello>,
    #[cfg(feature = "tls")]
    tls_ws_client_config_overwrites: Option<WsClientConfigOverwrites>,
    js_web_apis: Option<JsProfileWebApis>,
    source_info: Option<UserAgentSourceInfo>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_embedded_profiles() {
        let profiles: Vec<_> = try_load_embedded_profiles().unwrap().collect();
        assert!(!profiles.is_empty());
    }
}
