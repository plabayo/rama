use std::{collections::BTreeMap, sync::Arc};

use rama_core::error::{BoxError, ErrorContext as _};
use rama_http::HeaderMap;
use serde::{Deserialize, Serialize};

use crate::profile::*;
use crate::*;

/// Load the profiles embedded with the rama-ua crate.
///
/// This function is only available if the `embed-profiles` feature is enabled.
pub fn try_load_embedded_profiles() -> Result<impl Iterator<Item = UserAgentProfile>, BoxError> {
    Ok(try_load_profiles_json(include_bytes!("embed_profiles.json"))?.into_iter())
}

/// Load a JSON array of captured user-agent profile rows.
///
/// Rows with the same User-Agent are merged by filling fields that were not
/// observed in another row. The resulting database remains strict: every
/// merged profile must contain the HTTP/1, HTTP/2 and TLS components required
/// by [`UserAgentProfile`]. No embedded or synthetic data is used to fill gaps.
pub fn try_load_profiles_json(bytes: &[u8]) -> Result<Vec<UserAgentProfile>, BoxError> {
    let rows: Vec<UserAgentProfileInput> =
        serde_json::from_slice(bytes).context("deserialize user-agent profiles")?;
    let mut profiles = Vec::<UserAgentProfileInput>::new();
    let mut indices = BTreeMap::<String, usize>::new();
    for row in rows {
        if let Some(index) = indices.get(&row.uastr).copied() {
            profiles[index].merge_missing(row)?;
        } else {
            indices.insert(row.uastr.clone(), profiles.len());
            profiles.push(row);
        }
    }
    profiles
        .into_iter()
        .map(UserAgentProfileInput::try_into_profile)
        .collect()
}

#[derive(Debug, Deserialize, Serialize)]
/// Serializable user-agent profile input used by Rama's embedded and custom
/// profile databases.
///
/// Fields are optional because fingerprint collection often observes HTTP/1,
/// HTTP/2 and TLS over separate connections. Multiple rows with the same
/// `uastr` can therefore be combined without inventing unobserved data.
pub struct UserAgentProfileInput {
    pub uastr: String,
    pub h1_settings: Option<Http1Settings>,
    pub h1_headers_navigate: Option<HeaderMap>,
    pub h1_headers_fetch: Option<HeaderMap>,
    pub h1_headers_xhr: Option<HeaderMap>,
    pub h1_headers_form: Option<HeaderMap>,
    pub h1_headers_ws: Option<HeaderMap>,
    pub h2_settings: Option<Http2Settings>,
    pub h2_headers_navigate: Option<HeaderMap>,
    pub h2_headers_fetch: Option<HeaderMap>,
    pub h2_headers_xhr: Option<HeaderMap>,
    pub h2_headers_form: Option<HeaderMap>,
    pub h2_headers_ws: Option<HeaderMap>,
    #[cfg(feature = "tls")]
    pub tls_client_hello: Option<rama_tls::client::ClientHello>,
    #[cfg(feature = "tls")]
    pub tls_ws_client_config_overwrites: Option<WsClientConfigOverwrites>,
    pub js_web_apis: Option<JsProfileWebApis>,
    pub source_info: Option<UserAgentSourceInfo>,
}

impl UserAgentProfileInput {
    /// Create an empty captured profile row for a User-Agent value.
    pub fn new(uastr: impl Into<String>) -> Self {
        Self {
            uastr: uastr.into(),
            h1_settings: None,
            h1_headers_navigate: None,
            h1_headers_fetch: None,
            h1_headers_xhr: None,
            h1_headers_form: None,
            h1_headers_ws: None,
            h2_settings: None,
            h2_headers_navigate: None,
            h2_headers_fetch: None,
            h2_headers_xhr: None,
            h2_headers_form: None,
            h2_headers_ws: None,
            #[cfg(feature = "tls")]
            tls_client_hello: None,
            #[cfg(feature = "tls")]
            tls_ws_client_config_overwrites: None,
            js_web_apis: None,
            source_info: None,
        }
    }

    /// Fill fields absent from this row with observations from another row for
    /// the exact same User-Agent. Existing observations always win.
    pub fn merge_missing(&mut self, other: Self) -> Result<(), BoxError> {
        if self.uastr != other.uastr {
            return Err(BoxError::from(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "cannot merge profile rows for different User-Agent values",
            )));
        }
        macro_rules! fill {
            ($($field:ident),+ $(,)?) => {$ (
                if self.$field.is_none() {
                    self.$field = other.$field;
                }
            )+ };
        }
        fill!(
            h1_settings,
            h1_headers_navigate,
            h1_headers_fetch,
            h1_headers_xhr,
            h1_headers_form,
            h1_headers_ws,
            h2_settings,
            h2_headers_navigate,
            h2_headers_fetch,
            h2_headers_xhr,
            h2_headers_form,
            h2_headers_ws,
            js_web_apis,
            source_info,
        );
        #[cfg(feature = "tls")]
        fill!(tls_client_hello, tls_ws_client_config_overwrites);
        Ok(())
    }

    fn try_into_profile(self) -> Result<UserAgentProfile, BoxError> {
        let ua = UserAgent::new(self.uastr);
        let missing = |field: &str| {
            BoxError::from(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "user-agent profile '{}' is missing {field}",
                    ua.header_str()
                ),
            ))
        };
        Ok(UserAgentProfile {
            ua_kind: ua
                .ua_kind()
                .ok_or_else(|| missing("a recognized User-Agent kind"))?,
            ua_version: ua.ua_version(),
            platform: ua.platform(),
            http: Arc::new(HttpProfile {
                h1: Http1Profile {
                    settings: self.h1_settings.ok_or_else(|| missing("h1_settings"))?,
                    headers: HttpHeadersProfile {
                        navigate: self
                            .h1_headers_navigate
                            .ok_or_else(|| missing("h1_headers_navigate"))?,
                        fetch: self.h1_headers_fetch,
                        xhr: self.h1_headers_xhr,
                        form: self.h1_headers_form,
                        ws: self.h1_headers_ws,
                    },
                },
                h2: Http2Profile {
                    settings: self.h2_settings.ok_or_else(|| missing("h2_settings"))?,
                    headers: HttpHeadersProfile {
                        navigate: self
                            .h2_headers_navigate
                            .ok_or_else(|| missing("h2_headers_navigate"))?,
                        fetch: self.h2_headers_fetch,
                        xhr: self.h2_headers_xhr,
                        form: self.h2_headers_form,
                        ws: self.h2_headers_ws,
                    },
                },
            }),
            #[cfg(feature = "tls")]
            tls: Arc::new(TlsProfile {
                client_hello: self
                    .tls_client_hello
                    .ok_or_else(|| missing("tls_client_hello"))?,
                ws_client_config_overwrites: self.tls_ws_client_config_overwrites,
            }),
            runtime: match (&self.js_web_apis, &self.source_info) {
                (Some(_), _) | (_, Some(_)) => Some(Arc::new(UserAgentRuntimeProfile {
                    js_info: self.js_web_apis.map(|web_apis| JsProfile {
                        web_apis: Some(web_apis),
                    }),
                    source_info: self.source_info,
                })),
                _ => None,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_embedded_profiles() {
        let profiles: Vec<_> = try_load_embedded_profiles().unwrap().collect();
        assert!(!profiles.is_empty());
    }

    #[test]
    fn profile_loader_merges_only_observed_rows_for_the_same_user_agent() {
        let mut rows: Vec<UserAgentProfileInput> =
            serde_json::from_slice(include_bytes!("embed_profiles.json")).unwrap();
        let mut complete = rows.remove(0);
        let user_agent = complete.uastr.clone();

        let mut h1 = UserAgentProfileInput::new(user_agent.clone());
        h1.h1_settings = complete.h1_settings.take();
        h1.h1_headers_navigate = complete.h1_headers_navigate.take();
        h1.h1_headers_fetch = complete.h1_headers_fetch.take();
        h1.h1_headers_xhr = complete.h1_headers_xhr.take();
        h1.h1_headers_form = complete.h1_headers_form.take();
        h1.h1_headers_ws = complete.h1_headers_ws.take();

        let mut h2 = UserAgentProfileInput::new(user_agent.clone());
        h2.h2_settings = complete.h2_settings.take();
        h2.h2_headers_navigate = complete.h2_headers_navigate.take();
        h2.h2_headers_fetch = complete.h2_headers_fetch.take();
        h2.h2_headers_xhr = complete.h2_headers_xhr.take();
        h2.h2_headers_form = complete.h2_headers_form.take();
        h2.h2_headers_ws = complete.h2_headers_ws.take();

        let mut tls_and_runtime = UserAgentProfileInput::new(user_agent.clone());
        #[cfg(feature = "tls")]
        {
            tls_and_runtime.tls_client_hello = complete.tls_client_hello.take();
            tls_and_runtime.tls_ws_client_config_overwrites =
                complete.tls_ws_client_config_overwrites.take();
        }
        tls_and_runtime.js_web_apis = complete.js_web_apis.take();
        tls_and_runtime.source_info = complete.source_info.take();

        let encoded = serde_json::to_vec(&[h1, h2, tls_and_runtime]).unwrap();
        let profiles = try_load_profiles_json(&encoded).unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].ua_str(), Some(user_agent.as_str()));
    }

    #[test]
    fn profile_loader_rejects_incomplete_capture_without_polyfilling() {
        let user_agent =
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/149.0.0.0 Safari/537.36";
        let mut row = UserAgentProfileInput::new(user_agent);
        row.h1_settings = Some(Http1Settings::default());
        row.h1_headers_navigate = Some(HeaderMap::new());

        let error = try_load_profiles_json(&serde_json::to_vec(&[row]).unwrap()).unwrap_err();
        assert!(error.to_string().contains("h2_settings"));
    }
}
