use std::{collections::BTreeMap, fmt, sync::Arc};

use rama_core::error::{BoxError, ErrorContext as _};
use rama_http::HeaderMap;
use serde::{Deserialize, Serialize};

use crate::{profile::*, *};

/// Load the profiles embedded with the rama-ua crate.
///
/// Complementary captures are merged before incomplete profiles are skipped with
/// a warning. Malformed data and bundles with no usable profiles remain errors.
/// This function is only available if the `embed-profiles` feature is enabled.
#[cfg(feature = "embed-profiles")]
#[cfg_attr(docsrs, doc(cfg(feature = "embed-profiles")))]
pub fn try_load_embedded_profiles() -> Result<impl Iterator<Item = UserAgentProfile>, BoxError> {
    Ok(load_embedded_profiles(include_bytes!("embed_profiles.json"))?.into_iter())
}

#[cfg(feature = "embed-profiles")]
fn load_embedded_profiles(bytes: &[u8]) -> Result<Vec<UserAgentProfile>, BoxError> {
    let mut profiles = Vec::new();
    for row in parse_profile_rows(bytes)? {
        match row.try_into_profile() {
            Ok(profile) => profiles.push(profile),
            Err(error) if error.is::<IncompleteProfile>() => {
                rama_core::telemetry::tracing::warn!(%error, "skip incomplete embedded user-agent profile");
            }
            Err(error) => return Err(error),
        }
    }
    if profiles.is_empty() {
        return Err("embedded user-agent database has no usable profiles".into());
    }
    Ok(profiles)
}

/// Load a JSON array of captured user-agent profile rows.
///
/// Rows with the same User-Agent are merged by filling fields that were not
/// observed in another row. The resulting database remains strict: every
/// merged profile must contain the HTTP/1, HTTP/2 and TLS components required
/// by [`UserAgentProfile`]. No embedded or synthetic data is used to fill gaps.
pub fn try_load_profiles_json(bytes: &[u8]) -> Result<Vec<UserAgentProfile>, BoxError> {
    parse_profile_rows(bytes)?
        .into_iter()
        .map(UserAgentProfileInput::try_into_profile)
        .collect()
}

fn parse_profile_rows(bytes: &[u8]) -> Result<Vec<UserAgentProfileInput>, BoxError> {
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
    Ok(profiles)
}

#[derive(Debug)]
struct IncompleteProfile {
    user_agent: String,
    field: &'static str,
}

impl fmt::Display for IncompleteProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "user-agent profile '{}' is missing {}",
            self.user_agent, self.field
        )
    }
}

impl std::error::Error for IncompleteProfile {}

#[derive(Debug, Clone, Deserialize, Serialize)]
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

    /// Validate captured fields and move them into a complete emulation profile.
    /// This uses the same validation as JSON database loading, without encoding
    /// or parsing JSON and without cloning the captured header maps.
    pub fn try_into_profile(self) -> Result<UserAgentProfile, BoxError> {
        let ua = UserAgent::new(self.uastr);
        let missing = |field| IncompleteProfile {
            user_agent: ua.header_str().to_owned(),
            field,
        };
        Ok(UserAgentProfile {
            ua_kind: ua.ua_kind().ok_or_else(|| {
                format!("unrecognized User-Agent in profile '{}'", ua.header_str())
            })?,
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

#[cfg(all(test, feature = "embed-profiles"))]
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
        let embedded = load_embedded_profiles(&encoded).unwrap();
        assert_eq!(embedded.len(), 1);
        assert_eq!(embedded[0].ua_str(), Some(user_agent.as_str()));
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

    fn complete_row() -> Result<serde_json::Value, BoxError> {
        let rows: Vec<serde_json::Value> =
            serde_json::from_slice(include_bytes!("embed_profiles.json"))?;
        for row in rows {
            if serde_json::from_value::<UserAgentProfileInput>(row.clone())?
                .try_into_profile()
                .is_ok()
            {
                return Ok(row);
            }
        }
        Err("embedded fixtures contain no complete profile".into())
    }

    #[test]
    fn embedded_skips_incomplete_profiles_while_custom_imports_remain_strict() {
        let complete = complete_row().unwrap();
        let fields = [
            "h1_settings",
            "h1_headers_navigate",
            "h2_settings",
            "h2_headers_navigate",
            #[cfg(feature = "tls")]
            "tls_client_hello",
        ];
        for field in fields {
            let mut incomplete = complete.clone();
            incomplete["uastr"] = serde_json::json!(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/999.0.0.0 Safari/537.36"
            );
            incomplete[field] = serde_json::Value::Null;
            let bytes = serde_json::to_vec(&[&incomplete, &complete]).unwrap();
            let profiles = load_embedded_profiles(&bytes).unwrap();
            assert_eq!(profiles.len(), 1, "{field}");
            assert_eq!(profiles[0].ua_str(), complete["uastr"].as_str());
            let error = try_load_profiles_json(&bytes).unwrap_err();
            assert_eq!(
                error.downcast_ref::<IncompleteProfile>().unwrap().field,
                field
            );
            let bytes = serde_json::to_vec(&[incomplete]).unwrap();
            assert!(
                load_embedded_profiles(&bytes)
                    .unwrap_err()
                    .to_string()
                    .contains("no usable profiles")
            );
        }
        assert!(
            load_embedded_profiles(b"[]")
                .unwrap_err()
                .to_string()
                .contains("no usable profiles")
        );
    }

    #[test]
    fn embedded_does_not_hide_malformed_or_unsupported_profiles() {
        load_embedded_profiles(b"[").unwrap_err();
        let complete = complete_row().unwrap();
        for (field, value) in [
            ("h2_settings", serde_json::json!("invalid settings")),
            (
                "h1_headers_navigate",
                serde_json::json!([["invalid header name", "value"]]),
            ),
            ("uastr", serde_json::json!("unknown-browser")),
        ] {
            let mut invalid = complete.clone();
            invalid[field] = value;
            let bytes = serde_json::to_vec(&[&complete, &invalid]).unwrap();
            assert!(load_embedded_profiles(&bytes).is_err(), "{field}");
            assert!(try_load_profiles_json(&bytes).is_err(), "{field}");
        }
    }
}
