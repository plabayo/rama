use std::{collections::BTreeMap, sync::Arc};

use rama_core::error::BoxError;
use rama_http::HeaderMap;
use rama_utils::octets::kib;
use serde::{Deserialize, Serialize};

use crate::UserAgent;
use crate::profile::format::archive::read_bounded_profile_rows;
#[cfg(feature = "tls")]
use crate::profile::model::tls::{TlsProfile, WsClientConfigOverwrites};
use crate::profile::{
    format::{
        archive::{ProfileArchiveLimits, load_profile_archive_snapshot},
        canonical::ProfileDataError,
    },
    model::{
        http::{
            Http1Profile, Http1Settings, Http2Profile, Http2Settings, HttpHeadersProfile,
            HttpProfile,
        },
        identity::ProfileKey,
        js::{JsProfile, JsProfileWebApis},
        ua::{UserAgentProfile, UserAgentRuntimeProfile, UserAgentSourceInfo},
    },
};

/// Load the profiles embedded with the rama-ua crate.
///
/// Complementary captures are merged without synthesizing absent components.
/// Malformed data and empty bundles remain errors.
/// This function is only available if the `embed-profiles` feature is enabled.
#[cfg(feature = "embed-profiles")]
#[cfg_attr(docsrs, doc(cfg(feature = "embed-profiles")))]
pub fn try_load_embedded_profiles() -> Result<impl Iterator<Item = UserAgentProfile>, BoxError> {
    Ok(load_embedded_profiles(include_bytes!("embed_profiles.json"))?.into_iter())
}

#[cfg(feature = "embed-profiles")]
fn load_embedded_profiles(bytes: &[u8]) -> Result<Vec<UserAgentProfile>, BoxError> {
    let profiles = try_load_profiles_json(bytes)?;
    if profiles.is_empty() {
        return Err("embedded user-agent database has no usable profiles".into());
    }
    Ok(profiles)
}

/// Load a JSON array of captured user-agent profile rows.
///
/// Legacy rows with the same User-Agent fill only previously absent fields.
/// Versioned archives reproduce their recorded public snapshot. No embedded
/// or synthetic data fills missing components.
pub fn try_load_profiles_json(bytes: &[u8]) -> Result<Vec<UserAgentProfile>, BoxError> {
    if bytes.len() > ProfileArchiveLimits::default().bytes {
        return Err(ProfileDataError::LimitExceeded("profile input bytes").into());
    }
    if bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        == Some(b'{')
    {
        return Ok(
            load_profile_archive_snapshot(bytes, false, ProfileArchiveLimits::default())?
                .into_vec()
                .into_iter()
                .map(|entry| UserAgentProfile::from_captured(entry.analysis))
                .collect(),
        );
    }
    parse_profile_rows(bytes)?
        .into_iter()
        .map(UserAgentProfileInput::try_into_profile)
        .collect()
}

fn parse_profile_rows(bytes: &[u8]) -> Result<Vec<UserAgentProfileInput>, BoxError> {
    let rows: Vec<UserAgentProfileInput> =
        read_bounded_profile_rows(bytes, ProfileArchiveLimits::default().profiles)?;
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

    /// Validate captured fields and retain their observed protocol components.
    /// This uses the same validation as JSON database loading, without encoding
    /// or parsing JSON and without cloning the captured header maps.
    pub fn try_into_profile(self) -> Result<UserAgentProfile, BoxError> {
        let ua = UserAgent::new(self.uastr);
        let key = ProfileKey::from_user_agent(&ua);
        key.canonical(kib(16))?;
        let mut profile = UserAgentProfile::new(key);
        let h1 = (self.h1_settings.is_some()
            || self.h1_headers_navigate.is_some()
            || self.h1_headers_fetch.is_some()
            || self.h1_headers_xhr.is_some()
            || self.h1_headers_form.is_some()
            || self.h1_headers_ws.is_some())
        .then(|| Http1Profile {
            settings: self.h1_settings,
            headers: HttpHeadersProfile {
                navigate: self.h1_headers_navigate,
                fetch: self.h1_headers_fetch,
                xhr: self.h1_headers_xhr,
                form: self.h1_headers_form,
                ws: self.h1_headers_ws,
            },
        });
        let h2 = (self.h2_settings.is_some()
            || self.h2_headers_navigate.is_some()
            || self.h2_headers_fetch.is_some()
            || self.h2_headers_xhr.is_some()
            || self.h2_headers_form.is_some()
            || self.h2_headers_ws.is_some())
        .then(|| Http2Profile {
            settings: self.h2_settings,
            headers: HttpHeadersProfile {
                navigate: self.h2_headers_navigate,
                fetch: self.h2_headers_fetch,
                xhr: self.h2_headers_xhr,
                form: self.h2_headers_form,
                ws: self.h2_headers_ws,
            },
        });
        if h1.is_some() || h2.is_some() {
            profile.http = Some(Arc::new(HttpProfile { h1, h2 }));
        }

        #[cfg(feature = "tls")]
        {
            if self.tls_client_hello.is_none() && self.tls_ws_client_config_overwrites.is_some() {
                return Err(ProfileDataError::Incomplete(
                    "WebSocket TLS overrides without ClientHello",
                )
                .into());
            }
            profile.tls = self.tls_client_hello.map(|client_hello| {
                Arc::new(TlsProfile {
                    client_hello,
                    permute_extensions: profile.ua_kind.is_some_and(|kind| {
                        TlsProfile::user_agent_permutes_extensions(
                            kind,
                            profile.ua_version,
                            profile.platform,
                        )
                    }),
                    ws_client_config_overwrites: self.tls_ws_client_config_overwrites,
                })
            });
        }
        profile.runtime = match (&self.js_web_apis, &self.source_info) {
            (Some(_), _) | (_, Some(_)) => Some(Arc::new(UserAgentRuntimeProfile {
                js_info: self.js_web_apis.map(|web_apis| JsProfile {
                    web_apis: Some(web_apis),
                }),
                source_info: self.source_info,
            })),
            _ => None,
        };
        Ok(profile)
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
    fn partial_library_profiles_preserve_only_observed_components() {
        let mut row = UserAgentProfileInput::new("example-library/1.2");
        row.h2_headers_fetch = Some(HeaderMap::new());
        let profile = row.try_into_profile().unwrap();
        assert_eq!(profile.ua_str(), Some("example-library/1.2"));
        assert!(profile.ua_kind.is_none());
        assert!(profile.http.as_ref().unwrap().h1.is_none());
        let h2 = profile.http.as_ref().unwrap().h2.as_ref().unwrap();
        assert!(h2.settings.is_none());
        assert!(h2.headers.navigate.is_none());
        assert!(h2.headers.fetch.is_some());
        #[cfg(feature = "tls")]
        assert!(profile.tls.is_none());
    }

    #[test]
    fn metadata_only_profile_has_no_synthetic_protocol_components() {
        let profile = UserAgentProfileInput::new("metadata-only")
            .try_into_profile()
            .unwrap();
        assert!(profile.http.is_none());
        assert!(profile.captured.is_none());
        #[cfg(feature = "tls")]
        assert!(profile.tls.is_none());
    }

    #[test]
    fn embedded_and_custom_loaders_keep_partial_profiles() {
        let mut row = UserAgentProfileInput::new("partial-library");
        row.h1_settings = Some(Http1Settings {
            title_case_headers: true,
        });
        let bytes = serde_json::to_vec(&[row]).unwrap();
        for profiles in [
            load_embedded_profiles(&bytes).unwrap(),
            try_load_profiles_json(&bytes).unwrap(),
        ] {
            assert_eq!(profiles.len(), 1);
            let http = profiles[0].http.as_ref().unwrap();
            let h1 = http.h1.as_ref().unwrap();
            assert!(h1.settings.as_ref().unwrap().title_case_headers);
            assert!(h1.headers.navigate.is_none());
            assert!(http.h2.is_none());
        }
        load_embedded_profiles(b"[]").unwrap_err();
        load_embedded_profiles(b"[").unwrap_err();
        try_load_profiles_json(br#"[{"uastr":"library","h1_settings":"invalid"}]"#).unwrap_err();
    }

    #[cfg(feature = "tls")]
    #[test]
    fn websocket_tls_overrides_require_their_observed_client_hello() {
        let mut row = UserAgentProfileInput::new("library/1.2");
        row.tls_ws_client_config_overwrites = Some(WsClientConfigOverwrites { alpn: None });
        let error = row.try_into_profile().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("WebSocket TLS overrides without ClientHello")
        );
    }

    #[test]
    fn imported_and_live_headers_have_the_same_profile_identity() {
        for header in ["example-library/1.2", "Mozilla/5.0 Firefox/135.0"] {
            let imported = UserAgentProfileInput::new(header)
                .try_into_profile()
                .unwrap();
            let live = ProfileKey::from_user_agent(&UserAgent::new(header));
            assert_eq!(
                imported.key.canonical(kib(16)).unwrap().bytes,
                live.canonical(kib(16)).unwrap().bytes
            );
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn legacy_rows_preserve_the_existing_permutation_default() {
        let rows: Vec<UserAgentProfileInput> =
            serde_json::from_slice(include_bytes!("embed_profiles.json")).unwrap();
        for row in rows {
            let profile = row.try_into_profile().unwrap();
            let tls = profile.tls.as_ref().unwrap();
            let expected = profile.ua_kind.is_some_and(|kind| {
                TlsProfile::user_agent_permutes_extensions(
                    kind,
                    profile.ua_version,
                    profile.platform,
                )
            });
            assert_eq!(tls.permute_extensions, expected);
        }
    }
}
