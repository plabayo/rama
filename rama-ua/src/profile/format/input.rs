use std::{collections::BTreeMap, sync::Arc};

use rama_core::error::BoxError;
use rama_http::HeaderMap;
use rama_utils::octets::kib;
use serde::{Deserialize, Serialize};

use crate::UserAgent;
use crate::profile::format::archive::read_bounded_profile_rows;
#[cfg(feature = "embed-profiles")]
use crate::profile::format::compressed::try_load_compressed_profiles;
#[cfg(feature = "tls")]
use crate::profile::model::tls::WsClientConfigOverwrites;
use crate::profile::{
    analysis::profile::ProfileAnalysisLimits,
    format::{
        archive::{ProfileArchiveLimits, load_recorded_profile_archive_snapshot},
        canonical::ProfileDataError,
        legacy::LegacyFieldCapture,
    },
    model::{
        http::{Http1Settings, Http2Settings},
        identity::ProfileKey,
        js::{JsProfile, JsProfileWebApis},
        ua::{UserAgentProfile, UserAgentRuntimeProfile, UserAgentSourceInfo},
    },
};

/// Load the profiles embedded with the rama-ua crate.
///
/// The embedded file is a zstd-compressed archive of collected observations;
/// the profiles are recomputed from them on load.
/// This function is only available if the `embed-profiles` feature is enabled.
#[cfg(feature = "embed-profiles")]
#[cfg_attr(docsrs, doc(cfg(feature = "embed-profiles")))]
pub fn try_load_embedded_profiles() -> Result<impl Iterator<Item = UserAgentProfile>, BoxError> {
    Ok(try_load_compressed_profiles(include_bytes!("embed_profiles.json.zst"))?.into_iter())
}

/// Load a JSON array of captured user-agent profile rows.
///
/// Legacy rows with the same User-Agent fill only previously absent fields and are
/// converted into captured profiles. Archives load exactly as they were on the day they
/// were exported. No embedded or synthetic data fills missing components.
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
            load_recorded_profile_archive_snapshot(bytes, ProfileArchiveLimits::default())?
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

    /// Convert the row into a captured profile that can be emulated.
    ///
    /// Each recorded header set becomes a request flow and the H2 settings and TLS
    /// ClientHello become connection observations. Nothing unrecorded is synthesized.
    pub fn try_into_profile(self) -> Result<UserAgentProfile, BoxError> {
        let key = ProfileKey::from_user_agent(&UserAgent::new(self.uastr.clone()));
        key.canonical(kib(16))?;
        #[cfg(feature = "tls")]
        if self.tls_client_hello.is_none() && self.tls_ws_client_config_overwrites.is_some() {
            return Err(ProfileDataError::Incomplete(
                "WebSocket TLS overrides without ClientHello",
            )
            .into());
        }
        let mut profile =
            match LegacyFieldCapture::analyze_row(&self, ProfileAnalysisLimits::default())? {
                Some(captured) => UserAgentProfile::from_captured(captured),
                None => UserAgentProfile::new(key),
            };
        if self.js_web_apis.is_some() || self.source_info.is_some() {
            profile.runtime = Some(Arc::new(UserAgentRuntimeProfile {
                js_info: self.js_web_apis.map(|web_apis| JsProfile {
                    web_apis: Some(web_apis),
                }),
                source_info: self.source_info,
            }));
        }
        Ok(profile)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::model::{identity::FlowKey, runtime_hints::RequestInitiator};
    #[cfg(feature = "embed-profiles")]
    use crate::{UserAgentKind, profile::format::compressed::CompressedProfileArchiveWriter};
    use rama_http::Version;
    #[cfg(feature = "tls")]
    use rama_tls::{
        CipherSuite, CompressionAlgorithm, ProtocolVersion,
        client::{ClientHello, ClientHelloExtension},
    };
    #[cfg(feature = "embed-profiles")]
    use std::io::Write as _;

    #[cfg(feature = "embed-profiles")]
    fn compress(bytes: &[u8]) -> Vec<u8> {
        let mut writer = CompressedProfileArchiveWriter::new(Vec::new()).unwrap();
        writer.write_all(bytes).unwrap();
        writer.finish().unwrap()
    }

    #[cfg(feature = "tls")]
    fn client_hello() -> ClientHello {
        ClientHello::new(
            ProtocolVersion::TLSv1_2,
            vec![CipherSuite::from(0x1301)],
            vec![CompressionAlgorithm::from(0)],
            vec![ClientHelloExtension::SupportedVersions(vec![
                ProtocolVersion::TLSv1_3,
            ])],
        )
    }

    #[cfg(feature = "embed-profiles")]
    #[test]
    fn embedded_profiles_are_counted_archive_captures_including_h3_and_quic() {
        let profiles: Vec<_> = try_load_embedded_profiles().unwrap().collect();
        assert!(profiles.iter().all(|profile| profile.captured.is_some()));
        assert!(profiles.iter().any(|profile| {
            let components = &profile.captured.as_ref().unwrap().components;
            profile.ua_kind == Some(UserAgentKind::Firefox)
                && components.h3.is_some()
                && components.tls_quic.is_some()
                && components.quic.is_some()
        }));
    }

    #[test]
    fn profile_loader_merges_only_observed_rows_for_the_same_user_agent() {
        let user_agent = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0";
        let mut h1 = UserAgentProfileInput::new(user_agent);
        h1.h1_settings = Some(Http1Settings {
            title_case_headers: false,
        });
        h1.h1_headers_navigate = Some(HeaderMap::new());
        let mut h2 = UserAgentProfileInput::new(user_agent);
        h2.h2_headers_navigate = Some(HeaderMap::new());
        #[cfg_attr(not(feature = "tls"), expect(unused_mut))]
        let mut tls = UserAgentProfileInput::new(user_agent);
        #[cfg(feature = "tls")]
        {
            tls.tls_client_hello = Some(client_hello());
        }

        let encoded = serde_json::to_vec(&[h1, h2, tls]).unwrap();
        let profiles = try_load_profiles_json(&encoded).unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].ua_str(), Some(user_agent));
        let capabilities = profiles[0].capabilities();
        assert!(capabilities.h1 && capabilities.h2);
        #[cfg(feature = "tls")]
        assert!(capabilities.tls_tcp);
        #[cfg(feature = "embed-profiles")]
        {
            let compressed = try_load_compressed_profiles(&compress(&encoded)).unwrap();
            assert_eq!(compressed.len(), 1);
            assert_eq!(compressed[0].ua_str(), Some(user_agent));
        }
    }

    #[test]
    fn partial_library_profiles_preserve_only_observed_components() {
        let mut row = UserAgentProfileInput::new("example-library/1.2");
        row.h2_headers_fetch = Some(HeaderMap::new());
        let profile = row.try_into_profile().unwrap();
        assert_eq!(profile.ua_str(), Some("example-library/1.2"));
        assert!(profile.ua_kind.is_none());
        let capabilities = profile.capabilities();
        assert!(!capabilities.h1 && capabilities.h2 && !capabilities.tls_tcp);
        let flows = profile
            .captured
            .as_ref()
            .unwrap()
            .scopes
            .iter()
            .filter_map(|scope| scope.flow.clone())
            .collect::<Vec<_>>();
        assert!(!flows.is_empty());
        assert!(flows.iter().all(|flow| matches!(
            flow,
            FlowKey::Http {
                version: Version::HTTP_2,
                initiator: Some(RequestInitiator::Fetch),
                ..
            }
        )));
    }

    #[test]
    fn metadata_only_profile_has_no_synthetic_protocol_components() {
        let profile = UserAgentProfileInput::new("metadata-only")
            .try_into_profile()
            .unwrap();
        assert!(profile.captured.is_none());
    }

    #[test]
    fn embedded_and_custom_loaders_keep_partial_profiles() {
        let mut row = UserAgentProfileInput::new("partial-library");
        row.h1_settings = Some(Http1Settings {
            title_case_headers: true,
        });
        let bytes = serde_json::to_vec(&[row]).unwrap();
        #[cfg_attr(not(feature = "embed-profiles"), expect(unused_mut))]
        let mut loaded = vec![try_load_profiles_json(&bytes).unwrap()];
        #[cfg(feature = "embed-profiles")]
        loaded.push(try_load_compressed_profiles(&compress(&bytes)).unwrap());
        for profiles in loaded {
            assert_eq!(profiles.len(), 1);
            let capabilities = profiles[0].capabilities();
            assert!(capabilities.h1 && !capabilities.h2);
            // Settings alone form no request flow.
            assert!(
                profiles[0]
                    .captured
                    .as_ref()
                    .unwrap()
                    .scopes
                    .iter()
                    .all(|scope| scope.flow.is_none())
            );
        }
        #[cfg(feature = "embed-profiles")]
        {
            try_load_compressed_profiles(&compress(b"[]")).unwrap_err();
            try_load_compressed_profiles(&compress(b"[")).unwrap_err();
        }
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
}
