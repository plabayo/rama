//! Stable client and flow identities without a browser or mandatory HTTP component.

use std::str;

use rama_http::{HeaderMap, Method, Version};
use serde::{Deserialize, Serialize};

use crate::{DeviceKind, PlatformKind, UserAgent};

use super::{
    CanonicalValue, ProfileDataError, RequestInitiator,
    canonical::{CanonicalReader, CanonicalWriter, FLOW_DOMAIN, PROFILE_DOMAIN},
};

/// A client can be an application or library, with no User-Agent header at all.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileKey {
    pub client: Box<str>,
    pub version: Option<Box<str>>,
    pub platform: Option<PlatformKind>,
    pub device: Option<DeviceKind>,
    pub user_agent: Option<Box<str>>,
}

impl ProfileKey {
    pub fn new(client: impl Into<Box<str>>) -> Self {
        Self {
            client: client.into(),
            version: None,
            platform: None,
            device: None,
            user_agent: None,
        }
    }

    /// Derive the same identity for live, imported and offline HTTP observations.
    /// Unrecognized clients retain their exact header as the client name.
    pub fn from_user_agent(user_agent: &UserAgent) -> Self {
        Self {
            client: user_agent
                .ua_kind()
                .map_or(user_agent.header_str(), |kind| kind.as_str())
                .into(),
            version: user_agent
                .ua_version()
                .map(|version| version.to_string().into()),
            platform: user_agent.platform(),
            device: user_agent.device(),
            user_agent: Some(user_agent.header_str().into()),
        }
    }

    pub fn canonical(&self, maximum_bytes: usize) -> Result<CanonicalValue, ProfileDataError> {
        if self.client.is_empty() {
            return Err(ProfileDataError::Invalid("empty client identity"));
        }
        if let (Some(platform), Some(device)) = (self.platform, self.device)
            && platform.device() != device
        {
            return Err(ProfileDataError::Invalid(
                "inconsistent platform and device",
            ));
        }
        let mut writer = CanonicalWriter::new(PROFILE_DOMAIN, maximum_bytes)?;
        writer.bytes(self.client.as_bytes())?;
        optional_text(&mut writer, self.version.as_deref())?;
        writer.u8(match self.platform {
            None => 0,
            Some(PlatformKind::Windows) => 1,
            Some(PlatformKind::MacOS) => 2,
            Some(PlatformKind::Linux) => 3,
            Some(PlatformKind::Android) => 4,
            Some(PlatformKind::IOS) => 5,
        })?;
        writer.u8(match self.device {
            None => 0,
            Some(DeviceKind::Desktop) => 1,
            Some(DeviceKind::Mobile) => 2,
        })?;
        optional_text(&mut writer, self.user_agent.as_deref())?;
        Ok(writer.finish())
    }

    pub fn from_canonical(
        value: &CanonicalValue,
        maximum_bytes: usize,
    ) -> Result<Self, ProfileDataError> {
        value.verify(PROFILE_DOMAIN, maximum_bytes)?;
        let mut reader = CanonicalReader::new(&value.bytes, PROFILE_DOMAIN)?;
        let client = read_text(&mut reader, maximum_bytes)?;
        let version = read_optional_text(&mut reader, maximum_bytes)?;
        let platform = match reader.u8()? {
            0 => None,
            1 => Some(PlatformKind::Windows),
            2 => Some(PlatformKind::MacOS),
            3 => Some(PlatformKind::Linux),
            4 => Some(PlatformKind::Android),
            5 => Some(PlatformKind::IOS),
            _ => return Err(ProfileDataError::Invalid("platform tag")),
        };
        let device = match reader.u8()? {
            0 => None,
            1 => Some(DeviceKind::Desktop),
            2 => Some(DeviceKind::Mobile),
            _ => return Err(ProfileDataError::Invalid("device tag")),
        };
        let user_agent = read_optional_text(&mut reader, maximum_bytes)?;
        reader.finish()?;
        let key = Self {
            client,
            version,
            platform,
            device,
            user_agent,
        };
        if key.canonical(maximum_bytes)?.bytes != value.bytes {
            return Err(ProfileDataError::Invalid("noncanonical profile key"));
        }
        Ok(key)
    }
}

/// Unknown context is distinct from an observed fresh or resumed connection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResumptionContext {
    #[default]
    Unknown,
    Fresh,
    Resumed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionIpFamily {
    V4,
    V6,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionContext {
    pub resumption: ResumptionContext,
    pub early_data: Option<bool>,
    pub token_present: Option<bool>,
    pub ip_family: Option<ConnectionIpFamily>,
}

impl ConnectionContext {
    pub(super) fn encode(&self, writer: &mut CanonicalWriter) -> Result<(), ProfileDataError> {
        writer.u8(match self.resumption {
            ResumptionContext::Unknown => 0,
            ResumptionContext::Fresh => 1,
            ResumptionContext::Resumed => 2,
        })?;
        optional_bool(writer, self.early_data)?;
        optional_bool(writer, self.token_present)?;
        writer.u8(match self.ip_family {
            None => 0,
            Some(ConnectionIpFamily::V4) => 1,
            Some(ConnectionIpFamily::V6) => 2,
        })?;
        Ok(())
    }

    pub(super) fn decode(reader: &mut CanonicalReader<'_>) -> Result<Self, ProfileDataError> {
        let resumption = match reader.u8()? {
            0 => ResumptionContext::Unknown,
            1 => ResumptionContext::Fresh,
            2 => ResumptionContext::Resumed,
            _ => return Err(ProfileDataError::Invalid("resumption context tag")),
        };
        let early_data = read_optional_bool(reader)?;
        let token_present = read_optional_bool(reader)?;
        let ip_family = match reader.u8()? {
            0 => None,
            1 => Some(ConnectionIpFamily::V4),
            2 => Some(ConnectionIpFamily::V6),
            _ => return Err(ProfileDataError::Invalid("IP family tag")),
        };
        Ok(Self {
            resumption,
            early_data,
            token_present,
            ip_family,
        })
    }
}

/// Values and absence come from captures; selection does not synthesize Fetch metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FetchContext {
    pub mode: Option<Box<str>>,
    pub site: Option<Box<str>>,
    pub destination: Option<Box<str>>,
    pub user_activation: Option<Box<str>>,
}

impl FetchContext {
    /// Check the combined observed names and values before retaining any text.
    pub fn from_headers(
        headers: &HeaderMap,
        maximum_bytes: usize,
    ) -> Result<Option<Self>, ProfileDataError> {
        let mut remaining = maximum_bytes;
        let mut read = |name: &'static str| -> Result<Option<&str>, ProfileDataError> {
            let values = headers.get_all(name);
            let mut values = values.iter();
            let value = values.next();
            if values.next().is_some() {
                return Err(ProfileDataError::Invalid("duplicate Fetch context field"));
            }
            value
                .map(|value| {
                    remaining = remaining
                        .checked_sub(name.len())
                        .and_then(|n| n.checked_sub(value.len()))
                        .ok_or(ProfileDataError::LimitExceeded("Fetch context bytes"))?;
                    value
                        .to_str()
                        .map_err(|_error| ProfileDataError::Invalid("Fetch context value"))
                })
                .transpose()
        };
        let mode = read("sec-fetch-mode")?;
        let site = read("sec-fetch-site")?;
        let destination = read("sec-fetch-dest")?;
        let user_activation = read("sec-fetch-user")?;
        if mode.is_none() && site.is_none() && destination.is_none() && user_activation.is_none() {
            return Ok(None);
        }
        Ok(Some(Self {
            mode: mode.map(Box::from),
            site: site.map(Box::from),
            destination: destination.map(Box::from),
            user_activation: user_activation.map(Box::from),
        }))
    }
}

/// Non-browser HTTP requests have no initiator; non-HTTP clients use an explicit operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FlowKey {
    Http {
        version: Version,
        method: Method,
        initiator: Option<RequestInitiator>,
        fetch: Option<FetchContext>,
        connection: ConnectionContext,
    },
    Other {
        protocol: Box<str>,
        operation: Box<str>,
    },
}

impl FlowKey {
    pub fn canonical(&self, maximum_bytes: usize) -> Result<CanonicalValue, ProfileDataError> {
        let mut writer = CanonicalWriter::new(FLOW_DOMAIN, maximum_bytes)?;
        match self {
            Self::Http {
                version,
                method,
                initiator,
                fetch,
                connection,
            } => {
                writer.u8(0)?;
                writer.u8(match *version {
                    Version::HTTP_09 => 0,
                    Version::HTTP_10 => 1,
                    Version::HTTP_11 => 2,
                    Version::HTTP_2 => 3,
                    Version::HTTP_3 => 4,
                })?;
                writer.bytes(method.as_str().as_bytes())?;
                writer.u8(match initiator {
                    None => 0,
                    Some(RequestInitiator::Navigate) => 1,
                    Some(RequestInitiator::Form) => 2,
                    Some(RequestInitiator::Xhr) => 3,
                    Some(RequestInitiator::Fetch) => 4,
                    Some(RequestInitiator::Ws) => 5,
                })?;
                match fetch {
                    None => writer.u8(0)?,
                    Some(fetch) => {
                        writer.u8(1)?;
                        optional_text(&mut writer, fetch.mode.as_deref())?;
                        optional_text(&mut writer, fetch.site.as_deref())?;
                        optional_text(&mut writer, fetch.destination.as_deref())?;
                        optional_text(&mut writer, fetch.user_activation.as_deref())?;
                    }
                }
                connection.encode(&mut writer)?;
            }
            Self::Other {
                protocol,
                operation,
            } => {
                if protocol.is_empty() || operation.is_empty() {
                    return Err(ProfileDataError::Invalid("empty protocol or operation"));
                }
                writer.u8(1)?;
                writer.bytes(protocol.as_bytes())?;
                writer.bytes(operation.as_bytes())?;
            }
        }
        Ok(writer.finish())
    }

    pub fn from_canonical(
        value: &CanonicalValue,
        maximum_bytes: usize,
    ) -> Result<Self, ProfileDataError> {
        value.verify(FLOW_DOMAIN, maximum_bytes)?;
        let mut reader = CanonicalReader::new(&value.bytes, FLOW_DOMAIN)?;
        let key = match reader.u8()? {
            0 => {
                let version = match reader.u8()? {
                    0 => Version::HTTP_09,
                    1 => Version::HTTP_10,
                    2 => Version::HTTP_11,
                    3 => Version::HTTP_2,
                    4 => Version::HTTP_3,
                    _ => return Err(ProfileDataError::Invalid("HTTP version tag")),
                };
                let method = Method::from_bytes(reader.bytes(maximum_bytes)?)
                    .map_err(|_error| ProfileDataError::Invalid("HTTP method"))?;
                let initiator = match reader.u8()? {
                    0 => None,
                    1 => Some(RequestInitiator::Navigate),
                    2 => Some(RequestInitiator::Form),
                    3 => Some(RequestInitiator::Xhr),
                    4 => Some(RequestInitiator::Fetch),
                    5 => Some(RequestInitiator::Ws),
                    _ => return Err(ProfileDataError::Invalid("request initiator tag")),
                };
                let fetch = match reader.u8()? {
                    0 => None,
                    1 => Some(FetchContext {
                        mode: read_optional_text(&mut reader, maximum_bytes)?,
                        site: read_optional_text(&mut reader, maximum_bytes)?,
                        destination: read_optional_text(&mut reader, maximum_bytes)?,
                        user_activation: read_optional_text(&mut reader, maximum_bytes)?,
                    }),
                    _ => return Err(ProfileDataError::Invalid("Fetch context tag")),
                };
                let connection = ConnectionContext::decode(&mut reader)?;
                Self::Http {
                    version,
                    method,
                    initiator,
                    fetch,
                    connection,
                }
            }
            1 => Self::Other {
                protocol: read_text(&mut reader, maximum_bytes)?,
                operation: read_text(&mut reader, maximum_bytes)?,
            },
            _ => return Err(ProfileDataError::Invalid("flow tag")),
        };
        reader.finish()?;
        if key.canonical(maximum_bytes)?.bytes != value.bytes {
            return Err(ProfileDataError::Invalid("noncanonical flow key"));
        }
        Ok(key)
    }
}

fn optional_text(
    writer: &mut CanonicalWriter,
    value: Option<&str>,
) -> Result<(), ProfileDataError> {
    match value {
        Some(value) => {
            writer.u8(1)?;
            writer.bytes(value.as_bytes())
        }
        None => writer.u8(0),
    }
}

fn optional_bool(
    writer: &mut CanonicalWriter,
    value: Option<bool>,
) -> Result<(), ProfileDataError> {
    writer.u8(match value {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    })
}

fn read_text(
    reader: &mut CanonicalReader<'_>,
    maximum: usize,
) -> Result<Box<str>, ProfileDataError> {
    str::from_utf8(reader.bytes(maximum)?)
        .map(Box::from)
        .map_err(|_error| ProfileDataError::Invalid("canonical text"))
}

fn read_optional_text(
    reader: &mut CanonicalReader<'_>,
    maximum: usize,
) -> Result<Option<Box<str>>, ProfileDataError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => read_text(reader, maximum).map(Some),
        _ => Err(ProfileDataError::Invalid("optional text tag")),
    }
}

fn read_optional_bool(reader: &mut CanonicalReader<'_>) -> Result<Option<bool>, ProfileDataError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(false)),
        2 => Ok(Some(true)),
        _ => Err(ProfileDataError::Invalid("optional boolean tag")),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use rama_utils::octets::kib;
    use sha2::{Digest as _, Sha256};

    use crate::profile::ValueId;

    use super::*;

    #[test]
    fn profile_identity_accepts_application_only_and_preserves_absence() {
        let mut key = ProfileKey::new("application");
        let absent = key.canonical(kib(4)).unwrap();
        assert_eq!(
            ProfileKey::from_canonical(&absent, kib(4))
                .unwrap()
                .canonical(kib(4))
                .unwrap()
                .id,
            absent.id
        );
        key.user_agent = Some("".into());
        assert_ne!(absent.id, key.canonical(kib(4)).unwrap().id);
        key.user_agent = None;
        assert_eq!(absent.id, key.canonical(kib(4)).unwrap().id);
        key.platform = Some(PlatformKind::IOS);
        key.device = Some(DeviceKind::Desktop);
        key.canonical(kib(4)).unwrap_err();
    }

    #[test]
    fn flow_identity_preserves_protocol_initiator_and_context() {
        let mut ids = BTreeSet::new();
        for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
            for initiator in [
                None,
                Some(RequestInitiator::Navigate),
                Some(RequestInitiator::Fetch),
                Some(RequestInitiator::Xhr),
                Some(RequestInitiator::Form),
                Some(RequestInitiator::Ws),
            ] {
                for resumption in [
                    ResumptionContext::Unknown,
                    ResumptionContext::Fresh,
                    ResumptionContext::Resumed,
                ] {
                    let flow = FlowKey::Http {
                        version,
                        method: Method::GET,
                        initiator,
                        fetch: None,
                        connection: ConnectionContext {
                            resumption,
                            ..ConnectionContext::default()
                        },
                    };
                    let value = flow.canonical(kib(4)).unwrap();
                    assert!(ids.insert(value.id));
                    assert_eq!(
                        FlowKey::from_canonical(&value, kib(4))
                            .unwrap()
                            .canonical(kib(4))
                            .unwrap()
                            .id,
                        value.id
                    );
                    let restored: FlowKey =
                        serde_json::from_slice(&serde_json::to_vec(&flow).unwrap()).unwrap();
                    assert_eq!(restored.canonical(kib(4)).unwrap().id, value.id);
                }
            }
        }
        assert_eq!(ids.len(), 54);
        let non_http = FlowKey::Other {
            protocol: "custom".into(),
            operation: "exchange".into(),
        };
        let value = non_http.canonical(kib(4)).unwrap();
        assert!(ids.insert(value.id));
        assert_eq!(
            FlowKey::from_canonical(&value, kib(4))
                .unwrap()
                .canonical(kib(4))
                .unwrap()
                .id,
            value.id
        );
    }

    #[test]
    fn fetch_context_keeps_observed_omission() {
        assert!(
            FetchContext::from_headers(&HeaderMap::new(), 0)
                .unwrap()
                .is_none()
        );
        let mut headers = HeaderMap::new();
        headers.insert("sec-fetch-mode", "navigate".parse().unwrap());
        let context = FetchContext::from_headers(&headers, kib(4))
            .unwrap()
            .unwrap();
        assert_eq!(context.mode.as_deref(), Some("navigate"));
        assert!(context.user_activation.is_none());
        FetchContext::from_headers(&headers, "sec-fetch-mode".len() + "navigate".len()).unwrap();
        FetchContext::from_headers(&headers, "sec-fetch-mode".len() + "navigate".len() - 1)
            .unwrap_err();
        headers.insert("sec-fetch-site", "none".parse().unwrap());
        let total =
            "sec-fetch-mode".len() + "navigate".len() + "sec-fetch-site".len() + "none".len();
        FetchContext::from_headers(&headers, total).unwrap();
        FetchContext::from_headers(&headers, total - 1).unwrap_err();
        headers.append("sec-fetch-mode", "cors".parse().unwrap());
        FetchContext::from_headers(&headers, kib(4)).unwrap_err();
    }

    #[test]
    fn identity_golden_vectors_reject_truncation_and_oversized_input() {
        let profile = ProfileKey::new("app").canonical(kib(4)).unwrap();
        let flow = FlowKey::Other {
            protocol: "dns".into(),
            operation: "query".into(),
        }
        .canonical(kib(4))
        .unwrap();
        assert_eq!(
            profile.bytes.as_ref(),
            &[
                114, 97, 109, 97, 45, 112, 114, 111, 102, 105, 108, 101, 0, 0, 1, 0, 2, 0, 0, 0, 0,
                0, 0, 0, 3, 97, 112, 112, 0, 0, 0, 0
            ]
        );
        assert_eq!(
            profile.id.0,
            [
                237, 1, 86, 142, 161, 121, 123, 238, 236, 230, 29, 117, 228, 170, 235, 30, 172,
                223, 211, 94, 81, 203, 196, 103, 173, 109, 166, 45, 227, 244, 10, 64
            ]
        );
        assert_eq!(
            flow.bytes.as_ref(),
            &[
                114, 97, 109, 97, 45, 112, 114, 111, 102, 105, 108, 101, 0, 0, 1, 0, 3, 1, 0, 0, 0,
                0, 0, 0, 0, 3, 100, 110, 115, 0, 0, 0, 0, 0, 0, 0, 5, 113, 117, 101, 114, 121
            ]
        );
        assert_eq!(
            flow.id.0,
            [
                53, 241, 37, 255, 172, 47, 42, 125, 175, 17, 139, 216, 107, 155, 25, 229, 247, 95,
                173, 238, 202, 72, 46, 20, 119, 45, 22, 190, 223, 36, 12, 32
            ]
        );
        for value in [&profile, &flow] {
            for length in 0..value.bytes.len() {
                let bytes: Box<[u8]> = value.bytes[..length].into();
                let truncated = CanonicalValue {
                    id: ValueId(Sha256::digest(&bytes).into()),
                    bytes,
                };
                ProfileKey::from_canonical(&truncated, kib(4)).unwrap_err();
                FlowKey::from_canonical(&truncated, kib(4)).unwrap_err();
            }
        }
        ProfileKey::new("app")
            .canonical(profile.bytes.len() - 1)
            .unwrap_err();
        ProfileKey::from_canonical(&profile, profile.bytes.len() - 1).unwrap_err();
        FlowKey::from_canonical(&flow, flow.bytes.len() - 1).unwrap_err();
        ProfileKey::new("").canonical(kib(4)).unwrap_err();
        FlowKey::Other {
            protocol: "".into(),
            operation: "query".into(),
        }
        .canonical(kib(4))
        .unwrap_err();
        let mut oversized = profile.clone();
        oversized.bytes[17..25].fill(255);
        oversized.id.0 = Sha256::digest(&oversized.bytes).into();
        ProfileKey::from_canonical(&oversized, kib(4)).unwrap_err();
        let mut invalid = profile;
        *invalid.bytes.last_mut().unwrap() = 2;
        invalid.id.0 = Sha256::digest(&invalid.bytes).into();
        ProfileKey::from_canonical(&invalid, kib(4)).unwrap_err();
    }

    #[test]
    fn flow_round_trip_retains_explicit_fetch_and_connection_context() {
        for early_data in [None, Some(false), Some(true)] {
            for ip_family in [
                None,
                Some(ConnectionIpFamily::V4),
                Some(ConnectionIpFamily::V6),
            ] {
                let flow = FlowKey::Http {
                    version: Version::HTTP_3,
                    method: Method::POST,
                    initiator: Some(RequestInitiator::Fetch),
                    fetch: Some(FetchContext {
                        mode: Some("cors".into()),
                        site: Some("same-origin".into()),
                        destination: Some("".into()),
                        user_activation: None,
                    }),
                    connection: ConnectionContext {
                        resumption: ResumptionContext::Resumed,
                        early_data,
                        token_present: early_data,
                        ip_family,
                    },
                };
                let value = flow.canonical(kib(4)).unwrap();
                assert_eq!(
                    FlowKey::from_canonical(&value, kib(4))
                        .unwrap()
                        .canonical(kib(4))
                        .unwrap()
                        .id,
                    value.id
                );
            }
        }
    }

    #[test]
    fn http_flow_fixed_vectors_cover_all_owned_context_tags() {
        let expected = [
            [
                116, 13, 145, 26, 79, 250, 202, 46, 39, 9, 109, 139, 145, 204, 112, 140, 66, 125,
                236, 84, 172, 66, 55, 105, 32, 92, 74, 196, 223, 167, 210, 253,
            ],
            [
                137, 73, 1, 18, 78, 204, 165, 248, 253, 137, 148, 51, 66, 70, 133, 24, 83, 17, 151,
                213, 142, 182, 44, 254, 233, 39, 158, 89, 114, 13, 164, 240,
            ],
            [
                146, 232, 87, 127, 30, 247, 191, 205, 204, 166, 161, 50, 45, 230, 36, 217, 169,
                234, 135, 185, 191, 116, 126, 199, 233, 63, 155, 35, 101, 55, 151, 109,
            ],
            [
                96, 44, 224, 104, 63, 16, 104, 74, 129, 200, 170, 25, 67, 221, 237, 48, 194, 82,
                75, 107, 158, 58, 141, 165, 12, 132, 233, 149, 134, 120, 205, 68,
            ],
            [
                52, 27, 97, 15, 249, 243, 162, 42, 237, 246, 64, 48, 164, 172, 19, 24, 18, 237,
                250, 212, 7, 104, 12, 238, 27, 1, 17, 155, 57, 26, 112, 161,
            ],
            [
                196, 35, 47, 215, 95, 50, 63, 43, 196, 114, 89, 77, 132, 56, 200, 235, 26, 208,
                103, 205, 183, 17, 111, 221, 199, 152, 226, 216, 215, 164, 56, 10,
            ],
        ];
        let versions = [
            Version::HTTP_09,
            Version::HTTP_10,
            Version::HTTP_11,
            Version::HTTP_2,
            Version::HTTP_3,
        ];
        let initiators = [
            None,
            Some(RequestInitiator::Navigate),
            Some(RequestInitiator::Form),
            Some(RequestInitiator::Xhr),
            Some(RequestInitiator::Fetch),
            Some(RequestInitiator::Ws),
        ];
        let resumptions = [
            ResumptionContext::Unknown,
            ResumptionContext::Fresh,
            ResumptionContext::Resumed,
        ];
        let booleans = [None, Some(false), Some(true)];
        let families = [
            None,
            Some(ConnectionIpFamily::V4),
            Some(ConnectionIpFamily::V6),
        ];
        for (index, expected) in expected.into_iter().enumerate() {
            let fetch = match index {
                1 => Some(FetchContext {
                    mode: Some("cors".into()),
                    destination: Some("empty".into()),
                    ..FetchContext::default()
                }),
                3 => Some(FetchContext {
                    site: Some("same-origin".into()),
                    user_activation: Some("?1".into()),
                    ..FetchContext::default()
                }),
                5 => Some(FetchContext {
                    mode: Some("".into()),
                    site: Some("".into()),
                    destination: Some("".into()),
                    user_activation: Some("".into()),
                }),
                _ => None,
            };
            let flow = FlowKey::Http {
                version: versions[index % 5],
                method: if index == 5 {
                    Method::from_bytes(b"CUSTOM").unwrap()
                } else {
                    Method::GET
                },
                initiator: initiators[index],
                fetch,
                connection: ConnectionContext {
                    resumption: resumptions[index % 3],
                    early_data: booleans[index % 3],
                    token_present: booleans[(index + 1) % 3],
                    ip_family: families[(index + 2) % 3],
                },
            };
            let value = flow.canonical(kib(4)).unwrap();
            assert_eq!(value.id.0, expected, "vector {index}");
            assert_eq!(
                FlowKey::from_canonical(&value, kib(4))
                    .unwrap()
                    .canonical(kib(4))
                    .unwrap()
                    .bytes,
                value.bytes
            );
        }
    }
}
