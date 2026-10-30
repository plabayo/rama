//! Stable client and flow identities without a browser or mandatory HTTP component.

use std::str;

use rama_core::extensions::Extension;
use rama_http::{
    HeaderMap, HeaderName, Method, Version,
    header::{SEC_FETCH_DEST, SEC_FETCH_MODE, SEC_FETCH_SITE, SEC_FETCH_USER},
};
use serde::{Deserialize, Serialize};

use crate::{DeviceKind, PlatformKind, UserAgent};

use crate::profile::{
    format::canonical::{
        CanonicalReader, CanonicalValue, CanonicalWriter, FLOW_DOMAIN, PROFILE_DOMAIN,
        ProfileDataError,
    },
    model::runtime_hints::RequestInitiator,
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, Extension)]
#[extension(tags(ua))]
pub struct ConnectionContext {
    pub resumption: ResumptionContext,
    pub early_data: Option<bool>,
    pub token_present: Option<bool>,
    pub ip_family: Option<ConnectionIpFamily>,
}

impl ConnectionContext {
    pub(in crate::profile) fn encode(
        &self,
        writer: &mut CanonicalWriter,
    ) -> Result<(), ProfileDataError> {
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

    pub(in crate::profile) fn decode(
        reader: &mut CanonicalReader<'_>,
    ) -> Result<Self, ProfileDataError> {
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
        let mut read = |name: &'static HeaderName| -> Result<Option<&str>, ProfileDataError> {
            let values = headers.get_all(name);
            let mut values = values.iter();
            let value = values.next();
            if values.next().is_some() {
                return Err(ProfileDataError::Invalid("duplicate Fetch context field"));
            }
            value
                .map(|value| {
                    remaining = remaining
                        .checked_sub(name.as_str().len())
                        .and_then(|n| n.checked_sub(value.len()))
                        .ok_or(ProfileDataError::LimitExceeded("Fetch context bytes"))?;
                    value
                        .to_str()
                        .map_err(|_error| ProfileDataError::Invalid("Fetch context value"))
                })
                .transpose()
        };
        let mode = read(&SEC_FETCH_MODE)?;
        let site = read(&SEC_FETCH_SITE)?;
        let destination = read(&SEC_FETCH_DEST)?;
        let user_activation = read(&SEC_FETCH_USER)?;
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
mod tests;
