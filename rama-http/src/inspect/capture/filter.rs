use std::{convert::Infallible, fmt, str::FromStr};

use rama_net::Protocol;
use rama_utils::str::{NonEmptyStr, arcstr::ArcStr};
use serde::Deserialize;

use super::{HttpExchangeSummary, search::matches_display};
use crate::{Method, StatusCode};

/// A parsed selector. Unknown expressions remain visible without matching data.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum FilterValue<T> {
    #[default]
    Any,
    Value(T),
    Unknown(NonEmptyStr),
}

impl<T> FilterValue<T> {
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Any)
    }

    fn matches(&self, test: impl FnOnce(&T) -> bool) -> bool {
        match self {
            Self::Any => true,
            Self::Value(value) => test(value),
            Self::Unknown(_) => false,
        }
    }
}

impl<T: FromStr> FromStr for FilterValue<T> {
    type Err = Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(if value.is_empty() {
            Self::Any
        } else {
            match value.parse() {
                Ok(value) => Self::Value(value),
                Err(_) => NonEmptyStr::try_from(value)
                    .map(Self::Unknown)
                    .unwrap_or(Self::Any),
            }
        })
    }
}

impl<T: FromStr> From<&str> for FilterValue<T> {
    fn from(value: &str) -> Self {
        match value.parse() {
            Ok(value) => value,
            Err(error) => match error {},
        }
    }
}

impl<T: FromStr> From<String> for FilterValue<T> {
    fn from(value: String) -> Self {
        if value.is_empty() {
            Self::Any
        } else {
            match value.parse() {
                Ok(value) => Self::Value(value),
                Err(_) => NonEmptyStr::try_from(value)
                    .map(Self::Unknown)
                    .unwrap_or(Self::Any),
            }
        }
    }
}

impl<T: fmt::Display> fmt::Display for FilterValue<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => Ok(()),
            Self::Value(value) => value.fmt(f),
            Self::Unknown(value) => value.fmt(f),
        }
    }
}

impl<'de, T: FromStr> Deserialize<'de> for FilterValue<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = ArcStr::deserialize(deserializer)?;
        if value.is_empty() {
            return Ok(Self::Any);
        }
        Ok(match value.parse() {
            Ok(value) => Self::Value(value),
            Err(_) => {
                Self::Unknown(NonEmptyStr::try_from(value).map_err(serde::de::Error::custom)?)
            }
        })
    }
}

/// A human-visible connection number, optionally entered with a leading `#`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionQuery(pub u64);

impl FromStr for ConnectionQuery {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.trim().trim_start_matches('#').parse().map(Self)
    }
}

impl fmt::Display for ConnectionQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolQuery {
    Exact(Protocol),
    Other,
}

impl FromStr for ProtocolQuery {
    type Err = rama_core::error::BoxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "other" {
            Ok(Self::Other)
        } else {
            Ok(Self::Exact(s.parse()?))
        }
    }
}

impl ProtocolQuery {
    fn matches(&self, protocol: &Protocol) -> bool {
        match self {
            Self::Exact(value) => value == protocol,
            Self::Other => !matches!(
                *protocol,
                Protocol::HTTP | Protocol::HTTPS | Protocol::WS | Protocol::WSS
            ),
        }
    }
}

impl fmt::Display for ProtocolQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(value) => value.fmt(f),
            Self::Other => f.write_str("other"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusQuery {
    Exact(StatusCode),
    Informational,
    Success,
    Redirection,
    ClientError,
    ServerError,
    Pending,
}

impl FromStr for StatusQuery {
    type Err = rama_core::error::BoxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "1xx" => Ok(Self::Informational),
            "2xx" => Ok(Self::Success),
            "3xx" => Ok(Self::Redirection),
            "4xx" => Ok(Self::ClientError),
            "5xx" => Ok(Self::ServerError),
            _ => Ok(Self::Exact(s.parse()?)),
        }
    }
}

impl StatusQuery {
    fn matches(self, summary: &HttpExchangeSummary) -> bool {
        match self {
            Self::Pending => summary.active || summary.status.is_none(),
            Self::Exact(status) => summary.status == Some(status),
            Self::Informational => summary
                .status
                .is_some_and(|status| status.is_informational()),
            Self::Success => summary.status.is_some_and(|status| status.is_success()),
            Self::Redirection => summary.status.is_some_and(|status| status.is_redirection()),
            Self::ClientError => summary
                .status
                .is_some_and(|status| status.is_client_error()),
            Self::ServerError => summary
                .status
                .is_some_and(|status| status.is_server_error()),
        }
    }
}

impl fmt::Display for StatusQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => f.write_str("pending"),
            Self::Exact(status) => status.as_u16().fmt(f),
            Self::Informational => f.write_str("1xx"),
            Self::Success => f.write_str("2xx"),
            Self::Redirection => f.write_str("3xx"),
            Self::ClientError => f.write_str("4xx"),
            Self::ServerError => f.write_str("5xx"),
        }
    }
}

/// Parsed selectors and substring searches. Text patterns use shared storage;
/// native selectors avoid reparsing or formatting every captured exchange.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CaptureFilter {
    pub search: ArcStr,
    pub connection_id: FilterValue<ConnectionQuery>,
    pub user_agent: ArcStr,
    pub endpoint: ArcStr,
    pub method: FilterValue<Method>,
    pub status: FilterValue<StatusQuery>,
    pub protocol: FilterValue<ProtocolQuery>,
}

impl CaptureFilter {
    pub(super) fn matches_dimensions(&self, summary: &HttpExchangeSummary) -> bool {
        self.connection_id
            .matches(|id| id.0 == summary.connection_display_id)
            && matches_display(
                &summary
                    .user_agent
                    .as_ref()
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default(),
                &self.user_agent,
            )
            && (self.endpoint.is_empty()
                || summary
                    .endpoint
                    .as_ref()
                    .is_some_and(|v| matches_display(v, &self.endpoint)))
            && (self.method.is_empty()
                || self.method.matches(|method| {
                    summary
                        .method
                        .as_str()
                        .eq_ignore_ascii_case(method.as_str())
                }))
            && self.status.matches(|status| status.matches(summary))
            && self
                .protocol
                .matches(|protocol| protocol.matches(&summary.protocol))
    }

    pub fn search_matches_summary(&self, summary: &HttpExchangeSummary) -> bool {
        self.search.is_empty()
            || matches_display(
                &format_args!(
                    "{} {} {} {} {} {} {}",
                    summary.connection_display_id,
                    summary.method,
                    summary.http_version,
                    summary.url,
                    summary.protocol,
                    summary.status.map(|s| s.as_u16()).unwrap_or_default(),
                    summary
                        .user_agent
                        .as_ref()
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                ),
                &self.search,
            )
            || summary
                .endpoint
                .as_ref()
                .is_some_and(|value| matches_display(value, &self.search))
    }

    pub fn is_empty(&self) -> bool {
        self.search.is_empty()
            && self.connection_id.is_empty()
            && self.user_agent.is_empty()
            && self.endpoint.is_empty()
            && self.method.is_empty()
            && self.status.is_empty()
            && self.protocol.is_empty()
    }
}

#[cfg(test)]
pub(super) fn matches_connection_id(id: u64, query: &str) -> bool {
    FilterValue::<ConnectionQuery>::from(query).matches(|q| q.0 == id)
}

#[cfg(test)]
pub(super) fn matches_status(summary: &HttpExchangeSummary, query: &str) -> bool {
    FilterValue::<StatusQuery>::from(query).matches(|q| q.matches(summary))
}

#[cfg(test)]
pub(super) fn matches_protocol(protocol: &str, query: &str) -> bool {
    FilterValue::<ProtocolQuery>::from(query)
        .matches(|q| protocol.parse().is_ok_and(|protocol| q.matches(&protocol)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_queries_keep_unknown_values_and_custom_protocols() {
        let filter: CaptureFilter = serde_json::from_str(
            r##"{"method":"CUSTOM", "protocol":"example", "status":"6xx", "connection_id":"#12"}"##,
        )
        .unwrap();
        assert_eq!(
            filter.method,
            FilterValue::Value(Method::from_bytes(b"CUSTOM").unwrap())
        );
        assert_eq!(
            filter.protocol,
            FilterValue::Value(ProtocolQuery::Exact(Protocol::from_static("example")))
        );
        assert!(matches!(&filter.status, FilterValue::Unknown(value) if value.as_ref() == "6xx"));
        assert_eq!(
            filter.connection_id,
            FilterValue::Value(ConnectionQuery(12))
        );
        assert_eq!(filter.status.to_string(), "6xx");
    }
}
