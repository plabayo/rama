//! Loaded profiles with their summary text, filter keys and per-layer scopes.

use super::render::domain_label;
use crate::utils::terminal::display_text;
use jiff::{Timestamp, tz::TimeZone};
use rama::{
    error::{BoxError, BoxErrorExt as _},
    ua::UserAgent,
    ua::profile::{
        analysis::{
            capture::RetainedShares,
            order::AnalyzedOrderWeight,
            profile::{AnalyzedProfile, AnalyzedProfileScope},
        },
        evidence::counts::ObservationWeight,
        model::{identity::FlowKey, ua::UserAgentProfile},
    },
    utils::octets::mib,
};
use ratatui::style::Color;
use std::cmp::Reverse;

/// Capture bytes the viewer keeps for browsing, bounding database and file sources.
pub(super) const VIEWER_BYTES: usize = mib(256);

/// Capture layers in protocol stack order; a scope may belong to several.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Layer {
    Overview,
    TlsTcp,
    Http1,
    Http2,
    Quic,
    TlsQuic,
    Http3,
    Other,
}

impl Layer {
    pub(super) const ALL: [Self; 8] = [
        Self::Overview,
        Self::TlsTcp,
        Self::Http1,
        Self::Http2,
        Self::Quic,
        Self::TlsQuic,
        Self::Http3,
        Self::Other,
    ];

    /// The protocols shown per profile, in the order of [`Row::protocols`].
    pub(super) const PROTOCOLS: [Self; 6] = [
        Self::Http1,
        Self::Http2,
        Self::Http3,
        Self::TlsTcp,
        Self::TlsQuic,
        Self::Quic,
    ];

    pub(super) fn title(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::TlsTcp => "TLS/TCP",
            Self::Http1 => "HTTP/1",
            Self::Http2 => "HTTP/2",
            Self::Quic => "QUIC",
            Self::TlsQuic => "TLS/QUIC",
            Self::Http3 => "HTTP/3",
            Self::Other => "Other",
        }
    }

    /// The short tab label.
    pub(super) fn tab(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Other => "Other",
            layer => layer.chip(),
        }
    }

    /// The column label in the profile list.
    pub(super) fn chip(self) -> &'static str {
        match self {
            Self::Http1 => "H1",
            Self::Http2 => "H2",
            Self::Http3 => "H3",
            Self::TlsTcp => "TLS",
            Self::TlsQuic => "QTLS",
            Self::Quic => "QUIC",
            Self::Overview | Self::Other => "",
        }
    }

    pub(super) fn color(self) -> Color {
        match self {
            Self::Overview => Color::White,
            Self::TlsTcp => Color::LightGreen,
            Self::Http1 => Color::Yellow,
            Self::Http2 => Color::LightBlue,
            Self::Quic => Color::LightCyan,
            Self::TlsQuic => Color::Green,
            Self::Http3 => Color::LightMagenta,
            Self::Other => Color::Gray,
        }
    }

    /// Indices of the scopes in this layer, in display order.
    pub(super) fn scopes(self, analysis: &AnalyzedProfile) -> Vec<usize> {
        let components = &analysis.components;
        let mut scopes: Vec<usize> = match self {
            Self::Overview => Vec::new(),
            Self::TlsTcp => components.tls_tcp.as_deref().unwrap_or_default().to_vec(),
            Self::Http1 => components.h1.as_deref().unwrap_or_default().to_vec(),
            Self::Http2 => components.h2.as_deref().unwrap_or_default().to_vec(),
            Self::Quic => components.quic.as_deref().unwrap_or_default().to_vec(),
            Self::TlsQuic => components.tls_quic.as_deref().unwrap_or_default().to_vec(),
            Self::Http3 => components.h3.as_deref().unwrap_or_default().to_vec(),
            Self::Other => (0..analysis.scopes.len())
                .filter(|index| {
                    ![
                        &components.h1,
                        &components.h2,
                        &components.h3,
                        &components.tls_tcp,
                        &components.tls_quic,
                        &components.quic,
                    ]
                    .into_iter()
                    .flatten()
                    .any(|members| members.contains(index))
                })
                .collect(),
        };
        scopes.retain(|index| *index < analysis.scopes.len());
        scopes.sort_by_cached_key(|index| ScopeLabel::new(&analysis.scopes[*index]).order());
        scopes
    }
}

/// What a scope observed: its request flow, or the connection, and the capture kind.
pub(super) struct ScopeLabel {
    pub(super) flow: String,
    pub(super) detail: String,
    pub(super) capture: String,
    /// Scopes of one flow differ by the shape of what they captured.
    pub(super) shape: String,
    rank: u8,
}

impl ScopeLabel {
    pub(super) fn new(scope: &AnalyzedProfileScope) -> Self {
        let sample = scope
            .observations
            .variants
            .first()
            .and_then(|variant| variant.value.canonical().ok());
        let capture = domain_label(scope.observations.domain, sample.as_deref());
        let structure = &scope.context.structure.0;
        let shape = format!("#{:02x}{:02x}", structure[0], structure[1]);
        match &scope.flow {
            Some(FlowKey::Http {
                method,
                initiator,
                fetch,
                ..
            }) => {
                let destination = fetch
                    .as_ref()
                    .and_then(|fetch| fetch.destination.as_deref())
                    .map(display_text);
                let site = fetch
                    .as_ref()
                    .and_then(|fetch| fetch.site.as_deref())
                    .map(display_text);
                Self {
                    flow: format!(
                        "{method} {}",
                        initiator.map_or("subresource", |initiator| initiator.as_str())
                    ),
                    detail: [destination, site]
                        .into_iter()
                        .flatten()
                        .collect::<Vec<_>>()
                        .join(" · "),
                    capture,
                    shape,
                    rank: initiator.map_or(9, |initiator| 1 + initiator as u8),
                }
            }
            Some(FlowKey::Other {
                protocol,
                operation,
            }) => Self {
                flow: format!("{} {}", display_text(protocol), display_text(operation)),
                detail: String::new(),
                capture,
                shape,
                rank: 10,
            },
            None => Self {
                flow: "connection".to_owned(),
                detail: String::new(),
                capture,
                shape,
                rank: 0,
            },
        }
    }

    fn order(&self) -> (u8, String, String, String, String) {
        (
            self.rank,
            self.flow.clone(),
            self.capture.clone(),
            self.detail.clone(),
            self.shape.clone(),
        )
    }
}

/// How much one retained variant was observed, and its share of the scope.
pub(super) fn variant_weight(weight: &AnalyzedOrderWeight, total: u64) -> (String, f64) {
    let (text, observed) = match weight {
        AnalyzedOrderWeight::Counted(weight) => match weight {
            ObservationWeight::Exact(count) => (format!("{count} observed"), *count as f64),
            ObservationWeight::UnknownHistory { observed, .. } => (
                format!("{observed} observed, history unknown"),
                *observed as f64,
            ),
            ObservationWeight::LowerBound { observed, .. } => {
                (format!("at least {observed}"), *observed as f64)
            }
        },
        AnalyzedOrderWeight::Sample {
            observed,
            sample_size,
            population,
            ..
        } => (
            format!("{observed} of {sample_size} samples from {population}"),
            *observed as f64 * (*population as f64 / (*sample_size).max(1) as f64),
        ),
    };
    (
        text,
        if total == 0 {
            0.0
        } else {
            (observed / total as f64).min(1.0)
        },
    )
}

#[derive(Debug)]
pub(super) struct Row {
    pub(super) profile: UserAgentProfile,
    pub(super) client: String,
    pub(super) version: String,
    pub(super) platform: &'static str,
    pub(super) device: &'static str,
    pub(super) user_agent: String,
    pub(super) protocols: [bool; 6],
    pub(super) weight: String,
    pub(super) freshness: Option<String>,
    /// Lowercase text the filter matches against.
    search: String,
    retained: usize,
}

impl Row {
    pub(super) fn from_profile(profile: UserAgentProfile) -> Result<Self, BoxError> {
        let capability = profile.capabilities();
        let protocols = [
            capability.h1,
            capability.h2,
            capability.h3,
            capability.tls_tcp,
            capability.tls_quic,
            capability.quic,
        ];
        let weight = match profile.observation_weight()? {
            ObservationWeight::Exact(count) => format!("{count}"),
            ObservationWeight::UnknownHistory { observed, .. } => format!("{observed}?"),
            ObservationWeight::LowerBound { observed, .. } => format!("≥{observed}"),
        };
        let freshness = match &profile.captured {
            Some(captured) => {
                let through = Timestamp::from_second(i64::from(captured.current_day) * 86_400)?
                    .to_zoned(TimeZone::UTC)
                    .date();
                Some(format!(
                    "{} UTC days through {through} · revision {}",
                    captured.horizon, captured.classifier_revision
                ))
            }
            None => None,
        };
        let client = display_text(&profile.key.client);
        let version = display_text(profile.key.version.as_deref().unwrap_or("?"));
        let platform = profile
            .key
            .platform
            .map_or("unknown", |value| value.as_str());
        let device = profile.key.device.map_or("unknown", |value| value.as_str());
        let user_agent = display_text(profile.ua_str().unwrap_or("not recorded"));
        let chips: Vec<&str> = Layer::PROTOCOLS
            .iter()
            .zip(protocols)
            .filter_map(|(layer, present)| present.then_some(layer.chip()))
            .collect();
        let search = format!(
            "{client} {version} {platform} {device} {} {user_agent}",
            chips.join(" ")
        )
        .to_lowercase();
        let retained = profile.captured.as_ref().map_or(0, |captured| {
            let mut shared = RetainedShares::default();
            captured
                .scopes
                .iter()
                .flat_map(|scope| scope.observations.variants.iter())
                .map(|variant| variant.value.retained_bytes(&mut shared))
                .sum()
        });
        Ok(Self {
            retained: retained + search.len() + user_agent.len(),
            profile,
            client,
            version,
            platform,
            device,
            user_agent,
            protocols,
            weight,
            freshness,
            search,
        })
    }

    /// One plain line for `--summary` and non-terminal output.
    pub(super) fn summary(&self) -> String {
        let chips: Vec<&str> = Layer::PROTOCOLS
            .iter()
            .zip(self.protocols)
            .filter_map(|(layer, present)| present.then_some(layer.chip()))
            .collect();
        format!(
            "{} {} {} {}  [{}]  {} observed",
            self.client,
            self.version,
            self.platform,
            self.device,
            if chips.is_empty() {
                "none observed".to_owned()
            } else {
                chips.join(", ")
            },
            self.weight
        )
    }

    /// Read the filter as emulation reads an auto-detected User-Agent: the browser,
    /// platform and device it names select profiles; other words match the row text.
    pub(super) fn matches(&self, filter: &str) -> bool {
        let agent = UserAgent::new(filter.to_owned());
        let key = &self.profile.key;
        if agent
            .ua_kind()
            .is_some_and(|kind| self.profile.ua_kind != Some(kind))
            || agent
                .platform()
                .is_some_and(|platform| key.platform != Some(platform))
            || agent
                .device()
                .is_some_and(|device| key.device != Some(device))
        {
            return false;
        }
        filter
            .split_whitespace()
            .filter(|word| !names_a_class(word))
            .all(|word| self.search.contains(&word.to_lowercase()))
    }
}

/// Whether a filter word alone names a browser, platform or device.
fn names_a_class(word: &str) -> bool {
    let agent = UserAgent::new(word.to_owned());
    agent.ua_kind().is_some() || agent.platform().is_some() || agent.device().is_some()
}

/// Group by client and platform, newest version first.
pub(super) fn sort_rows(rows: &mut [Row]) {
    rows.sort_by_cached_key(|row| {
        let version = row
            .version
            .split(|ch: char| !ch.is_ascii_digit())
            .next()
            .and_then(|digits| digits.parse::<u64>().ok())
            .unwrap_or(0);
        (
            row.client.to_lowercase(),
            row.platform,
            row.device,
            Reverse(version),
            row.version.clone(),
        )
    })
}

pub(super) fn push_row(
    rows: &mut Vec<Row>,
    remaining: &mut usize,
    row: Row,
) -> Result<(), BoxError> {
    *remaining = remaining
        .checked_sub(row.retained)
        .ok_or_else(|| BoxError::from_static_str("profile viewer memory limit exceeded"))?;
    rows.push(row);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::ua::profile::{
        format::input::try_load_embedded_profiles, model::identity::ProfileKey,
    };

    #[test]
    fn viewer_budget_rejects_growth_without_retaining_a_partial_row() {
        let row = Row::from_profile(UserAgentProfile::new(ProfileKey::new("library"))).unwrap();
        let mut rows = Vec::new();
        let mut remaining = row.retained - 1;
        push_row(&mut rows, &mut remaining, row).unwrap_err();
        assert!(rows.is_empty());
        assert_ne!(remaining, 0);
    }

    #[test]
    fn viewer_budget_charges_compact_captures() {
        let profile = try_load_embedded_profiles()
            .unwrap()
            .find(|profile| {
                profile.captured.as_ref().is_some_and(|captured| {
                    captured.scopes.iter().any(|scope| {
                        scope
                            .observations
                            .variants
                            .iter()
                            .any(|variant| variant.value.as_canonical().is_none())
                    })
                })
            })
            .unwrap();
        let bare = Row::from_profile(UserAgentProfile::new(profile.key.clone())).unwrap();
        let row = Row::from_profile(profile).unwrap();
        assert!(row.retained > bare.retained + 4096);
    }

    #[test]
    fn rows_group_by_client_with_the_newest_version_first() {
        let mut rows: Vec<Row> = ["beta/9", "alpha/10", "alpha/9", "alpha/100"]
            .into_iter()
            .map(|name| {
                let (client, version) = name.split_once('/').unwrap();
                let mut key = ProfileKey::new(client);
                key.version = Some(version.into());
                Row::from_profile(UserAgentProfile::new(key)).unwrap()
            })
            .collect();
        sort_rows(&mut rows);
        let order: Vec<String> = rows
            .iter()
            .map(|row| format!("{}/{}", row.client, row.version))
            .collect();
        assert_eq!(order, ["alpha/100", "alpha/10", "alpha/9", "beta/9"]);
        assert!(rows[0].matches("alpha 100"));
        assert!(!rows[0].matches("alpha h3"));
    }
}
