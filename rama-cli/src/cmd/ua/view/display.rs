//! Human-readable profile summaries with bounded retained display text.

use crate::utils::terminal::display_text;
use jiff::{Timestamp, tz::TimeZone};
use rama::{
    error::{BoxError, BoxErrorExt as _},
    ua::profile::{
        evidence::counts::ObservationWeight,
        model::{identity::FlowKey, ua::UserAgentProfile},
    },
    utils::octets::kib,
};
use std::fmt::Write as _;

#[derive(Debug)]
pub(super) struct Row {
    pub(super) label: String,
    pub(super) details: String,
}

impl Row {
    pub(super) fn from_profile(profile: &UserAgentProfile) -> Result<Self, BoxError> {
        let capability = profile.capabilities();
        let protocols = [
            (capability.h1, "H1"),
            (capability.h2, "H2"),
            (capability.h3, "H3"),
            (capability.tls_tcp, "TLS/TCP"),
            (capability.tls_quic, "TLS/QUIC"),
            (capability.quic, "QUIC"),
        ]
        .into_iter()
        .filter_map(|(present, name)| present.then_some(name))
        .collect::<Vec<_>>()
        .join(", ");
        let protocols = if protocols.is_empty() {
            "none observed"
        } else {
            &protocols
        };
        let weight = match profile.observation_weight()? {
            ObservationWeight::Exact(count) => format!("{count} exact"),
            ObservationWeight::UnknownHistory { observed, .. } => {
                format!("{observed} retained; earlier history unknown")
            }
            ObservationWeight::LowerBound { observed, .. } => format!("at least {observed}"),
        };
        let client = display_text(&profile.key.client);
        let version = display_text(profile.key.version.as_deref().unwrap_or("unknown"));
        let mut details = format!(
            "Client: {client}\nVersion: {version}\nPlatform: {}\nDevice: {}\nProtocols: {protocols}\nObservations: {weight}\nUser-Agent: {}\n",
            profile
                .key
                .platform
                .map_or("unknown", |value| value.as_str()),
            profile.key.device.map_or("unknown", |value| value.as_str()),
            display_text(profile.ua_str().unwrap_or("not recorded")),
        );
        if let Some(captured) = &profile.captured {
            let through = Timestamp::from_second(i64::from(captured.current_day) * 86_400)?
                .to_zoned(TimeZone::UTC)
                .date();
            writeln!(
                details,
                "\nFreshness: {} UTC day buckets through {through}\nClassifier revision: {}\nScopes: {}",
                captured.horizon,
                captured.classifier_revision,
                captured.scopes.len()
            )?;
            for scope in &captured.scopes {
                let flow = match &scope.flow {
                    Some(FlowKey::Http {
                        version,
                        method,
                        initiator,
                        ..
                    }) => {
                        format!("{version:?} {method} {initiator:?}")
                    }
                    Some(FlowKey::Other {
                        protocol,
                        operation,
                    }) => {
                        format!("{} {}", display_text(protocol), display_text(operation))
                    }
                    None => "connection".to_owned(),
                };
                let observations = &scope.observations;
                let counts = &observations.counts;
                writeln!(
                    details,
                    "\n{flow} / {:?}\n  {} observations, {} literal values, {} retained samples\n  {} unassigned; {} oversized, {} retention losses; history {}\n  {} order analyses, {} numeric distributions",
                    observations.domain,
                    counts.total,
                    counts.values.len(),
                    observations.retained_samples,
                    counts.untracked,
                    counts.losses.oversize,
                    counts.losses.retention,
                    if counts.losses.history_known {
                        "known"
                    } else {
                        "unknown"
                    },
                    observations.orders.len(),
                    observations.numeric.len()
                )?;
                if details.len() > kib(64) {
                    details.push_str("\nFurther scope details omitted from this overview.\n");
                    break;
                }
            }
        } else {
            details
                .push_str("\nLegacy capture: original sample counts and freshness are unknown.\n");
        }
        Ok(Self {
            label: format!(
                "{client} {version} {} {}  [{protocols}]  {weight}",
                profile
                    .key
                    .platform
                    .map_or("unknown", |value| value.as_str()),
                profile.key.device.map_or("unknown", |value| value.as_str()),
            ),
            details,
        })
    }
}

pub(super) fn push_row(
    rows: &mut Vec<Row>,
    remaining: &mut usize,
    row: Row,
) -> Result<(), BoxError> {
    *remaining = remaining
        .checked_sub(row.label.len())
        .and_then(|bytes| bytes.checked_sub(row.details.len()))
        .ok_or_else(|| BoxError::from_static_str("profile viewer memory limit exceeded"))?;
    rows.push(row);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn viewer_summary_budget_rejects_growth_without_retaining_a_partial_row() {
        let row = Row {
            label: "a".into(),
            details: "bc".into(),
        };
        let mut rows = Vec::new();
        let mut remaining = 2;
        push_row(&mut rows, &mut remaining, row).unwrap_err();
        assert!(rows.is_empty());
        assert_eq!(remaining, 2);
    }
}
