//! Path observations use only tuples and transitions known to the engine.
use std::net::SocketAddr;

use serde::Serialize;

use crate::proto::{ConnectionId, Instant, TIMER_GRANULARITY, connection::Connection};

#[derive(Serialize)]
#[serde(tag = "name", content = "data")]
enum PathEvent {
    #[serde(rename = "quic:tuple_assigned")]
    TupleAssigned(TupleAssigned),
    #[serde(rename = "quic:migration_state_updated")]
    MigrationStateUpdated {
        new: MigrationState,
        tuple_id: String,
    },
    #[serde(rename = "quic:connection_id_updated")]
    ConnectionIdUpdated {
        initiator: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        old: Option<String>,
        new: String,
    },
    #[serde(rename = "quic:mtu_updated")]
    MtuUpdated { old: u16, new: u16 },
    #[serde(rename = "quic:recovery_parameters_set")]
    RecoveryParametersSet {
        #[serde(skip_serializing_if = "Option::is_none")]
        reordering_threshold: Option<u16>,
        time_threshold: f32,
        timer_granularity: u16,
        initial_rtt: f64,
        max_datagram_size: u16,
        initial_congestion_window: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        persistent_congestion_threshold: Option<u16>,
    },
}

#[derive(Serialize)]
struct OnTuple<E> {
    #[serde(skip_serializing_if = "Option::is_none")]
    tuple: Option<String>,
    #[serde(flatten)]
    event: E,
}

/// Attach a known path, leaving the default handshake tuple implicit.
pub(in crate::proto::connection) fn with_path(
    generation: u64,
    event: impl Serialize,
) -> impl Serialize {
    OnTuple {
        tuple: (generation != 0).then(|| generation.to_string()),
        event,
    }
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::proto::connection) enum MigrationState {
    ProbingStarted,
    ProbingAbandoned,
    ProbingSuccessful,
    MigrationStarted,
    MigrationAbandoned,
    MigrationComplete,
}

#[derive(Serialize)]
struct TupleAssigned {
    tuple_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tuple_remote: Option<TupleEndpointInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tuple_local: Option<TupleEndpointInfo>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum TupleEndpointInfo {
    V4 { ip_v4: String, port_v4: u16 },
    V6 { ip_v6: String, port_v6: u16 },
}

impl From<SocketAddr> for TupleEndpointInfo {
    fn from(address: SocketAddr) -> Self {
        match address {
            SocketAddr::V4(address) => Self::V4 {
                ip_v4: address.ip().to_string(),
                port_v4: address.port(),
            },
            SocketAddr::V6(address) => Self::V6 {
                ip_v6: address.ip().to_string(),
                port_v6: address.port(),
            },
        }
    }
}

fn tuple_id(generation: u64) -> String {
    if generation == 0 {
        String::new()
    } else {
        generation.to_string()
    }
}

impl Connection {
    pub(in crate::proto::connection) fn qlog_init_recovery(&self, now: Instant) {
        self.config
            .qlog_sink
            .emit(self.trace_cid, now, || PathEvent::RecoveryParametersSet {
                reordering_threshold: self.config.packet_threshold.try_into().ok(),
                time_threshold: self.config.time_threshold,
                timer_granularity: TIMER_GRANULARITY.as_millis() as u16,
                initial_rtt: self.config.initial_rtt.as_secs_f64() * 1000.0,
                max_datagram_size: self.path.current_mtu(),
                initial_congestion_window: self.path.congestion.initial_window(),
                persistent_congestion_threshold: self
                    .config
                    .persistent_congestion_threshold
                    .try_into()
                    .ok(),
            });
    }

    pub(in crate::proto::connection) fn qlog_assign_current_tuple(&self, now: Instant) {
        self.config.qlog_sink.emit(self.trace_cid, now, || {
            PathEvent::TupleAssigned(TupleAssigned {
                tuple_id: tuple_id(self.path.generation()),
                tuple_remote: Some(self.path.remote.into()),
                tuple_local: self.path.local.map(Into::into),
            })
        });
    }

    pub(in crate::proto::connection) fn qlog_migration_state(
        &self,
        now: Instant,
        new: MigrationState,
    ) {
        self.config.qlog_sink.emit(self.trace_cid, now, || {
            with_path(
                self.path.generation(),
                PathEvent::MigrationStateUpdated {
                    new,
                    tuple_id: tuple_id(self.path.generation()),
                },
            )
        });
    }

    pub(in crate::proto::connection) fn qlog_candidate_state(
        &self,
        now: Instant,
        seq: u64,
        remote: SocketAddr,
        new: MigrationState,
    ) {
        // The reserved CID sequence is unique for each probing attempt. A path generation is
        // assigned only after promotion; the probe tuple remains the history of that attempt.
        self.config.qlog_sink.emit(self.trace_cid, now, || {
            PathEvent::TupleAssigned(TupleAssigned {
                tuple_id: format!("probe-{seq}"),
                tuple_remote: Some(remote.into()),
                tuple_local: self.path.local.map(Into::into),
            })
        });
        self.config.qlog_sink.emit(self.trace_cid, now, || OnTuple {
            tuple: Some(format!("probe-{seq}")),
            event: PathEvent::MigrationStateUpdated {
                new,
                tuple_id: format!("probe-{seq}"),
            },
        });
    }

    pub(in crate::proto::connection) fn qlog_remote_cid_updated(
        &self,
        now: Instant,
        old: ConnectionId,
    ) {
        let new = self.rem_cids.active();
        if old == new {
            return;
        }
        self.config
            .qlog_sink
            .emit(self.trace_cid, now, || PathEvent::ConnectionIdUpdated {
                initiator: "remote",
                old: Some(old.to_string()),
                new: new.to_string(),
            });
    }

    pub(in crate::proto::connection) fn qlog_local_cid_updated(
        &self,
        now: Instant,
        old: Option<ConnectionId>,
        new: ConnectionId,
    ) {
        if old == Some(new) {
            return;
        }
        self.config
            .qlog_sink
            .emit(self.trace_cid, now, || PathEvent::ConnectionIdUpdated {
                initiator: "local",
                old: old.map(|id| id.to_string()),
                new: new.to_string(),
            });
    }

    pub(in crate::proto::connection) fn qlog_mtu_updated(&self, now: Instant, old: u16) {
        let new = self.path.current_mtu();
        if old == new {
            return;
        }
        self.config.qlog_sink.emit(self.trace_cid, now, || {
            with_path(self.path.generation(), PathEvent::MtuUpdated { old, new })
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_scoping_keeps_default_tuple_implicit() {
        let default = serde_json::to_value(with_path(
            0,
            PathEvent::MtuUpdated {
                old: 1200,
                new: 1300,
            },
        ))
        .unwrap();
        assert!(default.get("tuple").is_none());
        assert_eq!(default["name"], "quic:mtu_updated");
        assert_eq!(
            default["data"],
            serde_json::json!({"old": 1200, "new": 1300})
        );
        let migrated = serde_json::to_value(with_path(
            7,
            PathEvent::MtuUpdated {
                old: 1300,
                new: 1200,
            },
        ))
        .unwrap();
        assert_eq!(migrated["tuple"], "7");
        assert_eq!(migrated["data"]["new"], 1200);
        assert!(migrated["data"].get("done").is_none());
    }

    #[test]
    fn tuple_and_cid_schema() {
        let event = PathEvent::TupleAssigned(TupleAssigned {
            tuple_id: String::new(),
            tuple_remote: Some("[::1]:443".parse::<SocketAddr>().unwrap().into()),
            tuple_local: None,
        });
        let value = serde_json::to_value(event).unwrap();
        assert_eq!(value["name"], "quic:tuple_assigned");
        assert_eq!(value["data"]["tuple_id"], "");
        assert_eq!(value["data"]["tuple_remote"]["ip_v6"], "::1");
        assert_eq!(value["data"]["tuple_remote"]["port_v6"], 443);
        assert!(value["data"].get("tuple_local").is_none());
        let value = serde_json::to_value(PathEvent::ConnectionIdUpdated {
            initiator: "remote",
            old: Some("abcd".into()),
            new: "ef12".into(),
        })
        .unwrap();
        assert_eq!(
            value["data"],
            serde_json::json!({"initiator": "remote", "old": "abcd", "new": "ef12"})
        );
    }
}
