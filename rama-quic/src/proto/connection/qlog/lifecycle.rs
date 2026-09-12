//! Connection lifetime events. Observation does not drive the transport state machine.

use std::{borrow::Cow, net::SocketAddr};

use serde::Serialize;

use crate::proto::{
    ConnectionId, Instant,
    connection::{Connection, ConnectionError, State},
    frame::Close,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::proto::connection) enum ConnectionState {
    Attempted,
    HandshakeStarted,
    HandshakeComplete,
    HandshakeConfirmed,
    Closing,
    Draining,
    Closed,
}

#[derive(Serialize)]
#[serde(tag = "name", content = "data")]
enum Event<'a> {
    #[serde(rename = "quic:connection_started")]
    Started {
        local: TupleEndpointInfo,
        remote: TupleEndpointInfo,
    },
    #[serde(rename = "quic:connection_state_updated")]
    StateUpdated {
        #[serde(skip_serializing_if = "Option::is_none")]
        old: Option<ConnectionState>,
        new: ConnectionState,
    },
    #[serde(rename = "quic:connection_closed")]
    Closed(ConnectionClosed<'a>),
}

#[derive(Serialize)]
struct TupleEndpointInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_v4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port_v4: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_v6: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port_v6: Option<u16>,
    connection_ids: [String; 1],
}

impl TupleEndpointInfo {
    fn new(address: Option<SocketAddr>, cid: ConnectionId) -> Self {
        Self {
            ip_v4: address
                .filter(SocketAddr::is_ipv4)
                .map(|a| a.ip().to_string()),
            port_v4: address.filter(SocketAddr::is_ipv4).map(|a| a.port()),
            ip_v6: address
                .filter(SocketAddr::is_ipv6)
                .map(|a| a.ip().to_string()),
            port_v6: address.filter(SocketAddr::is_ipv6).map(|a| a.port()),
            connection_ids: [cid.to_string()],
        }
    }
}

#[derive(Default, Serialize)]
struct ConnectionClosed<'a> {
    initiator: &'static str,
    trigger: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    connection_error: Option<Cow<'static, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    application_error: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<Cow<'a, str>>,
}

impl<'a> ConnectionClosed<'a> {
    fn transport(initiator: &'static str, code: u64, reason: Cow<'a, str>) -> Self {
        let (connection_error, error_code) = transport_error(code);
        Self {
            initiator,
            trigger: if code == 0 { "unspecified" } else { "error" },
            connection_error: Some(connection_error),
            error_code,
            reason: Some(reason),
            ..Self::default()
        }
    }

    fn close(initiator: &'static str, reason: &'a Close) -> Self {
        match reason {
            Close::Connection(close) => Self::transport(
                initiator,
                close.error_code.into(),
                String::from_utf8_lossy(&close.reason),
            ),
            Close::Application(close) => Self {
                initiator,
                trigger: "application",
                application_error: Some("unknown"),
                error_code: Some(close.error_code.into()),
                reason: Some(String::from_utf8_lossy(&close.reason)),
                ..Self::default()
            },
        }
    }

    fn error(error: &'a ConnectionError) -> Self {
        match error {
            ConnectionError::TransportError(error) => {
                Self::transport("local", error.code.into(), Cow::Borrowed(&error.reason))
            }
            ConnectionError::ConnectionClosed(close) => Self::transport(
                "remote",
                close.error_code.into(),
                String::from_utf8_lossy(&close.reason),
            ),
            ConnectionError::ApplicationClosed(close) => Self {
                initiator: "remote",
                trigger: "application",
                application_error: Some("unknown"),
                error_code: Some(close.error_code.into()),
                reason: Some(String::from_utf8_lossy(&close.reason)),
                ..Self::default()
            },
            other => Self {
                initiator: if matches!(other, ConnectionError::Reset) {
                    "remote"
                } else {
                    "local"
                },
                trigger: match other {
                    ConnectionError::VersionMismatch => "version_mismatch",
                    ConnectionError::Reset => "stateless_reset",
                    ConnectionError::TimedOut => "idle_timeout",
                    ConnectionError::LocallyClosed => "application",
                    _ => "error",
                },
                reason: Some(Cow::Owned(other.to_string())),
                ..Self::default()
            },
        }
    }
}

fn transport_error(code: u64) -> (Cow<'static, str>, Option<u64>) {
    let name = match code {
        0x00 => "no_error",
        0x01 => "internal_error",
        0x02 => "connection_refused",
        0x03 => "flow_control_error",
        0x04 => "stream_limit_error",
        0x05 => "stream_state_error",
        0x06 => "final_size_error",
        0x07 => "frame_encoding_error",
        0x08 => "transport_parameter_error",
        0x09 => "connection_id_limit_error",
        0x0a => "protocol_violation",
        0x0b => "invalid_token",
        0x0c => "application_error",
        0x0d => "crypto_buffer_exceeded",
        0x0e => "key_update_error",
        0x0f => "aead_limit_reached",
        0x10 => "no_viable_path",
        0x100..=0x1ff => return (format!("crypto_error_0x{code:03x}").into(), None),
        _ => return (Cow::Borrowed("unknown"), Some(code)),
    };
    (Cow::Borrowed(name), None)
}

impl Connection {
    pub(in crate::proto::connection) fn qlog_connection_started(&mut self, now: Instant) {
        self.config
            .qlog_sink
            .emit(self.trace_cid, now, || Event::Started {
                local: TupleEndpointInfo::new(self.path.local, self.handshake_cid),
                remote: TupleEndpointInfo::new(Some(self.path.remote), self.rem_handshake_cid),
            });
        self.qlog_state_updated(now, ConnectionState::Attempted);
    }

    fn qlog_state_updated(&mut self, now: Instant, new: ConnectionState) {
        if !self.config.qlog_sink.is_enabled() || self.qlog_state == Some(new) {
            return;
        }
        let old = self.qlog_state.replace(new);
        self.config
            .qlog_sink
            .emit(self.trace_cid, now, || Event::StateUpdated { old, new });
    }

    pub(in crate::proto::connection) fn qlog_handshake_started(&mut self, now: Instant) {
        if self.qlog_state == Some(ConnectionState::Attempted) {
            self.qlog_state_updated(now, ConnectionState::HandshakeStarted);
        }
    }

    pub(in crate::proto::connection) fn qlog_connection_error(
        &mut self,
        now: Instant,
        error: &ConnectionError,
    ) {
        if !self.config.qlog_sink.is_enabled() || self.qlog_closed {
            return;
        }
        self.qlog_closed = true;
        self.config.qlog_sink.emit(self.trace_cid, now, || {
            Event::Closed(ConnectionClosed::error(error))
        });
    }

    pub(in crate::proto::connection) fn qlog_local_close(&mut self, now: Instant, reason: &Close) {
        if !self.config.qlog_sink.is_enabled() || self.qlog_closed {
            return;
        }
        self.qlog_closed = true;
        self.config.qlog_sink.emit(self.trace_cid, now, || {
            Event::Closed(ConnectionClosed::close("local", reason))
        });
    }

    pub(in crate::proto::connection) fn qlog_handshake_timeout(&mut self, now: Instant) {
        if !self.config.qlog_sink.is_enabled() || self.qlog_closed {
            return;
        }
        self.qlog_closed = true;
        self.config.qlog_sink.emit(self.trace_cid, now, || {
            Event::Closed(ConnectionClosed {
                initiator: "local",
                trigger: "error",
                reason: Some(Cow::Borrowed("handshake timeout")),
                ..ConnectionClosed::default()
            })
        });
    }

    pub(in crate::proto::connection) fn qlog_discarded(&mut self, now: Instant) {
        self.qlog_state_updated(now, ConnectionState::Closed);
    }

    /// Called at packet processing boundaries, before application polling can consume the error.
    pub(in crate::proto::connection) fn qlog_observe_state(&mut self, now: Instant) {
        if !self.config.qlog_sink.is_enabled() {
            return;
        }
        if !self.qlog_closed
            && let Some(error) = &self.error
        {
            self.qlog_closed = true;
            self.config.qlog_sink.emit(self.trace_cid, now, || {
                Event::Closed(ConnectionClosed::error(error))
            });
        }
        match self.state {
            State::Handshake(_) => {}
            State::Established => {
                if matches!(
                    self.qlog_state,
                    None | Some(ConnectionState::Attempted | ConnectionState::HandshakeStarted)
                ) {
                    self.qlog_state_updated(now, ConnectionState::HandshakeComplete);
                }
                if self.handshake_confirmed() {
                    self.qlog_state_updated(now, ConnectionState::HandshakeConfirmed);
                }
            }
            State::Closed(_) => self.qlog_state_updated(now, ConnectionState::Closing),
            State::Draining => self.qlog_state_updated(now, ConnectionState::Draining),
            State::Drained => self.qlog_discarded(now),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{TransportError, TransportErrorCode, VarInt, coding::Codec, frame};
    use rama_core::bytes::Bytes;
    use serde_json::json;

    fn peer_close(code: TransportErrorCode) -> frame::ConnectionClose {
        frame::ConnectionClose {
            error_code: code,
            frame_type: None,
            reason: Bytes::from_static(b"closure reason"),
        }
    }

    #[test]
    fn transport_closes_serialize_standard_error_names() {
        // These are the QUIC error names in the serialized event contract, not Rust's
        // Display descriptions or Debug names. NO_ERROR does not imply an error trigger.
        for (code, name, trigger) in [
            (TransportErrorCode::NO_ERROR, "no_error", "unspecified"),
            (
                TransportErrorCode::INTERNAL_ERROR,
                "internal_error",
                "error",
            ),
            (
                TransportErrorCode::CONNECTION_REFUSED,
                "connection_refused",
                "error",
            ),
            (
                TransportErrorCode::FLOW_CONTROL_ERROR,
                "flow_control_error",
                "error",
            ),
            (
                TransportErrorCode::STREAM_LIMIT_ERROR,
                "stream_limit_error",
                "error",
            ),
            (
                TransportErrorCode::STREAM_STATE_ERROR,
                "stream_state_error",
                "error",
            ),
            (
                TransportErrorCode::FINAL_SIZE_ERROR,
                "final_size_error",
                "error",
            ),
            (
                TransportErrorCode::FRAME_ENCODING_ERROR,
                "frame_encoding_error",
                "error",
            ),
            (
                TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                "transport_parameter_error",
                "error",
            ),
            (
                TransportErrorCode::CONNECTION_ID_LIMIT_ERROR,
                "connection_id_limit_error",
                "error",
            ),
            (
                TransportErrorCode::PROTOCOL_VIOLATION,
                "protocol_violation",
                "error",
            ),
            (TransportErrorCode::INVALID_TOKEN, "invalid_token", "error"),
            (
                TransportErrorCode::APPLICATION_ERROR,
                "application_error",
                "error",
            ),
            (
                TransportErrorCode::CRYPTO_BUFFER_EXCEEDED,
                "crypto_buffer_exceeded",
                "error",
            ),
            (
                TransportErrorCode::KEY_UPDATE_ERROR,
                "key_update_error",
                "error",
            ),
            (
                TransportErrorCode::AEAD_LIMIT_REACHED,
                "aead_limit_reached",
                "error",
            ),
            (
                TransportErrorCode::NO_VIABLE_PATH,
                "no_viable_path",
                "error",
            ),
        ] {
            let local = Close::Connection(peer_close(code));
            let remote = ConnectionError::ConnectionClosed(peer_close(code));
            let internal =
                ConnectionError::TransportError(TransportError::new(code, "closure reason"));
            for (initiator, event) in [
                (
                    "local",
                    Event::Closed(ConnectionClosed::close("local", &local)),
                ),
                ("remote", Event::Closed(ConnectionClosed::error(&remote))),
                ("local", Event::Closed(ConnectionClosed::error(&internal))),
            ] {
                assert_eq!(
                    serde_json::to_value(event).unwrap(),
                    json!({
                        "name": "quic:connection_closed",
                        "data": {
                            "initiator": initiator,
                            "trigger": trigger,
                            "connection_error": name,
                            "reason": "closure reason"
                        }
                    }),
                    "transport code {code:?}, initiator {initiator}"
                );
            }
        }
    }

    #[test]
    fn unknown_transport_codes_remain_numeric() {
        // Exercise boundaries around assigned and TLS error ranges, plus the largest wire
        // code. A future/unknown error must retain its exact value, rather than a TLS name.
        for raw in [0x11, 0xff, 0x200, VarInt::MAX.into_inner()] {
            let mut encoded = Vec::new();
            VarInt::from_u64(raw).unwrap().encode(&mut encoded);
            let code = TransportErrorCode::decode(&mut encoded.as_slice()).unwrap();
            let local = Close::Connection(peer_close(code));
            let remote = ConnectionError::ConnectionClosed(peer_close(code));
            for (initiator, event) in [
                (
                    "local",
                    Event::Closed(ConnectionClosed::close("local", &local)),
                ),
                ("remote", Event::Closed(ConnectionClosed::error(&remote))),
            ] {
                assert_eq!(
                    serde_json::to_value(event).unwrap(),
                    json!({
                        "name": "quic:connection_closed",
                        "data": {
                            "initiator": initiator,
                            "trigger": "error",
                            "connection_error": "unknown",
                            "error_code": raw,
                            "reason": "closure reason"
                        }
                    })
                );
            }
        }
    }

    #[test]
    fn tls_alerts_serialize_as_zero_padded_crypto_error_names() {
        for (alert, name) in [
            (0x00, "crypto_error_0x100"),
            (0x0a, "crypto_error_0x10a"),
            (0x2a, "crypto_error_0x12a"),
            (0xff, "crypto_error_0x1ff"),
        ] {
            let error =
                ConnectionError::ConnectionClosed(peer_close(TransportErrorCode::crypto(alert)));
            assert_eq!(
                serde_json::to_value(Event::Closed(ConnectionClosed::error(&error))).unwrap(),
                json!({
                    "name": "quic:connection_closed",
                    "data": {
                        "initiator": "remote",
                        "trigger": "error",
                        "connection_error": name,
                        "reason": "closure reason"
                    }
                })
            );
        }
    }

    #[test]
    fn internal_close_causes_have_specific_triggers_without_fabricated_wire_codes() {
        for (error, initiator, trigger, reason) in [
            (
                ConnectionError::VersionMismatch,
                "local",
                "version_mismatch",
                "peer doesn't implement any supported version",
            ),
            (
                ConnectionError::LocallyClosed,
                "local",
                "application",
                "closed",
            ),
            (
                ConnectionError::Reset,
                "remote",
                "stateless_reset",
                "reset by peer",
            ),
            (
                ConnectionError::TimedOut,
                "local",
                "idle_timeout",
                "timed out",
            ),
            (
                ConnectionError::CidsExhausted,
                "local",
                "error",
                "CIDs exhausted",
            ),
        ] {
            assert_eq!(
                serde_json::to_value(Event::Closed(ConnectionClosed::error(&error))).unwrap(),
                json!({
                    "name": "quic:connection_closed",
                    "data": { "initiator": initiator, "trigger": trigger, "reason": reason }
                })
            );
        }
    }

    #[test]
    fn application_closes_preserve_large_codes_and_render_non_utf8_reasons_as_text() {
        let close = frame::ApplicationClose {
            error_code: VarInt::MAX,
            reason: Bytes::from_static(b"reason: \xff"),
        };
        let local = Close::Application(close.clone());
        let remote = ConnectionError::ApplicationClosed(close);
        for (initiator, event) in [
            (
                "local",
                Event::Closed(ConnectionClosed::close("local", &local)),
            ),
            ("remote", Event::Closed(ConnectionClosed::error(&remote))),
        ] {
            assert_eq!(
                serde_json::to_value(event).unwrap(),
                json!({
                    "name": "quic:connection_closed",
                    "data": {
                        "initiator": initiator,
                        "trigger": "application",
                        "application_error": "unknown",
                        "error_code": 4_611_686_018_427_387_903_u64,
                        "reason": "reason: \u{fffd}"
                    }
                })
            );
        }
    }
}
