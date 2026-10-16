//! WebSocket lifecycle summaries for raw sockets and HTTP upgrades, including
//! extended CONNECT. Byte counts use [`Message::len`], normally application
//! message bytes before compression; raw frame messages retain their own length.
//! No payloads or per-frame trace events are recorded.
//! Counts cover messages read or accepted for writing (including caller-sent
//! control messages), not automatic replies or bytes acknowledged by the peer.
//! Close codes describe received or queued close frames.

use crate::protocol::{Message, ProtocolError, Role};
use dial9_trace_format::TraceEvent;
use rama_core::telemetry::dial9::{Operation, Outcome, core::clock_monotonic_ns};

#[cfg(test)]
pub(crate) fn recorder_slot() -> parking_lot::MutexGuard<'static, ()> {
    static SLOT: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    SLOT.lock()
}

#[derive(TraceEvent)]
pub struct WebSocketOpened {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub flow_id: u64,
    pub operation_id: u64,
    pub server: bool,
}

#[derive(TraceEvent)]
pub struct WebSocketClosed {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub flow_id: u64,
    pub operation_id: u64,
    pub outcome: u32,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    /// Zero when no close code was observed in this direction.
    pub sent_close_code: u32,
    pub received_close_code: u32,
}

#[derive(Debug)]
pub(crate) struct Lifecycle {
    operation: Option<Operation>,
    messages_sent: u64,
    messages_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
    pub(crate) sent_close_code: u32,
    received_close_code: u32,
}

impl Lifecycle {
    pub(crate) fn new(role: Role) -> Self {
        let operation = Operation::new("websocket");
        operation.record_event_with(|context| WebSocketOpened {
            timestamp_ns: clock_monotonic_ns(),
            flow_id: context.flow_id(),
            operation_id: context.operation_id(),
            server: role == Role::Server,
        });
        Self {
            operation: operation.is_recorded().then_some(operation),
            messages_sent: 0,
            messages_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            sent_close_code: 0,
            received_close_code: 0,
        }
    }

    pub(crate) fn message_size(&self, message: &Message) -> Option<u64> {
        self.operation.as_ref().map(|_| message.len() as u64)
    }

    pub(crate) fn read(&mut self, result: &Result<Message, ProtocolError>, terminated: bool) {
        if self.operation.is_none() {
            return;
        }
        if let Ok(message) = result {
            self.messages_received = self.messages_received.saturating_add(1);
            self.bytes_received = self.bytes_received.saturating_add(message.len() as u64);
            if let Message::Close(Some(frame)) = message {
                self.received_close_code = u32::from(u16::from(frame.code));
            }
        }
        self.result(result.as_ref().map(|_| ()), terminated);
    }

    pub(crate) fn written(
        &mut self,
        size: Option<u64>,
        result: &Result<(), ProtocolError>,
        terminated: bool,
    ) {
        if let Some(size) = size
            && (result.is_ok()
                || matches!(result, Err(ProtocolError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock))
        {
            self.messages_sent = self.messages_sent.saturating_add(1);
            self.bytes_sent = self.bytes_sent.saturating_add(size);
        }
        self.result(result.as_ref().map(|_| ()), terminated);
    }

    pub(crate) fn result(&mut self, result: Result<(), &ProtocolError>, terminated: bool) {
        match result {
            Ok(()) if terminated => self.finish(Outcome::Success),
            Err(ProtocolError::Io(error))
                if terminated && error.kind() == std::io::ErrorKind::ConnectionAborted =>
            {
                self.finish(Outcome::Success);
            }
            Err(ProtocolError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(ProtocolError::WriteBufferFull(_) | ProtocolError::SendAfterClosing) | Ok(()) => {}
            Err(_) => self.finish(Outcome::Error),
        }
    }

    fn finish(&mut self, outcome: Outcome) {
        let Some(operation) = self.operation.take() else {
            return;
        };
        operation.record_event_with(|context| WebSocketClosed {
            timestamp_ns: clock_monotonic_ns(),
            flow_id: context.flow_id(),
            operation_id: context.operation_id(),
            outcome: outcome as u32,
            messages_sent: self.messages_sent,
            messages_received: self.messages_received,
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            sent_close_code: self.sent_close_code,
            received_close_code: self.received_close_code,
        });
        operation.finish_with_bytes(outcome, self.bytes_sent, self.bytes_received);
    }
}

impl Drop for Lifecycle {
    fn drop(&mut self) {
        self.finish(Outcome::Cancelled);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::WebSocket;
    use dial9_trace_format::{decoder::Decoder, types::FieldValueRef};
    use rama_core::{
        rt::blocking::Runtime,
        telemetry::dial9::{DiskBuffer, recorder},
    };
    use std::{
        collections::BTreeMap,
        io::{self, Cursor, Read, Write},
    };

    struct Peer(Cursor<Vec<u8>>);

    impl Read for Peer {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.0.read(bytes)
        }
    }

    impl Write for Peer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn close_reset_and_drop_have_distinct_outcomes_and_keep_partial_bytes() {
        let _slot = recorder_slot();
        let dir = rama_utils::fs::tempdir().unwrap();
        let recorder = recorder(
            DiskBuffer::builder()
                .base_path(dir.path())
                .max_total_size(4 << 20)
                .build()
                .unwrap(),
        )
        .build();
        assert!(recorder.handle().is_enabled());
        let runtime = Runtime::builder()
            .with_dial9_recorder(recorder)
            .with_worker_threads(1)
            .try_build()
            .unwrap();
        runtime.block_on(async {
            // The peer sends one text message followed by a normal close.
            let mut closed = WebSocket::from_raw_socket(
                Peer(Cursor::new(vec![
                    0x81, 3, b'o', b'n', b'e', 0x88, 2, 3, 232,
                ])),
                Role::Client,
                None,
            );
            assert_eq!(closed.read().unwrap(), Message::text("one"));
            assert!(matches!(closed.read(), Ok(Message::Close(_))));
            assert!(matches!(closed.read(), Err(ProtocolError::Io(_))));
            drop(closed);
            // EOF without a close handshake is an error, even though the state is terminated.
            let mut reset = WebSocket::from_raw_socket(
                Peer(Cursor::new(vec![0x81, 3, b't', b'w', b'o'])),
                Role::Client,
                None,
            );
            assert_eq!(reset.read().unwrap(), Message::text("two"));
            assert!(matches!(
                reset.read(),
                Err(ProtocolError::ResetWithoutClosingHandshake)
            ));
            drop(reset);
            let mut cancelled =
                WebSocket::from_raw_socket(Peer(Cursor::new(vec![])), Role::Client, None);
            cancelled.send(Message::text("three")).unwrap();
            drop(cancelled);
        });
        drop(runtime);
        let bytes = std::fs::read(dir.path().join("trace.0.bin")).unwrap();
        let mut summaries = Vec::new();
        Decoder::new(&bytes)
            .unwrap()
            .for_each_event(|event| {
                if event.name != "WebSocketClosed" {
                    return;
                }
                let fields: BTreeMap<_, _> = event.field_names().zip(event.fields.iter()).collect();
                let value = |name| match fields[name] {
                    FieldValueRef::Varint(value) => *value,
                    _ => panic!("integer field"),
                };
                summaries.push((
                    value("outcome"),
                    value("bytes_sent"),
                    value("bytes_received"),
                    value("received_close_code"),
                    value("sent_close_code"),
                ));
            })
            .unwrap();
        assert_eq!(
            summaries,
            [
                (Outcome::Success as u64, 0, 3, 1000, 1000),
                (Outcome::Error as u64, 0, 3, 0, 0),
                (Outcome::Cancelled as u64, 5, 0, 0, 0),
            ]
        );
    }
}
