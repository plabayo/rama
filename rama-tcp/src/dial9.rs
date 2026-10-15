//! TCP connection targets, paired with the `tcp.connect` operation's duration
//! and outcome. Each Happy Eyeballs attempt has its own operation identifier.

use dial9_trace_format::TraceEvent;
use rama_net::address::Host;

#[derive(TraceEvent)]
pub struct TcpConnectAttempt {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub flow_id: u64,
    pub operation_id: u64,
    pub remote_ip: Host,
    pub remote_port: u32,
}

#[cfg(test)]
mod tests {
    use crate::client::{DenyTcpStreamConnector, tcp_connect};
    use dial9_trace_format::{decoder::Decoder, types::FieldValueRef};
    use rama_core::{
        extensions::{Extensions, ExtensionsRef as _},
        rt::blocking::Runtime,
        telemetry::dial9::{DiskBuffer, TraceContext, recorder},
    };

    #[test]
    fn successful_and_denied_connections_record_the_target_and_distinct_outcomes() {
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
        let port = runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let target = rama_net::address::HostWithPort::from(address);
            let (stream, _) = tcp_connect(&Extensions::new(), target.clone(), &())
                .await
                .unwrap();
            assert_ne!(
                stream
                    .extensions()
                    .get_ref::<TraceContext>()
                    .unwrap()
                    .operation_id(),
                0
            );
            tcp_connect(&Extensions::new(), target, &DenyTcpStreamConnector::new())
                .await
                .unwrap_err();
            address.port()
        });
        drop(runtime);
        let bytes = std::fs::read(dir.path().join("trace.0.bin")).unwrap();
        let mut attempts = 0;
        let mut outcomes = Vec::new();
        Decoder::new(&bytes)
            .unwrap()
            .for_each_event(|event| {
                if event.name == "TcpConnectAttempt" {
                    attempts += 1;
                    for (name, value) in event.field_names().zip(event.fields.iter()) {
                        match (name, value) {
                            ("remote_ip", FieldValueRef::String(value)) => {
                                assert_eq!(*value, "127.0.0.1")
                            }
                            ("remote_port", FieldValueRef::Varint(value)) => {
                                assert_eq!(*value, u64::from(port))
                            }
                            _ => {}
                        }
                    }
                } else if event.name == "RamaOperationFinished" {
                    for (name, value) in event.field_names().zip(event.fields.iter()) {
                        if name == "outcome"
                            && let FieldValueRef::Varint(value) = value
                        {
                            outcomes.push(*value);
                        }
                    }
                }
            })
            .unwrap();
        outcomes.sort();
        assert_eq!(attempts, 2);
        assert_eq!(outcomes, [0, 1]);
    }
}
