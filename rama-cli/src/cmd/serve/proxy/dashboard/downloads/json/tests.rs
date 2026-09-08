use rama::http::inspect::control::{HttpMessageDirection, Payload};
use tokio::io::AsyncReadExt as _;

use super::*;

#[tokio::test]
async fn streamed_interception_json_preserves_typed_metadata_and_raw_payloads() {
    for binary in [false, true] {
        let bytes = Bytes::from(vec![b'x'; kib(128)]);
        let record = CapturedRecordStream {
            metadata: StoredRecord::Interception {
                direction: HttpMessageDirection::Ingress,
                outcome: "Forwarded".into(),
                original_headers: HeaderMap::new(),
                original_status: None,
                original_payload: Some(if binary {
                    Payload::binary(Bytes::new())
                } else {
                    Payload::text("")
                }),
                original_payload_length: Some(bytes.len() as u64),
                forwarded_headers: None,
            },
            payload: Box::pin(std::io::Cursor::new(bytes.clone())),
        };
        let (mut writer, mut reader) = tokio::io::duplex(kib(1));
        let mut wire = Vec::new();
        let produce = async {
            write_http_record(&mut writer, record).await.unwrap();
            writer.shutdown().await.unwrap();
        };
        let consume = async {
            reader.read_to_end(&mut wire).await.unwrap();
        };
        tokio::join!(produce, consume);
        let StoredRecord::Interception {
            original_payload: Some(payload),
            original_payload_length,
            ..
        } = serde_json::from_slice::<StoredRecord>(&wire).unwrap()
        else {
            panic!("missing interception")
        };
        assert_eq!(payload.bytes(), &bytes);
        assert_eq!(payload.is_binary(), binary);
        assert_eq!(original_payload_length, Some(bytes.len() as u64));
    }
}
