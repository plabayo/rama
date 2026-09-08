use super::*;
use rama::{
    futures::StreamExt,
    http::ws::inspect::{CapturedWebSocketMessage, har::write_captured_websocket_json},
    stream::io::ReaderStream,
};
use tokio::io::AsyncWriteExt as _;

pub(in crate::cmd::serve::proxy::dashboard) async fn capture_json(
    State(state): State<DashboardState>,
    Path(IdPath { id }): Path<IdPath>,
) -> Response {
    let selected = match state.capture.exchange_capture(id) {
        Ok(selected) => selected,
        Err(error) => return error_response(StatusCode::NOT_FOUND, error),
    };
    let details = selected.summary_details();
    let metadata = match capture_metadata(&details) {
        Ok(metadata) => metadata,
        Err(error) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, error),
    };
    let mut records = Box::pin(selected.records_stream());
    let message_count = selected.count::<CapturedWebSocketMessage>();
    let stream = stream_fn(move |mut output| async move {
        let result = async {
            output.yield_item(Ok(Bytes::from(metadata))).await;
            let mut first = true;
            while let Some(record) = records.next().await {
                if !first {
                    output.yield_item(Ok(Bytes::from_static(b","))).await;
                }
                first = false;
                output
                    .yield_item(Ok(Bytes::from(serde_json::to_vec(&record?)?)))
                    .await;
            }
            output
                .yield_item(Ok(Bytes::from_static(b"],\"websocket\":[")))
                .await;
            let (mut writer, reader) = tokio::io::duplex(rama::utils::octets::kib(16));
            let produce = async {
                for index in 0..message_count {
                    let Some(message) = selected
                        .record_stream::<CapturedWebSocketMessage>(index)
                        .await?
                    else {
                        break;
                    };
                    if index != 0 {
                        writer.write_all(b",").await?;
                    }
                    write_captured_websocket_json(&mut writer, message).await?;
                }
                writer.shutdown().await?;
                Ok::<(), BoxError>(())
            };
            let consume = async {
                let mut chunks = ReaderStream::new(reader);
                while let Some(chunk) = chunks.next().await {
                    output.yield_item(Ok(chunk?)).await;
                }
                Ok::<(), BoxError>(())
            };
            tokio::try_join!(produce, consume)?;
            output.yield_item(Ok(Bytes::from_static(b"]}"))).await;
            Ok::<(), BoxError>(())
        }
        .await;
        if let Err(error) = result {
            output.yield_item(Err(error)).await;
        }
    });
    (
        Headers((
            ContentType::json(),
            ContentDisposition::attachment(&format!("rama-capture-{id}.json")),
            CacheControl::new().with_no_store(),
        )),
        Body::from_stream(stream),
    )
        .into_response()
}

// Only the metadata prefix is buffered. HTTP records and WebSocket messages
// remain typed and are serialized individually as the response is consumed.
fn capture_metadata(details: &CaptureDetails) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"{\"summary\":");
    serde_json::to_writer(&mut bytes, &details.summary)?;
    field(&mut bytes, "connection", &details.connection)?;
    field(
        &mut bytes,
        "connection_tls",
        &details.metadata.connection.get_ref::<TlsObservation>(),
    )?;
    field(
        &mut bytes,
        "upstream_tls",
        &details.metadata.upstream.get_ref::<TlsObservation>(),
    )?;
    field(
        &mut bytes,
        "user_agent",
        &details.metadata.exchange.get_ref::<UserAgentObservation>(),
    )?;
    bytes.extend_from_slice(b",\"records\":[");
    Ok(bytes)
}
fn field<T: serde::Serialize>(
    bytes: &mut Vec<u8>,
    name: &'static str,
    value: &T,
) -> Result<(), serde_json::Error> {
    bytes.push(b',');
    serde_json::to_writer(&mut *bytes, name)?;
    bytes.push(b':');
    serde_json::to_writer(bytes, value)
}
