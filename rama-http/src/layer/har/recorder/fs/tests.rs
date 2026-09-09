use base64::{Engine as _, engine::general_purpose::STANDARD};
use rama_utils::octets::kib;
use serde_json::Value;

use super::capture::write_web_socket_capture;
use super::*;
use crate::{Request, Response, mime::Mime};

#[test]
fn file_recorder_can_be_constructed_without_a_runtime() {
    let recorder = FileRecorder::default();
    assert!(recorder.task.task.lock().is_some());
}

#[tokio::test]
async fn stop_before_any_recording_is_a_no_op() {
    let dir = rama_utils::fs::tempdir().unwrap();
    let recorder = FileRecorder::new(dir.path().to_owned(), "unused".to_owned());

    tokio::time::timeout(std::time::Duration::from_secs(2), recorder.stop_record())
        .await
        .unwrap();

    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn exact_path_recorder_writes_the_requested_file() {
    let dir = rama_utils::fs::tempdir().unwrap();
    let path = dir.path().join("nested").join("capture.har");
    let recorder = FileRecorder::try_new_at(path.clone()).unwrap();

    let extensions = recorder.record(spec::Log::default()).await.unwrap();
    assert_eq!(extensions.get_ref::<HarFilePath>().unwrap().as_ref(), path);
    recorder.stop_record().await;

    let bytes = tokio::fs::read(&path).await.unwrap();
    serde_json::from_slice::<spec::LogFile>(&bytes).unwrap();
    assert_eq!(
        std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
        1
    );
}

#[tokio::test]
async fn dropping_temp_path_defers_file_io_to_cleanup_worker() {
    let dir = rama_utils::fs::tempdir().unwrap();
    let path = dir.path().join("artifact");
    tokio::fs::write(&path, b"temporary").await.unwrap();
    let (temp_cleanup, temp_cleanup_worker) = TempPathCleanup::new();

    drop(TempPath::new(path.clone(), temp_cleanup.clone()));
    assert!(path.exists(), "TempPath::drop must not perform file I/O");

    let temp_cleanup_task = tokio::spawn(temp_cleanup_worker.run());
    temp_cleanup.flush().await;
    assert!(!path.exists());
    drop(temp_cleanup);
    temp_cleanup_task.await.unwrap();
}

#[tokio::test]
async fn stop_record_waits_until_the_har_file_is_complete() {
    let dir = rama_utils::fs::tempdir().unwrap();
    let recorder = FileRecorder::new(dir.path().to_owned(), "recording".to_owned());

    let extensions = recorder.record(spec::Log::default()).await.unwrap();
    let path = extensions.get_ref::<HarFilePath>().unwrap().to_owned();

    recorder.stop_record().await;

    let bytes = tokio::fs::read(path.as_ref()).await.unwrap();
    serde_json::from_slice::<spec::LogFile>(&bytes).unwrap();
}

#[tokio::test]
async fn rollback_keeps_the_last_complete_har_entry_valid() {
    let dir = rama_utils::fs::tempdir().unwrap();
    let path = dir.path().join("rollback.har");
    let artifact = dir.path().join("entry.json");
    tokio::fs::write(&artifact, br#"{"marker":true}"#)
        .await
        .unwrap();
    let mut storage = Storage::try_new(path.clone(), &spec::Log::default())
        .await
        .unwrap();
    storage.append_artifact(&artifact).await.unwrap();
    let checkpoint = storage.valid_position;

    storage.file.write_all(b",{\"truncated\":").await.unwrap();
    storage.valid = false;
    storage.rollback(checkpoint).await.unwrap();
    storage.valid = true;
    finish_storage(storage).await;

    let value: Value = serde_json::from_slice(&tokio::fs::read(path).await.unwrap()).unwrap();
    assert_eq!(
        value["log"]["entries"],
        serde_json::json!([{"marker": true}])
    );
}

#[tokio::test]
async fn completed_workers_are_written_in_request_start_order() {
    let dir = rama_utils::fs::tempdir().unwrap();
    let (temp_cleanup, temp_cleanup_worker) = TempPathCleanup::new();
    let temp_cleanup_task = tokio::spawn(temp_cleanup_worker.run());
    let path = dir.path().join("ordered.har");
    let mut storage = Some(
        Storage::try_new(path.clone(), &spec::Log::default())
            .await
            .unwrap(),
    );
    let mut completed = BTreeMap::new();
    let mut next_sequence_to_write = 0;

    let (first_path, mut first) =
        create_temp_file_sync(dir.path(), "first", temp_cleanup.clone()).unwrap();
    first.write_all(br#"{"sequence":0}"#).unwrap();
    first.flush().unwrap();
    drop(first);
    let (second_path, mut second) =
        create_temp_file_sync(dir.path(), "second", temp_cleanup.clone()).unwrap();
    second.write_all(br#"{"sequence":1}"#).unwrap();
    second.flush().unwrap();
    drop(second);

    assert!(
        !handle_worker(
            Some(Ok((1, Ok(second_path)))),
            &mut storage,
            &mut completed,
            &mut next_sequence_to_write,
        )
        .await
    );
    assert!(
        !storage.as_ref().unwrap().has_entries,
        "a later capture must wait for the earlier capture"
    );
    assert!(
        !handle_worker(
            Some(Ok((0, Ok(first_path)))),
            &mut storage,
            &mut completed,
            &mut next_sequence_to_write,
        )
        .await
    );
    assert!(completed.is_empty());
    assert_eq!(next_sequence_to_write, 2);

    finish_storage(storage.take().unwrap()).await;
    temp_cleanup.flush().await;
    let value: Value = serde_json::from_slice(&tokio::fs::read(path).await.unwrap()).unwrap();
    assert_eq!(
        value["log"]["entries"],
        serde_json::json!([{"sequence": 0}, {"sequence": 1}])
    );
    drop(temp_cleanup);
    temp_cleanup_task.await.unwrap();
}

#[tokio::test]
async fn failed_storage_generation_discards_its_remaining_workers() {
    let dir = rama_utils::fs::tempdir().unwrap();
    let (temp_cleanup, temp_cleanup_worker) = TempPathCleanup::new();
    let temp_cleanup_task = tokio::spawn(temp_cleanup_worker.run());
    let old_path = dir.path().join("old.har");
    let fresh_path = dir.path().join("fresh.har");
    let mut storage = Some(
        Storage::try_new(old_path.clone(), &spec::Log::default())
            .await
            .unwrap(),
    );
    let missing_artifact =
        TempPath::new(dir.path().join("missing-entry.json"), temp_cleanup.clone());
    let mut completed = BTreeMap::new();
    let mut next_sequence_to_write = 0;

    assert!(
        handle_worker(
            Some(Ok((0, Ok(missing_artifact)))),
            &mut storage,
            &mut completed,
            &mut next_sequence_to_write,
        )
        .await,
        "an append failure invalidates the active generation"
    );

    let (artifact_path, mut artifact) =
        create_temp_file_sync(dir.path(), "late-entry", temp_cleanup.clone()).unwrap();
    artifact.write_all(br#"{"late":true}"#).unwrap();
    artifact.flush().unwrap();
    drop(artifact);
    let artifact_path_copy = artifact_path.to_path_buf();
    let mut workers = JoinSet::new();
    workers.spawn(async move { (1, Ok::<_, BoxError>(artifact_path)) });
    let (cancel, _) = watch::channel(false);

    reset_failed_generation(
        &cancel,
        &mut workers,
        &mut storage,
        &mut completed,
        2,
        &mut next_sequence_to_write,
    )
    .await;
    temp_cleanup.flush().await;

    assert!(storage.is_none());
    assert!(workers.is_empty());
    assert!(completed.is_empty());
    assert_eq!(next_sequence_to_write, 2);
    assert!(!artifact_path_copy.exists());

    finish_storage(
        Storage::try_new(fresh_path.clone(), &spec::Log::default())
            .await
            .unwrap(),
    )
    .await;
    for path in [old_path, fresh_path] {
        let log: spec::LogFile =
            serde_json::from_slice(&tokio::fs::read(path).await.unwrap()).unwrap();
        assert!(
            log.log.entries.is_empty(),
            "a worker from the failed generation must not reach another HAR file"
        );
    }
    drop(temp_cleanup);
    temp_cleanup_task.await.unwrap();
}

async fn body_artifact(dir: &Path, cleanup: &TempPathCleanup, bytes: &[u8]) -> BodyArtifact {
    let (path, mut file) = create_temp_file(dir.to_owned(), "test-body", cleanup.clone())
        .await
        .unwrap();
    file.write_all(bytes).await.unwrap();
    file.flush().await.unwrap();
    drop(file);
    BodyArtifact {
        path,
        size: bytes.len() as i64,
        outcome: CaptureOutcome::Complete,
        finished_at: Instant::now(),
    }
}

async fn serialized_entry(
    request: &[u8],
    mime: Option<Mime>,
    response: Option<&[u8]>,
    messages: Option<&[spec::WebSocketMessage]>,
) -> spec::Entry {
    let dir = rama_utils::fs::tempdir().unwrap();
    let (cleanup, worker) = TempPathCleanup::new();
    let worker = tokio::spawn(worker.run());
    let request_body = body_artifact(dir.path(), &cleanup, request).await;
    let request =
        spec::Request::from_http_request_parts(&Request::new(()).into_parts().0, &[], false)
            .unwrap();
    let response = match response {
        Some(bytes) => Some((
            spec::Response::from_http_response_parts(&Response::new(()).into_parts().0, &[], false)
                .unwrap(),
            body_artifact(dir.path(), &cleanup, bytes).await,
        )),
        None => None,
    };
    let messages = match messages {
        Some(messages) => {
            let (path, file) = create_temp_file(dir.path().to_owned(), "test-ws", cleanup.clone())
                .await
                .unwrap();
            let (sender, receiver) = mpsc::channel(messages.len().max(1));
            for message in messages {
                sender
                    .send(RecordedWebSocketMessage {
                        message: message.clone(),
                        observed_at: Instant::now(),
                    })
                    .await
                    .unwrap();
            }
            drop(sender);
            let (_closed, closed_at) = watch::channel(None);
            Some(
                write_web_socket_capture(file, path, receiver, closed_at)
                    .await
                    .unwrap(),
            )
        }
        None => None,
    };
    let path = build_entry_artifact(
        dir.path().to_owned(),
        "2026-01-01T00:00:00Z".parse().unwrap(),
        17,
        request,
        mime,
        request_body,
        response,
        messages,
        cleanup.clone(),
    )
    .await
    .unwrap();
    let entry = serde_json::from_slice::<spec::Entry>(&tokio::fs::read(&path).await.unwrap())
        .expect("one complete typed HAR entry without duplicate fields");
    assert_eq!(entry.time, 17);
    drop(path);
    cleanup.flush().await;
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    drop(cleanup);
    worker.await.unwrap();
    entry
}

#[tokio::test]
async fn file_entry_preserves_unicode_and_incomplete_utf8_across_read_boundaries() {
    let text = "x".repeat(kib(8) - 1) + "🦀\\\"\n";
    let mut binary = vec![b'x'; kib(8) - 1];
    binary.extend_from_slice(&[0xf0, 0x9f]);
    let entry = serialized_entry(text.as_bytes(), None, Some(&binary), None).await;
    assert_eq!(entry.request.body_size, text.len() as i64);
    assert_eq!(
        entry.request.post_data.unwrap().text.as_deref(),
        Some(text.as_str())
    );
    assert_eq!(entry.response.body_size, binary.len() as i64);
    assert_eq!(entry.response.content.encoding.as_deref(), Some("base64"));
    assert_eq!(
        STANDARD
            .decode(entry.response.content.text.unwrap().as_bytes())
            .unwrap(),
        binary
    );
}

#[tokio::test]
async fn file_entry_streams_form_fields_with_repeated_and_malformed_parameters() {
    let name = "n".repeat(kib(8) - 2);
    let form = format!("{name}=%E2%98%83&repeat=1&repeat=2&empty&bad=%GG%&partial=%E2%82");
    let entry = serialized_entry(
        form.as_bytes(),
        Some(crate::mime::APPLICATION_WWW_FORM_URLENCODED),
        Some(b""),
        None,
    )
    .await;
    let post = entry.request.post_data.unwrap();
    assert_eq!(post.text.as_deref(), Some(form.as_str()));
    let params = post.params.unwrap();
    assert_eq!(params.len(), 6);
    assert_eq!(params[0].name, name.as_str());
    assert_eq!(params[0].value.as_deref(), Some("☃"));
    for (parameter, (name, value)) in params[1..].iter().zip([
        ("repeat", "1"),
        ("repeat", "2"),
        ("empty", ""),
        ("bad", "%GG%"),
        ("partial", "�"),
    ]) {
        assert_eq!(parameter.name, name);
        assert_eq!(parameter.value.as_deref(), Some(value));
    }
}

#[tokio::test]
async fn file_entry_distinguishes_an_empty_response_from_an_absent_response() {
    for response in [Some(b"".as_slice()), None] {
        let entry = serialized_entry(b"", None, response, None).await;
        assert!(entry.request.post_data.is_none());
        assert_eq!(entry.response.content.size, 0);
        assert!(entry.response.content.text.is_none());
        assert!(entry.response.content.encoding.is_none());
        if response.is_some() {
            assert_eq!(entry.response.status, 200);
            assert_eq!(entry.response.body_size, 0);
        } else {
            assert_eq!(entry.response.status, 0);
            assert_eq!(entry.response.body_size, -1);
        }
    }
}

#[tokio::test]
async fn file_entry_streams_empty_and_populated_websocket_spools_once() {
    let messages = [
        spec::WebSocketMessage::text(spec::WebSocketMessageType::Send, 1.25, "hello\n☃"),
        spec::WebSocketMessage::binary(spec::WebSocketMessageType::Receive, 2.5, [0, 0xff]),
    ];
    for messages in [messages.as_slice(), &[]] {
        let entry = serialized_entry(b"", None, Some(b""), Some(messages)).await;
        assert_eq!(entry.resource_type.as_deref(), Some("websocket"));
        assert_eq!(entry.web_socket_messages.as_deref(), Some(messages));
    }
}
