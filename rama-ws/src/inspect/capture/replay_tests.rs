use super::*;

#[tokio::test]
async fn cancelling_a_sender_keeps_queued_payload_memory_admitted() {
    let budget = Arc::new(Semaphore::new(8));
    let payload = Bytes::from_owner(ReplayPayload {
        bytes: vec![0; 8],
        _permit: budget.clone().try_acquire_many_owned(8).unwrap(),
    });
    let (send, mut receive) = tokio::sync::mpsc::channel(1);
    let task = tokio::spawn(async move {
        send.send(payload.clone()).await.unwrap();
        std::future::pending::<()>().await;
        drop(payload);
    });
    let queued = receive.recv().await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(budget.available_permits(), 0);
    let writing = queued.clone();
    drop(queued);
    assert_eq!(budget.available_permits(), 0);
    drop(writing);
    assert_eq!(budget.available_permits(), 8);
}
