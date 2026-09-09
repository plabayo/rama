use std::{sync::mpsc, time::Duration};

use tokio::sync::oneshot;

use super::*;

#[tokio::test]
async fn cancelling_pending_creation_cleans_up_its_late_artifact() {
    let directory = rama_utils::fs::tempdir().unwrap();
    let dir = directory.path().to_owned();
    let (cleanup, worker) = TempPathCleanup::new();
    let worker = tokio::spawn(worker.run());
    let (started, starting) = oneshot::channel();
    let (release, resume) = mpsc::sync_channel(1);
    let (created, finished) = oneshot::channel();
    let task = tokio::spawn({
        let cleanup = cleanup.clone();
        create(move || {
            started.send(()).unwrap();
            resume.recv().unwrap();
            let (path, file) = create_temp_file_sync(&dir, "cancel-test", cleanup)?;
            created.send(path.to_path_buf()).unwrap();
            Ok((path, file))
        })
    });

    starting.await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    release.send(()).unwrap();
    let path = finished.await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            cleanup.flush().await;
            if !tokio::fs::try_exists(&path).await.unwrap() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("an abandoned creation result must remove its completed artifact");
    drop(cleanup);
    worker.await.unwrap();
}
