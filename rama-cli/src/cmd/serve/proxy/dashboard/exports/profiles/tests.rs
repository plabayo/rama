use rama::ua::profile::UserAgentDatabase;
use tokio::{io::AsyncReadExt as _, sync::Semaphore};

use super::*;

fn profile() -> UserAgentProfileInput {
    let database = UserAgentDatabase::try_embedded().unwrap();
    let observed = database.iter().next().unwrap();
    let mut profile = UserAgentProfileInput::new(observed.ua_str().unwrap());
    profile.h1_settings = Some(observed.http.h1.settings.clone());
    profile.h1_headers_navigate = Some(observed.http.h1.headers.navigate.clone());
    profile.h2_settings = Some(observed.http.h2.settings.clone());
    profile.h2_headers_navigate = Some(observed.http.h2.headers.navigate.clone());
    profile.tls_client_hello = Some(observed.tls.client_hello.clone());
    profile
}

async fn staged(limit: Arc<Semaphore>) -> StagedProfiles {
    tokio::task::spawn_blocking(move || {
        StagedProfiles::create(Some(limit.try_acquire_owned().unwrap())).unwrap()
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn profile_download_streams_valid_json_and_retains_admission_until_drop() {
    let limit = Arc::new(Semaphore::new(1));
    let staged = staged(limit.clone()).await;
    let path = staged.staging.path().to_owned();
    let mut profile = profile();
    profile.h1_headers_navigate.as_mut().unwrap().insert(
        "x-padding",
        rama::http::HeaderValue::from_bytes("x".repeat(kib(32)).as_bytes()).unwrap(),
    );
    let expected = serde_json::to_vec(&[&profile]).unwrap();
    let mut download =
        tokio::task::spawn_blocking(move || staged.write(profile, true).unwrap().finish().unwrap())
            .await
            .unwrap();
    assert_eq!(download.length, expected.len() as u64);
    assert_eq!(limit.available_permits(), 0);
    assert!(path.exists());
    let mut bytes = Vec::new();
    download.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, expected);
    assert_eq!(
        UserAgentDatabase::try_from_json_slice(&bytes)
            .unwrap()
            .len(),
        1
    );
    drop(download);
    assert!(!path.exists());
    assert_eq!(limit.available_permits(), 1);
}

#[tokio::test]
async fn invalid_profiles_remove_staged_output_and_release_admission() {
    let limit = Arc::new(Semaphore::new(1));
    let staged = staged(limit.clone()).await;
    let path = staged.staging.path().to_owned();
    let error = tokio::task::spawn_blocking(move || {
        staged
            .write(UserAgentProfileInput::new("incomplete"), true)
            .err()
            .unwrap()
    })
    .await
    .unwrap();
    assert_eq!(
        error.downcast_ref::<IoError>().unwrap().kind(),
        ErrorKind::InvalidInput
    );
    assert!(!path.exists());
    assert_eq!(limit.available_permits(), 1);
}
