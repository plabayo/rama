use super::utils;
use rama::{http::BodyExtractExt, service::Context};

#[tokio::test]
#[ignore]
async fn test_tls_termination() {
    utils::init_tracing();

    // On windows this test is for some reason flaky... so not run it for now on that platform.
    // NOTE: if you are a contributor on windows, feel free to enable this and fix it...
    #[cfg(not(target_os = "windows"))]
    {
        let runner = utils::ExampleRunner::interactive("tls_termination");

        let reply = runner
            .get("http://127.0.0.1:62800")
            .send(Context::default())
            .await
            .unwrap()
            .try_into_string()
            .await
            .unwrap();

        assert_eq!("Hello world!", reply);

        let reply = runner
            .get("https://127.0.0.1:63800")
            .send(Context::default())
            .await
            .unwrap()
            .try_into_string()
            .await
            .unwrap();

        assert_eq!("Hello world!", reply);
    }
}
