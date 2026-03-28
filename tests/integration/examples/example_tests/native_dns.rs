use super::utils;

#[tokio::test]
#[ignore]
async fn test_native_dns() {
    utils::init_tracing();

    let output = utils::ExampleRunner::run_with_args_output("native_dns", ["localhost"]).await;
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);

    #[cfg(any(target_vendor = "apple", target_os = "windows"))]
    {
        assert!(stdout.contains("localhost"));
        assert!(stdout.contains("127.0.0.1") || stdout.contains("::1"));
    }

    #[cfg(not(any(target_vendor = "apple", target_os = "windows")))]
    {
        assert!(stdout.contains("Apple/Windows only"));
    }
}
