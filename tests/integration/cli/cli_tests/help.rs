use super::utils;

#[tokio::test]
#[ignore]
async fn test_help() {
    utils::init_tracing();

    let lines = utils::RamaService::run(vec!["help"]).unwrap();
    assert!(lines.contains("rama cli to move and transform network packets"));
    assert!(lines.contains("Usage:"));
    assert!(lines.contains("Commands:"));
    assert!(lines.contains("Options:"));
}

#[tokio::test]
#[ignore]
async fn test_help_ip() {
    utils::init_tracing();

    let lines = utils::RamaService::run(vec!["help", "serve", "ip"]).unwrap();
    assert!(lines.contains("rama ip service"));
    assert!(lines.contains("Usage:"));
    assert!(lines.contains("Options:"));
}

#[tokio::test]
#[ignore]
async fn test_help_echo() {
    utils::init_tracing();

    let lines = utils::RamaService::run(vec!["help", "serve", "echo"]).unwrap();
    assert!(lines.contains("rama echo service"));
    assert!(lines.contains("Usage:"));
    assert!(lines.contains("Options:"));
}

#[tokio::test]
#[ignore]
async fn test_help_http() {
    utils::init_tracing();

    let lines = utils::RamaService::run(vec!["help", "send"]).unwrap();
    assert!(lines.contains("send (client) request"));
    assert!(lines.contains("Usage:"));
    assert!(lines.contains("Arguments:"));
    assert!(lines.contains("Options:"));
}
