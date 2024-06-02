use super::utils;

#[tokio::test]
#[ignore]
async fn test_help() {
    let lines = utils::RamaService::run(vec!["help"]).unwrap();
    assert!(lines.contains("rama cli to move and transform network packets"));
    assert!(lines.contains("Usage:"));
    assert!(lines.contains("Commands:"));
    assert!(lines.contains("Options:"));
}

#[tokio::test]
#[ignore]
async fn test_help_ip() {
    let lines = utils::RamaService::run(vec!["help", "ip"]).unwrap();
    assert!(lines.contains("rama ip service"));
    assert!(lines.contains("Usage:"));
    assert!(lines.contains("Options:"));
}

#[tokio::test]
#[ignore]
async fn test_help_echo() {
    let lines = utils::RamaService::run(vec!["help", "echo"]).unwrap();
    assert!(lines.contains("rama echo service"));
    assert!(lines.contains("Usage:"));
    assert!(lines.contains("Options:"));
}

#[tokio::test]
#[ignore]
async fn test_help_http() {
    let lines = utils::RamaService::run(vec!["help", "http"]).unwrap();
    assert!(lines.contains("rama http client"));
    assert!(lines.contains("Usage:"));
    assert!(lines.contains("Arguments:"));
    assert!(lines.contains("rama http :3000"));
    assert!(lines.contains("Options:"));
}
