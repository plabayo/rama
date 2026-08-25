//! End-to-end tests for `rama pac`.

use super::utils;

const STATEFUL_PAC: &str = r#"
var calls = 0;
function FindProxyForURL(url, host) {
    calls += 1;
    return calls === 1 ? "DIRECT" : "PROXY stateful.example:8080";
}
"#;

#[tokio::test]
#[ignore]
async fn test_pac_generate_then_evaluate() {
    utils::init_tracing();
    let directory = rama_utils::fs::tempdir().unwrap();
    let output = directory.path().join("generated.pac");
    let output_arg = output.to_str().unwrap();

    let (ok, stdout, stderr) = utils::RamaService::run_capture(&[
        "pac",
        "generate",
        "--route",
        "exact:health.corp.example=DIRECT",
        "--route",
        "*.corp.example=PROXY proxy.example:8080; DIRECT",
        "--default",
        "HTTPS fallback.example:443",
        "--output",
        output_arg,
    ])
    .unwrap();
    assert!(ok, "generate failed\nstdout: {stdout}\nstderr: {stderr}");

    let (ok, stdout, stderr) = utils::RamaService::run_capture(&[
        "pac",
        "eval",
        "--offline",
        "--format",
        "json",
        output_arg,
        "health.corp.example",
        "https://api.corp.example/path",
        "https://outside.example/",
    ])
    .unwrap();
    assert!(ok, "eval failed\nstdout: {stdout}\nstderr: {stderr}");

    let records: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(records[0]["uri"], "http://health.corp.example/");
    assert_eq!(records[0]["directives"], "DIRECT");
    assert_eq!(records[1]["directives"], "PROXY proxy.example:8080; DIRECT");
    assert_eq!(records[2]["directives"], "HTTPS fallback.example:443");
    assert!(!stderr.contains("Loading JavaScript engine"));
}

#[tokio::test]
#[ignore]
async fn test_pac_eval_reads_source_or_uris_from_stdin() {
    utils::init_tracing();
    let direct = b"function FindProxyForURL(url, host) { return 'DIRECT'; }";
    let (ok, stdout, stderr) = utils::RamaService::run_capture_with_stdin(
        &["pac", "eval", "-", "https://source-from-stdin.example/"],
        direct,
    )
    .unwrap();
    assert!(ok, "eval failed\nstdout: {stdout}\nstderr: {stderr}");
    assert_eq!(stdout, "https://source-from-stdin.example/\tDIRECT\n");

    let (ok, stdout, stderr) = utils::RamaService::run_capture_with_stdin(
        &[
            "pac",
            "eval",
            "--offline",
            "--source",
            "function FindProxyForURL(url, host) { return 'DIRECT'; }",
        ],
        b"https://first.example/\n\nhttps://second.example/\n",
    )
    .unwrap();
    assert!(ok, "eval failed\nstdout: {stdout}\nstderr: {stderr}");
    assert_eq!(
        stdout,
        "https://first.example/\tDIRECT\nhttps://second.example/\tDIRECT\n"
    );
}

#[tokio::test]
#[ignore]
async fn test_pac_eval_reuses_or_refreshes_the_javascript_realm() {
    utils::init_tracing();
    let args = [
        "pac",
        "eval",
        "--source",
        STATEFUL_PAC,
        "https://first.example/",
        "https://second.example/",
    ];
    let (ok, stdout, stderr) = utils::RamaService::run_capture(&args).unwrap();
    assert!(ok, "eval failed\nstdout: {stdout}\nstderr: {stderr}");
    assert_eq!(
        stdout,
        "https://first.example/\tDIRECT\nhttps://second.example/\tPROXY stateful.example:8080\n"
    );

    let mut fresh_args = args.to_vec();
    fresh_args.insert(2, "--fresh");
    let (ok, stdout, stderr) = utils::RamaService::run_capture(&fresh_args).unwrap();
    assert!(ok, "fresh eval failed\nstdout: {stdout}\nstderr: {stderr}");
    assert_eq!(
        stdout,
        "https://first.example/\tDIRECT\nhttps://second.example/\tDIRECT\n"
    );
}

#[tokio::test]
#[ignore]
async fn test_pac_eval_reports_each_failure_and_exits_unsuccessfully() {
    utils::init_tracing();
    let (ok, stdout, stderr) = utils::RamaService::run_capture(&[
        "pac",
        "eval",
        "--source",
        "function FindProxyForURL(url, host) { return 'DIRECT'; }",
        "mailto:missing-host@example.com",
        "https://valid.example/",
    ])
    .unwrap();

    assert!(!ok);
    assert!(stdout.contains("mailto:missing-host@example.com\tERROR\t"));
    assert!(stdout.contains("https://valid.example/\tDIRECT"));
    assert!(stderr.contains("one or more PAC evaluations failed"));

    let (ok, stdout, stderr) = utils::RamaService::run_capture(&[
        "pac",
        "eval",
        "--fail-fast",
        "--source",
        "function FindProxyForURL(url, host) { return 'DIRECT'; }",
        "mailto:missing-host@example.com",
        "https://must-not-run.example/",
    ])
    .unwrap();
    assert!(!ok);
    assert!(stdout.contains("mailto:missing-host@example.com\tERROR\t"));
    assert!(!stdout.contains("must-not-run"));
    assert!(stderr.contains("one or more PAC evaluations failed"));
}

#[tokio::test]
#[ignore]
async fn test_pac_eval_applies_sanitization_and_offline_mode() {
    utils::init_tracing();
    let path_sensitive = "function FindProxyForURL(url, host) { return url.indexOf('/private') >= 0 ? 'PROXY visible.example:8080' : 'DIRECT'; }";
    let base = [
        "pac",
        "eval",
        "--source",
        path_sensitive,
        "https://target.example/private",
    ];
    let (ok, stdout, stderr) = utils::RamaService::run_capture(&base).unwrap();
    assert!(ok, "eval failed\nstdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.ends_with("\tDIRECT\n"));

    let mut unsanitized = base.to_vec();
    unsanitized.insert(2, "none");
    unsanitized.insert(2, "--sanitize");
    let (ok, stdout, stderr) = utils::RamaService::run_capture(&unsanitized).unwrap();
    assert!(ok, "eval failed\nstdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.ends_with("\tPROXY visible.example:8080\n"));

    let (ok, stdout, stderr) = utils::RamaService::run_capture(&[
        "pac",
        "eval",
        "--offline",
        "--source",
        "function FindProxyForURL(url, host) { return isResolvable('localhost') ? 'PROXY dns.example:8080' : 'DIRECT'; }",
        "https://target.example/",
    ])
    .unwrap();
    assert!(
        ok,
        "offline eval failed\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.ends_with("\tDIRECT\n"));
}
