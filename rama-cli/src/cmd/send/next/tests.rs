use clap::Parser;

use super::*;

#[derive(Debug, Parser)]
struct TestCli {
    #[command(flatten)]
    send: SendCommand,
}

fn parse(arguments: &[&str]) -> Result<(SendCommand, Vec<RequestArgs>), BoxError> {
    let cli = TestCli::try_parse_from(
        std::iter::once("rama-next-test").chain(arguments.iter().copied()),
    )?;
    let following = following_requests(&cli.send)?;
    Ok((cli.send, following))
}

#[test]
fn next_requests_have_only_their_own_request_options() {
    let (first, following) = parse(&[
        "--http3",
        "-H",
        "x-first: 1",
        "-u",
        "first",
        "https://example.com/",
        "--next",
        "-X",
        "POST",
        "-H",
        "x-second: 2",
        "https://example.com/api",
        "--next",
        "https://example.com/last",
    ])
    .unwrap();
    assert!(first.http_3);
    assert_eq!(first.req.uri, "https://example.com/");
    assert_eq!(first.req.header.len(), 1);
    assert_eq!(first.req.user.as_deref(), Some("first"));
    assert_eq!(
        following
            .iter()
            .map(|req| req.uri.as_str())
            .collect::<Vec<_>>(),
        ["https://example.com/api", "https://example.com/last"]
    );
    assert_eq!(following[0].request.as_deref(), Some("POST"));
    assert_eq!(following[0].header.len(), 1);
    assert!(following[0].user.is_none());
    assert!(following[1].header.is_empty() && following[1].request.is_none());
    // Each parsed request gave its remaining arguments to the next one.
    assert!(following.iter().all(|req| req.next.is_empty()));
}

#[test]
fn client_options_and_unkeyed_emulation_are_refused_in_any_request() {
    let pin = "00".repeat(32);
    for arguments in [
        &[
            "https://example.com/",
            "--next",
            "--http2",
            "https://example.com/",
        ][..],
        &["https://example.com/", "--next"],
        &[
            "https://example.com/",
            "--next",
            "--emulate-connection-variant",
            &pin,
            "https://example.com/",
        ],
        &["--emulate-connection-bootstrap", "https://example.com/"],
    ] {
        parse(arguments).unwrap_err();
    }
}
