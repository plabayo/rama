use super::utils;

#[test]
#[ignore = "spawns example processes"]
fn test_masque_proxy_chain() {
    utils::init_tracing();

    let output = utils::ExampleRunner::command(utils::example!("masque_proxy_chain"))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "{stdout}");
    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        [
            "hop a: CONNECT https://127.0.0.1:62051/.well-known/masque/udp/127.0.0.1/62052/ HTTP/3.0",
            "hop b: CONNECT 127.0.0.1:62053 HTTP/3.0",
            "origin answered over HTTP/2.0: hello through two hops",
            "hop a: CONNECT https://127.0.0.1:62051/.well-known/masque/udp/127.0.0.1/62052/ HTTP/3.0",
            "hop b: CONNECT https://127.0.0.1:62052/.well-known/masque/udp/127.0.0.1/62053/ HTTP/3.0",
            "origin answered over HTTP/3.0: hello through two hops",
        ],
    );
}
