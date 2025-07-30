use super::utils;
use rama::{
    Context,
    dns::{DnsOverwrite, InMemoryDns},
    http::BodyExtractExt,
    net::address::Domain,
};
use std::net::IpAddr;

#[tokio::test]
#[ignore]
async fn test_tls_sni_router() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("tls_sni_router", Some("boring"));

    let mut ctx = Context::default();
    let mut mem_dns = InMemoryDns::new();
    mem_dns.insert_address(
        &Domain::from_static("foo.local"),
        IpAddr::V4([127, 0, 0, 1].into()),
    );
    mem_dns.insert_address(
        &Domain::from_static("bar.local"),
        IpAddr::V4([127, 0, 0, 1].into()),
    );
    ctx.insert(DnsOverwrite::from(mem_dns));

    for (uri, expected_response) in [
        ("https://127.0.0.1:63804", "foo"),
        ("https://127.0.0.1:63805", "bar"),
        ("https://foo.local:62026", "foo"),
        ("https://bar.local:62026", "bar"),
        ("https://127.0.0.1:62026", "baz"),
    ] {
        let response = runner
            .get(uri)
            .send(ctx.clone())
            .await
            .unwrap()
            .try_into_string()
            .await
            .unwrap();
        assert_eq!(expected_response, response);
    }
}
