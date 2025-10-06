use super::utils;
use rama::{
    dns::{DnsOverwrite, InMemoryDns},
    http::BodyExtractExt,
};
use std::net::IpAddr;

#[tokio::test]
#[ignore]
async fn test_tls_sni_router() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("tls_sni_router", Some("boring"));

    let mut mem_dns = InMemoryDns::new();
    mem_dns.insert_address("foo.local", IpAddr::V4([127, 0, 0, 1].into()));
    mem_dns.insert_address("bar.local", IpAddr::V4([127, 0, 0, 1].into()));

    for (uri, expected_response) in [
        ("https://127.0.0.1:63804", "foo"),
        ("https://127.0.0.1:63805", "bar"),
        ("https://foo.local:62026", "foo"),
        ("https://bar.local:62026", "bar"),
        ("https://127.0.0.1:62026", "baz"),
    ] {
        let response = runner
            .get(uri)
            .extension(DnsOverwrite::from(mem_dns.clone()))
            .send()
            .await
            .unwrap()
            .try_into_string()
            .await
            .unwrap();
        assert_eq!(expected_response, response);
    }
}
