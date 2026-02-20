use super::utils;
use rama::{
    dns::client::resolver::DnsAddresssResolverOverwrite, http::BodyExtractExt,
    net::address::DomainTrie,
};
use std::net::Ipv4Addr;

#[tokio::test]
#[ignore]
async fn test_tls_sni_router() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("tls_sni_router", Some("boring"));

    let mut overwrite_dns_trie = DomainTrie::new();
    overwrite_dns_trie.insert_domain("foo.local", Ipv4Addr::new(127, 0, 0, 1));
    overwrite_dns_trie.insert_domain("bar.local", Ipv4Addr::new(127, 0, 0, 1));
    let overwrite_dns = DnsAddresssResolverOverwrite::new(overwrite_dns_trie);

    for (uri, expected_response) in [
        ("https://127.0.0.1:63804", "foo"),
        ("https://127.0.0.1:63805", "bar"),
        ("https://foo.local:62026", "foo"),
        ("https://bar.local:62026", "bar"),
        ("https://127.0.0.1:62026", "baz"),
    ] {
        let response = runner
            .get(uri)
            .extension(overwrite_dns.clone())
            .send()
            .await
            .unwrap()
            .try_into_string()
            .await
            .unwrap();
        assert_eq!(expected_response, response);
    }
}
