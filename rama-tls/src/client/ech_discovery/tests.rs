use super::*;
use crate::{
    ProtocolVersion,
    client::{ClientHelloExtension, ECHClientHello},
};
use parking_lot::Mutex;
use rama_core::{
    ServiceInput,
    extensions::ExtensionsRef,
    futures::{Stream, stream},
    service::service_fn,
};
use rama_dns::{
    client::resolver::ServiceBindingRecord,
    wire::{Name, ServiceBinding},
};
use rama_net::{
    address::Domain,
    client::{ConnectRequest, ProxyRoute},
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
#[derive(Clone, Default)]
struct Resolver(Arc<AtomicUsize>, bool, Arc<Mutex<Vec<Domain>>>);
impl DnsServiceBindingResolver for Resolver {
    type Error = BoxError;
    fn lookup_https(
        &self,
        name: Domain,
    ) -> impl Stream<Item = Result<ServiceBindingRecord, BoxError>> + Send + '_ {
        self.2.lock().push(name);
        self.0.fetch_add(1, Ordering::SeqCst);
        let wire = [0, 1, 0, 0, 5, 0, 7, 0, 5, 0xfe, 0x0d, 0, 1, 0];
        stream::iter([Ok(ServiceBindingRecord {
            owner: Name::from_presentation(if self.1 {
                "cdn.example"
            } else {
                "origin.example"
            })
            .unwrap(),
            binding: ServiceBinding::parse_rdata(&wire).unwrap(),
        })])
    }
    fn lookup_svcb(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<ServiceBindingRecord, BoxError>> + Send + '_ {
        stream::empty()
    }
}

#[tokio::test]
async fn fixed_endpoint_discovers_real_configuration_and_reliance() {
    let resolver = Resolver::default();
    let layer = TargetEchConfigLayer::new()
        .with_resolver(resolver.clone())
        .with_capable(true);
    let input = ConnectRequest::new("origin.example:443".parse().unwrap());
    input.extensions().insert(TlsEncryptedClientHello(true));
    layer.prepare(&input).await.unwrap();
    assert!(
        input
            .extensions()
            .get_ref::<TargetEchConfig>()
            .unwrap()
            .matches_target(&input.authority)
    );
    assert_eq!(
        input
            .extensions()
            .get_ref::<TargetEchServiceBinding>()
            .map(|fact| fact.reliant),
        Some(true)
    );
    layer.prepare(&input).await.unwrap();
    assert_eq!(resolver.0.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn no_capability_or_proxy_permission_means_no_dns() {
    for proxy in [false, true] {
        let resolver = Resolver::default();
        let layer = TargetEchConfigLayer::new()
            .with_resolver(resolver.clone())
            .with_capable(proxy);
        let input = ConnectRequest::new("origin.example:443".parse().unwrap());
        if proxy {
            input.extensions().insert(TlsEncryptedClientHello(true));
            input.extensions().insert(ProxyRoute::Proxy(
                "socks5h://proxy.example:1080".parse().unwrap(),
            ));
        }
        layer.prepare(&input).await.unwrap();
        assert_eq!(resolver.0.load(Ordering::SeqCst), 0);
        input.extensions().insert(EchRequirement::Required);
        layer.prepare(&input).await.unwrap_err();
    }
}

#[tokio::test]
async fn explicit_required_preknowledge_works_without_proxy_discovery() {
    let resolver = Resolver::default();
    let layer = TargetEchConfigLayer::new()
        .with_resolver(resolver.clone())
        .with_capable(true);
    let input = ConnectRequest::new("origin.example:443".parse().unwrap());
    input.extensions().insert(EchRequirement::Required);
    input.extensions().insert(ProxyRoute::Proxy(
        "http://proxy.example:3128".parse().unwrap(),
    ));
    input
        .extensions()
        .insert(TargetEchConfig::new(input.authority.clone(), vec![0, 1, 2]));
    layer.prepare(&input).await.unwrap();
    assert_eq!(resolver.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cname_owner_root_target_uses_the_original_address_resolution() {
    let resolver = Resolver(Arc::default(), true, Arc::default());
    let layer = TargetEchConfigLayer::new()
        .with_resolver(resolver)
        .with_capable(true);
    let input = ConnectRequest::new("origin.example:443".parse().unwrap());
    input.extensions().insert(TlsEncryptedClientHello(true));
    layer.prepare(&input).await.unwrap();
    assert!(
        input
            .extensions()
            .get_ref::<TargetEchConfig>()
            .unwrap()
            .matches_target(&input.authority)
    );
    assert_eq!(
        input
            .extensions()
            .get_ref::<TargetEchServiceBinding>()
            .map(|fact| fact.reliant),
        Some(true)
    );
}

fn peeked(ech: bool, sni: bool) -> InputWithClientHello<ServiceInput<()>> {
    let mut extensions = Vec::new();
    if sni {
        extensions.push(ClientHelloExtension::ServerName(Some(
            "origin.example".parse().unwrap(),
        )));
    }
    if ech {
        extensions.push(ClientHelloExtension::EncryptedClientHello(
            ECHClientHello::Inner,
        ));
    }
    let input = ServiceInput::new(());
    input
        .extensions()
        .insert(ConnectorTarget("origin.example:443".parse().unwrap()));
    InputWithClientHello {
        input,
        client_hello: ClientHello::new(ProtocolVersion::TLSv1_3, vec![], vec![], extensions),
    }
}

#[tokio::test]
async fn mirrored_discovery_binds_sni_knowledge_to_the_dialed_ip() {
    for (port, query) in [
        (443, "origin.example"),
        (8443, "_8443._https.origin.example"),
    ] {
        let resolver = Resolver::default();
        let layer = TargetEchConfigLayer::new()
            .with_resolver(resolver.clone())
            .with_capable(true);
        let input = peeked(true, true);
        let target: HostWithPort = format!("192.0.2.1:{port}").parse().unwrap();
        input
            .input
            .extensions()
            .insert(ConnectorTarget(target.clone()));
        layer.prepare_client_hello(&input).await.unwrap();
        assert!(
            input
                .input
                .extensions()
                .get_ref::<TargetEchConfig>()
                .unwrap()
                .matches_target(&target)
        );
        assert_eq!(resolver.0.load(Ordering::SeqCst), 1);

        assert_eq!(
            resolver.2.lock().as_slice(),
            &[query.parse::<Domain>().unwrap()]
        );

        // Matching preknowledge avoids repeating discovery, including for IP dials.
        layer.prepare_client_hello(&input).await.unwrap();
        assert_eq!(resolver.0.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn mirrored_discovery_preserves_intent_and_proxy_privacy() {
    for (ech, sni, disabled, proxy) in [
        (false, true, false, false),
        (true, false, false, false),
        (true, true, true, false),
        (true, true, false, true),
    ] {
        let resolver = Resolver::default();
        let layer = TargetEchConfigLayer::new()
            .with_resolver(resolver.clone())
            .with_capable(true);
        let input = peeked(ech, sni);
        if disabled {
            input
                .input
                .extensions()
                .insert(TlsEncryptedClientHello(false));
        }
        if proxy {
            input.input.extensions().insert(ProxyRoute::Proxy(
                "socks5h://proxy.example:1080".parse().unwrap(),
            ));
        }
        layer.prepare_client_hello(&input).await.unwrap();
        assert_eq!(resolver.0.load(Ordering::SeqCst), 0);
        assert!(!input.input.extensions().contains::<TargetEchConfig>());
    }
}

#[tokio::test]
async fn mirrored_required_conflict_fails_without_discovery() {
    let resolver = Resolver::default();
    let layer = TargetEchConfigLayer::new()
        .with_resolver(resolver.clone())
        .with_capable(true);
    let input = peeked(true, true);
    input
        .input
        .extensions()
        .insert(TlsEncryptedClientHello(false));
    input.input.extensions().insert(EchRequirement::Required);
    layer.prepare_client_hello(&input).await.unwrap_err();
    assert_eq!(resolver.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn peeked_service_respects_mirrored_alpn_and_explicit_override() {
    let resolver = Resolver::default();
    let layer = TargetEchConfigLayer::new()
        .with_resolver(resolver.clone())
        .with_capable(true);
    let service = layer.layer(service_fn(
        |input: InputWithClientHello<ServiceInput<()>>| async move {
            Ok::<_, BoxError>(input.input.extensions().contains::<TargetEchConfig>())
        },
    ));
    for explicit_alpn in [false, true] {
        let mut input = peeked(true, true);
        input.client_hello.extensions.push(
            ClientHelloExtension::ApplicationLayerProtocolNegotiation(vec![
                ApplicationProtocol::HTTP_2,
            ]),
        );
        if explicit_alpn {
            input
                .input
                .extensions()
                .insert(TlsAlpn(vec![ApplicationProtocol::HTTP_11].into()));
        }
        // The fixture advertises only default H1. A mirrored H2-only offer
        // cannot consume it; an explicit H1 policy can.
        assert_eq!(service.serve(input).await.unwrap(), explicit_alpn);
    }
    assert_eq!(resolver.0.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn selected_binding_without_ech_does_not_repeat_discovery() {
    let resolver = Resolver::default();
    let layer = TargetEchConfigLayer::new()
        .with_resolver(resolver.clone())
        .with_capable(true);
    let input = ConnectRequest::new("origin.example:443".parse().unwrap());
    input.extensions().insert(TargetEchServiceBinding {
        target: input.authority.clone(),
        reliant: false,
        mandatory: false,
    });
    layer.prepare(&input).await.unwrap();
    assert_eq!(resolver.0.load(Ordering::SeqCst), 0);
    assert!(!input.extensions().contains::<TargetEchConfig>());
    input.extensions().insert(EchRequirement::Required);
    layer.prepare(&input).await.unwrap_err();
    assert_eq!(resolver.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn unbound_relay_and_insecure_connector_do_not_query() {
    let resolver = Resolver::default();
    let layer = TargetEchConfigLayer::new()
        .with_resolver(resolver.clone())
        .with_capable(true);
    let mut input = peeked(true, true);
    input.input = ServiceInput::new(());
    layer.prepare_client_hello(&input).await.unwrap();
    let request = ConnectRequest::new("origin.example:80".parse().unwrap())
        .with_application_protocol(rama_net::Protocol::HTTP);
    layer.prepare(&request).await.unwrap();
    assert_eq!(resolver.0.load(Ordering::SeqCst), 0);
}
