use super::*;

#[tokio::test]
async fn embedded_h3_emulation_prepares_quic_and_h3_components() {
    let database = Arc::new(UserAgentDatabase::try_embedded().unwrap());
    let connector = service_fn(|input: ConnectRequest| async move {
        let prepared = input
            .extensions()
            .get_ref::<PreparedConnectionComponents>()
            .unwrap();
        assert!(prepared.quic_parameters.is_some());
        assert!(prepared.h3_peer_settings.is_some());
        #[cfg(feature = "tls")]
        assert!(prepared.tls.is_some());
        let conn = ServiceInput::new(());
        conn.extensions().insert(TargetHttpVersion(Version::HTTP_3));
        Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
    });
    let connector = ProfileEmulateHttpConnectModifier::new(connector);
    let inner = service_fn(move |req: Request<()>| {
        let connector = connector.clone();
        async move {
            let context = EmulationContext::of(req.extensions()).unwrap().clone();
            let captured = context.selected.profile().captured.clone().unwrap();
            assert!(captured.components.h3.is_some());
            assert!(captured.components.quic.is_some());
            let input = ConnectRequest::new("example.com:443".parse().unwrap())
                .with_application_protocol(Protocol::HTTPS);
            input
                .extensions()
                .insert(TargetHttpVersion(Version::HTTP_3));
            context.publish(input.extensions());
            connector.serve(input).await.unwrap();
            Ok::<_, Infallible>(())
        }
    });
    let service = ProfileEmulateLayer::new(database)
        .with_seed(ProfileSeed([1; 32]))
        .with_connection_key(DrawKey([2; 32]))
        .with_request_key(DrawKey([3; 32]))
        .into_layer(inner);
    // The embedded H3 captures are form submissions.
    let request = Request::builder()
        .uri("https://example.com/")
        .version(Version::HTTP_3)
        .extension(RequestInitiator::Form)
        .body(())
        .unwrap();
    service.serve(request).await.unwrap();
}
