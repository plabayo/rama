use super::*;

#[tokio::test]
async fn mutated_bindings_and_foreign_owner_cannot_consume_prepared_tls() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let fixture = fixture().await;
        let mut input = fixture.input();
        fixture.compile(&input).apply(input.extensions());
        let original = input.authority.clone();
        input.authority =
            HostWithPort::localhost_domain_with_port(fixture.port.checked_add(1).unwrap_or(1));
        rejected(fixture.connector.prepare_tls(&input));
        input.authority = "other.invalid:443".parse().unwrap();
        rejected(fixture.connector.prepare_tls(&input));
        input.authority = original;
        input = input.with_application_protocol(Protocol::HTTP);
        rejected(fixture.connector.prepare_tls(&input));
        input = input.with_application_protocol(Protocol::HTTPS);
        input
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_2));
        rejected(fixture.connector.prepare_tls(&input));
        input
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_3));
        let other = Http3Connector::builder(Executor::new())
            .with_tls_config(fixture.connector.tls.clone())
            .with_tls_provider(Arc::new(BoringTlsProvider))
            .build_lazy()
            .unwrap();
        rejected(other.prepare_tls(&input));
        input.extensions().insert(ConnectionContext {
            token_present: Some(true),
            ..ConnectionContext::default()
        });
        rejected(fixture.connector.prepare_tls(&input));
        input.extensions().insert(ConnectionContext::default());
        // Rejections leave the first native configuration available to its owner.
        fixture.connector.prepare_tls(&input).unwrap();
        rejected(fixture.connector.prepare_tls(&input));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn changing_tls_policy_rejects_the_plan_without_rewriting_caller_settings() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let fixture = fixture().await;
        for (original, changed) in [
            (
                rama_tls::client::ServerVerifyMode::Auto,
                rama_tls::client::ServerVerifyMode::Disable,
            ),
            (
                rama_tls::client::ServerVerifyMode::Disable,
                rama_tls::client::ServerVerifyMode::Auto,
            ),
        ] {
            let input = fixture.input();
            input
                .extensions()
                .insert(rama_tls::client::TlsServerVerify(original));
            fixture.compile(&input).apply(input.extensions());
            input
                .extensions()
                .insert(rama_tls::client::TlsServerVerify(changed));
            rejected(fixture.connector.prepare_tls(&input));
            input
                .extensions()
                .insert(rama_tls::client::TlsServerVerify(original));
            fixture.connector.prepare_tls(&input).unwrap();
        }
    })
    .await
    .unwrap();
}
