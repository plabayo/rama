use super::*;

#[tokio::test]
async fn final_http_target_and_protocol_are_validated_without_pending_state() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let fixture = fixture().await;
        let mut input = fixture.input();
        fixture.install(&input);
        input = input.with_application_protocol(Protocol::HTTP);
        rejected(fixture.connector.prepare_connection(&input));
        input = input.with_application_protocol(Protocol::HTTPS);
        input
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_2));
        rejected(fixture.connector.prepare_connection(&input));
        input
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_3));
        // Repeated attempts prepare independent native state, never a shared take.
        fixture.connector.prepare_connection(&input).unwrap();
        fixture.connector.prepare_connection(&input).unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn final_tls_policy_is_used_without_rewriting_caller_settings() {
    use rama_tls::client::{ServerVerifyMode, TlsServerVerify};
    tokio::time::timeout(Duration::from_secs(15), async {
        let fixture = fixture().await;
        for mode in [ServerVerifyMode::Disable, ServerVerifyMode::Auto] {
            let input = fixture.input();
            fixture.install(&input);
            input.extensions().insert(TlsServerVerify(mode));
            let before = fixture.connector.tls_provider().pool_id(input.extensions());
            let (prepared, _) = fixture.connector.prepare_connection(&input).unwrap();
            assert_eq!(
                prepared.authenticated_identity.is_some(),
                mode != ServerVerifyMode::Disable
            );
            assert_eq!(
                before,
                fixture.connector.tls_provider().pool_id(input.extensions())
            );
        }
    })
    .await
    .unwrap();
}
