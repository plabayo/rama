use super::*;

#[tokio::test]
async fn captured_tls_reaches_a_rustls_h3_peer_and_stays_exclusive_without_context() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut fixture = fixture().await;
        // A different, supported wire order proves the prepared configuration
        // reaches the dial; rebuilding the ordinary default cannot pass.
        fixture.capture.ciphers.reverse();
        let input = fixture.input();
        let compiled = fixture.compile(&input);
        assert!(compiled.supports(CapturedSlotKind::QuicTls));
        assert!(!compiled.supports(CapturedSlotKind::QuicFirstFlight));
        let before = fixture.connector.tls_provider().pool_id(input.extensions());
        compiled.apply(input.extensions());
        assert_eq!(
            before,
            fixture.connector.tls_provider().pool_id(input.extensions())
        );
        let transport = fixture.connector.serve(input).await.unwrap().conn;
        assert!(
            !transport
                .connection
                .extensions()
                .get_ref::<ConnectionReuse>()
                .unwrap()
                .is_reusable()
        );
        request(transport).await;
        let captures = fixture.task.take().unwrap().await.unwrap();
        assert_eq!(captures.len(), 2);
        assert_eq!(captures[1], fixture.capture);
    })
    .await
    .unwrap();
}
