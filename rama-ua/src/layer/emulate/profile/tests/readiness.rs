use super::*;
use crate::profile::selection::variants::SelectedProfile;
use rama_net::tls::TargetEchConfig;
use rama_tls::client::TlsEncryptedClientHello;

struct ReadinessSource {
    expected: Option<bool>,
    database: Arc<UserAgentDatabase>,
}

impl ProfileSource for ReadinessSource {
    fn select_profile(
        &self,
        request: &SelectionRequest,
        seed: ProfileSeed,
        key: DrawKey,
    ) -> Result<SelectedProfile, SelectionError> {
        assert_eq!(request.client.ech_ready, self.expected);
        self.database.select(request, seed, key)
    }
}

#[tokio::test]
async fn profile_draw_reads_only_existing_target_bound_ech_readiness() {
    for (config, enabled, expected) in [
        (None, true, None),
        (Some("origin.test:443"), true, Some(true)),
        (Some("origin.test:443"), false, Some(false)),
        (Some("other.test:443"), true, None),
    ] {
        let source = ReadinessSource {
            expected,
            database: database(),
        };
        let service = ProfileEmulateLayer::new(Arc::new(source))
            .with_seed(ProfileSeed([1; 32]))
            .with_connection_key(DrawKey([2; 32]))
            .into_layer(service_fn(async |_: Request<()>| Ok::<_, Infallible>(())));
        let request = Request::builder()
            .uri("https://origin.test/")
            .version(Version::HTTP_2)
            .extension(TargetHttpVersion(Version::HTTP_2))
            .body(())
            .unwrap();
        if let Some(target) = config {
            request
                .extensions()
                .insert(TargetEchConfig::new(target.parse().unwrap(), vec![0, 1, 2]));
        }
        request
            .extensions()
            .insert(TlsEncryptedClientHello(enabled));
        service.serve(request).await.unwrap();
    }
}
