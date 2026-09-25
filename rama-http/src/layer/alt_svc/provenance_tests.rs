use super::{AltSvcCache, AltSvcLayer};
use crate::{Body, Request, Response, header::ALT_USED};
use rama_core::{
    Layer, Service,
    extensions::{Extensions, ExtensionsRef},
};
use rama_http_types::conn::{
    EstablishedHttpService, HttpOrigin, HttpServiceCandidate, HttpServiceCandidates,
    HttpServiceSelection, HttpServiceSource,
};
use rama_net::{Protocol, tls::ApplicationProtocol};
use std::{convert::Infallible, sync::Arc};

struct Connection {
    extensions: Extensions,
}

impl ExtensionsRef for Connection {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl Service<Request> for Connection {
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, request: Request) -> Result<Response, Infallible> {
        let mut response = Response::new(Body::empty());
        if let Some(value) = request.headers().get(ALT_USED) {
            response.headers_mut().insert(ALT_USED, value.clone());
        }
        Ok(response)
    }
}

fn origin() -> HttpOrigin {
    HttpOrigin::new(Protocol::HTTPS, "origin.example:443".parse().unwrap()).unwrap()
}

fn candidate(source: HttpServiceSource) -> HttpServiceCandidate {
    HttpServiceCandidate::new(
        ApplicationProtocol::HTTP_2,
        "alternative.example:8443".parse().unwrap(),
    )
    .with_source(source)
}

fn selected_request(candidate: HttpServiceCandidate) -> Request {
    let request = Request::builder()
        .uri("https://origin.example/")
        .body(Body::empty())
        .unwrap();
    request.extensions().insert(HttpServiceSelection {
        candidates: Arc::new(HttpServiceCandidates::new(origin(), vec![candidate])),
        index: 0,
        route: None,
    });
    request
}

#[tokio::test]
async fn request_discovery_source_can_change_on_one_established_connection() {
    for initial_source in [HttpServiceSource::Configured, HttpServiceSource::AltSvc] {
        let extensions = Extensions::new();
        let established = extensions.insert_arc(Arc::new(EstablishedHttpService::new(
            origin(),
            candidate(initial_source),
        )));
        let service = AltSvcLayer::new(AltSvcCache::default()).layer(Connection { extensions });

        for source in [
            HttpServiceSource::Configured,
            HttpServiceSource::AltSvc,
            HttpServiceSource::Configured,
            HttpServiceSource::AltSvc,
        ] {
            let response = service
                .serve(selected_request(candidate(source)))
                .await
                .unwrap();
            assert_eq!(
                response
                    .headers()
                    .get(ALT_USED)
                    .map(|value| value.as_bytes()),
                (source == HttpServiceSource::AltSvc)
                    .then_some(b"alternative.example:8443".as_slice()),
                "the current request's source takes precedence over {initial_source:?}",
            );
            assert!(Arc::ptr_eq(
                &established,
                &service
                    .extensions()
                    .get_arc::<EstablishedHttpService>()
                    .unwrap(),
            ));
            assert_eq!(established.candidate.source, initial_source);
        }
    }
}

#[tokio::test]
async fn unrelated_selection_cannot_change_established_discovery_source() {
    for initial_source in [HttpServiceSource::Configured, HttpServiceSource::AltSvc] {
        let extensions = Extensions::new();
        extensions.insert(EstablishedHttpService::new(
            origin(),
            candidate(initial_source),
        ));
        let service = AltSvcLayer::new(AltSvcCache::default()).layer(Connection { extensions });
        let mut unrelated = candidate(match initial_source {
            HttpServiceSource::Configured => HttpServiceSource::AltSvc,
            _ => HttpServiceSource::Configured,
        });
        unrelated.target = "unrelated.example:443".parse().unwrap();
        let response = service.serve(selected_request(unrelated)).await.unwrap();
        assert_eq!(
            response.headers().get(ALT_USED).is_some(),
            initial_source == HttpServiceSource::AltSvc,
        );
    }
}
