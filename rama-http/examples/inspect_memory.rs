//! HTTP inspection and a native content consumer without TLS, WS or file storage.

use std::convert::Infallible;

use rama_core::{Layer, Service, futures::StreamExt, service::service_fn};
use rama_http::{
    Body, Request, Response,
    body::util::BodyExt,
    inspect::capture::{CaptureConfig, CaptureHttpLayer, CaptureQuery, CaptureStore},
};
use rama_inspect::{
    InspectionState,
    storage::{MemoryStore, Storage, StorageLimits},
};

#[tokio::main]
async fn main() -> Result<(), rama_core::error::BoxError> {
    let captures = CaptureStore::with_storage(
        Storage::new(MemoryStore::new(StorageLimits::default())),
        CaptureConfig::default(),
        InspectionState::default(),
    );
    let application = CaptureHttpLayer::new(Some(captures.clone())).layer(service_fn(
        async |request: Request| {
            request.into_body().collect().await?;
            Ok::<_, rama_core::error::BoxError>(Response::new(Body::from("inspected")))
        },
    ));
    application
        .serve(Request::new(Body::empty()))
        .await?
        .into_body()
        .collect()
        .await?;
    let mut views = Box::pin(captures.subscribe(CaptureQuery::default()));
    let view = views.next().await.ok_or("inspector closed")?;
    assert_eq!(view.exchanges.len(), 1);
    let _result: Result<_, Infallible> = captures.serve(CaptureQuery::default()).await;
    Ok(())
}
