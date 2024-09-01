use rama::context::{AsRef, Context};
use rama::http::service::web::WebService;
use rama::http::{Body, Request, StatusCode};
use rama::service::{service_fn, Service};
use std::sync::Arc;

// This will implement `AsRef` for each field in the struct.
#[derive(Clone, AsRef)]
struct AppState {
    auth_token: String,
}

async fn handler<S>(ctx: Context<S>, _req: Request) -> Result<StatusCode, std::convert::Infallible>
where
    S: std::convert::AsRef<String> + Send + Sync + 'static,
{
    let _auth_token = ctx.state().as_ref();
    // ...
    Ok(StatusCode::OK)
}

fn main() {
    let state = AppState {
        auth_token: Default::default(),
    };

    let service = WebService::default().get("/", service_fn(handler));

    let ctx = Context::with_state(Arc::new(state));
    let req = Request::builder().body(Body::empty()).unwrap();

    let _resp_fut = service.serve(ctx, req);
}
