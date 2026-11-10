#![expect(
    clippy::expect_used,
    reason = "example/test/bench: panic-on-error is the standard pattern for harnesses"
)]

//! In-memory benchmark for the web router's dispatch, decoupled from any
//! transport: a table of parameterised routes plus a nested router, hit with
//! requests that resolve early, late, through the nested router, to a 405 and
//! to a 404. Handlers answer with a bare status so dispatch dominates.

use divan::black_box;
use rama::Service;
use rama::http::service::web::response::IntoResponse;
use rama::http::service::web::router::{Router, RouterError};
use rama::http::{Body, Method, Request, Response, StatusCode};
use std::task::{Context, Poll, Waker};

mod bench_alloc;

const ROUTES: usize = 48;

#[derive(Debug, Clone, Copy)]
enum Case {
    StaticRoute,
    FirstParamRoute,
    LastParamRoute,
    NestedParamRoute,
    MethodNotAllowed,
    NotFound,
}

const CASES: &[Case] = &[
    Case::StaticRoute,
    Case::FirstParamRoute,
    Case::LastParamRoute,
    Case::NestedParamRoute,
    Case::MethodNotAllowed,
    Case::NotFound,
];

impl Case {
    fn request(self) -> (Method, String, StatusCode) {
        match self {
            Self::StaticRoute => (Method::GET, "/health".to_owned(), StatusCode::OK),
            Self::FirstParamRoute => (
                Method::GET,
                "/r0/items/42/parts/7".to_owned(),
                StatusCode::OK,
            ),
            Self::LastParamRoute => (
                Method::GET,
                format!("/r{}/items/42/parts/7", ROUTES - 1),
                StatusCode::OK,
            ),
            Self::NestedParamRoute => (
                Method::GET,
                "/tenants/acme/api/users/42/orders/7".to_owned(),
                StatusCode::OK,
            ),
            Self::MethodNotAllowed => (
                Method::DELETE,
                "/r24/items/42/parts/7".to_owned(),
                StatusCode::METHOD_NOT_ALLOWED,
            ),
            Self::NotFound => (
                Method::GET,
                "/missing/items/42/parts/7".to_owned(),
                StatusCode::NOT_FOUND,
            ),
        }
    }
}

fn router() -> impl Service<Request, Output = Response, Error = RouterError> {
    let mut router = Router::new().with_get("/health", StatusCode::OK);
    for i in 0..ROUTES {
        let path = format!("/r{i}/items/{{item_id}}/parts/{{part_id}}");
        router = router
            .with_get(&path, StatusCode::OK)
            .with_post(&path, StatusCode::OK);
    }
    router.with_sub_service(
        "/tenants/{tenant}/api",
        Router::new().with_get("/users/{user_id}/orders/{order_id}", StatusCode::OK),
    )
}

/// Minimal single-future block-on: dispatch never waits on I/O.
fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = std::pin::pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
            return out;
        }
        std::hint::spin_loop();
    }
}

fn request(method: &Method, path: &str) -> Request {
    Request::builder()
        .method(method.clone())
        .uri(path)
        .body(Body::empty())
        .expect("valid request")
}

fn main() {
    // correctness preflight, outside any timing
    let router = router();
    for case in CASES {
        let (method, path, status) = case.request();
        let response = block_on(router.serve(request(&method, &path)))
            .unwrap_or_else(IntoResponse::into_response);
        assert_eq!(status, response.status(), "{case:?}");
    }

    divan::main();
}

#[divan::bench(args = CASES)]
fn dispatch(bencher: divan::Bencher, case: Case) {
    let router = router();
    let (method, path, _) = case.request();
    bencher
        .with_inputs(|| request(&method, &path))
        .bench_local_values(|req| block_on(router.serve(black_box(req))));
}
