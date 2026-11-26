#![expect(
    clippy::expect_used,
    reason = "example/test/bench: panic-on-error is the standard pattern for harnesses"
)]

//! In-memory benchmark for the web router's dispatch, decoupled from any
//! transport: a table of parameterised routes plus a nested router, hit with
//! requests that resolve early, late, through the nested router, to a 405 and
//! to a 404. Further cases cover a small router, a directory mount next to
//! routes, two levels of nested routers, matchers with and without a path.
//! Handlers answer with a bare status so dispatch dominates.

use divan::black_box;
use rama::Service;
use rama::http::matcher::HttpMatcher;
use rama::http::service::web::response::IntoResponse;
use rama::http::service::web::router::{Router, RouterError};
use rama::http::{Body, HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use rama::utils::fs::{TempDir, tempdir};
use std::sync::LazyLock;
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

fn status_of(result: Result<Response, RouterError>) -> StatusCode {
    result.unwrap_or_else(IntoResponse::into_response).status()
}

/// Bench `router` with `make_request`, after checking it answers `expected`.
fn bench_router(
    bencher: divan::Bencher,
    router: &Router,
    make_request: impl Fn() -> Request + Sync,
    expected: StatusCode,
) {
    assert_eq!(status_of(block_on(router.serve(make_request()))), expected);
    bencher
        .with_inputs(&make_request)
        .bench_local_values(|req| block_on(router.serve(black_box(req))));
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

    // A static is never dropped, so its directory is removed here.
    if let Some(dir) = LazyLock::get(&SERVE_DIR) {
        _ = std::fs::remove_dir_all(dir.path());
    }
}

#[divan::bench(args = CASES)]
fn dispatch(bencher: divan::Bencher, case: Case) {
    let router = router();
    let (method, path, _) = case.request();
    bencher
        .with_inputs(|| request(&method, &path))
        .bench_local_values(|req| block_on(router.serve(black_box(req))));
}

#[divan::bench(args = [0, 1, 10])]
fn router_not_found(bencher: divan::Bencher, endpoints: usize) {
    let mut service: Router = Router::new();
    for i in 0..endpoints {
        service = service.with_get(format!("/endpoint{i}"), StatusCode::OK);
    }
    let method = Method::GET;
    let path = "/missing";
    assert_eq!(
        block_on(service.serve(request(&method, path)))
            .unwrap_or_else(IntoResponse::into_response)
            .status(),
        StatusCode::NOT_FOUND,
    );
    bencher
        .with_inputs(|| request(&method, path))
        .bench_local_values(|req| block_on(service.serve(black_box(req))));
}

#[derive(Debug, Clone, Copy)]
enum SmallCase {
    StaticHit,
    ParamHit,
    NotFound,
}

#[divan::bench(args = [SmallCase::StaticHit, SmallCase::ParamHit, SmallCase::NotFound])]
fn small_router(bencher: divan::Bencher, case: SmallCase) {
    let router: Router = Router::new()
        .with_get("/", StatusCode::OK)
        .with_get("/health", StatusCode::OK)
        .with_get("/users/{id}", StatusCode::OK);
    let (path, expected) = match case {
        SmallCase::StaticHit => ("/health", StatusCode::OK),
        SmallCase::ParamHit => ("/users/42", StatusCode::OK),
        SmallCase::NotFound => ("/missing", StatusCode::NOT_FOUND),
    };
    bench_router(bencher, &router, || request(&Method::GET, path), expected);
}

/// Created once for every directory mount case; it holds `index.html`.
static SERVE_DIR: LazyLock<TempDir> = LazyLock::new(|| {
    let dir = tempdir().expect("create temp dir");
    std::fs::write(dir.path().join("index.html"), "<h1>bench</h1>").expect("write index.html");
    dir
});

#[derive(Debug, Clone, Copy)]
enum DirCase {
    ExistingFile,
    MissingFileToNotFound,
}

#[divan::bench(args = [DirCase::ExistingFile, DirCase::MissingFileToNotFound])]
fn dir_mount_next_to_routes(bencher: divan::Bencher, case: DirCase) {
    let mut router: Router = Router::new();
    for i in 0..20 {
        router = router.with_get(format!("/api/r{i}/{{id}}"), StatusCode::OK);
    }
    let router = router
        .with_dir("/", SERVE_DIR.path())
        .with_not_found(StatusCode::IM_A_TEAPOT);
    let (path, expected) = match case {
        DirCase::ExistingFile => ("/index.html", StatusCode::OK),
        DirCase::MissingFileToNotFound => ("/missing.html", StatusCode::IM_A_TEAPOT),
    };
    // file reads go through the blocking pool, so this case needs a runtime
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build runtime");
    let serve = |req| status_of(runtime.block_on(router.serve(req)));
    assert_eq!(serve(request(&Method::GET, path)), expected);
    bencher
        .with_inputs(|| request(&Method::GET, path))
        .bench_local_values(|req| runtime.block_on(router.serve(black_box(req))));
}

#[derive(Debug, Clone, Copy)]
enum NestedCase {
    Hit,
    MissToParentNotFound,
}

#[divan::bench(args = [NestedCase::Hit, NestedCase::MissToParentNotFound])]
fn nested_two_levels(bencher: divan::Bencher, case: NestedCase) {
    let router: Router = Router::new()
        .with_get("/", StatusCode::OK)
        .with_sub_router_make_fn("/a", |router| {
            router
                .with_get("/status", StatusCode::OK)
                .with_sub_router_make_fn("/b", |router| {
                    router.with_get("/items/{id}", StatusCode::OK)
                })
        })
        .with_not_found(StatusCode::IM_A_TEAPOT);
    let (path, expected) = match case {
        NestedCase::Hit => ("/a/b/items/42", StatusCode::OK),
        NestedCase::MissToParentNotFound => ("/a/b/missing", StatusCode::IM_A_TEAPOT),
    };
    bench_router(bencher, &router, || request(&Method::GET, path), expected);
}

#[derive(Debug, Clone, Copy)]
enum MatcherCase {
    LastHits,
    NoneHits,
}

#[divan::bench(args = [MatcherCase::LastHits, MatcherCase::NoneHits])]
fn pathless_header_matchers(bencher: divan::Bencher, case: MatcherCase) {
    let mut router: Router = Router::new();
    for i in 0..8 {
        let name = HeaderName::try_from(format!("x-route-{i}")).expect("valid header name");
        router = router.with_matcher(HttpMatcher::header_exists(name), StatusCode::OK);
    }
    let (header, expected) = match case {
        MatcherCase::LastHits => ("x-route-7", StatusCode::OK),
        MatcherCase::NoneHits => ("x-route-none", StatusCode::NOT_FOUND),
    };
    let make_request = || {
        let mut req = request(&Method::GET, "/anything");
        req.headers_mut().insert(
            HeaderName::from_static(header),
            HeaderValue::from_static("1"),
        );
        req
    };
    bench_router(bencher, &router, make_request, expected);
}

#[divan::bench]
fn path_bound_matcher(bencher: divan::Bencher) {
    let router: Router = Router::new()
        .with_get("/items", StatusCode::OK)
        .with_matcher(
            HttpMatcher::get("/items/{id}").and_header_exists(HeaderName::from_static("x-tenant")),
            StatusCode::OK,
        );
    let make_request = || {
        let mut req = request(&Method::GET, "/items/42");
        req.headers_mut().insert(
            HeaderName::from_static("x-tenant"),
            HeaderValue::from_static("acme"),
        );
        req
    };
    bench_router(bencher, &router, make_request, StatusCode::OK);
}
