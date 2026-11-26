use rama_core::{
    extensions::{Extension, ExtensionsRef},
    service::service_fn,
};
use rama_http_types::{Body, Method, Request, StatusCode, body::util::BodyExt, header};
use rama_net::uri::PathRef;

use super::super::*;
use crate::{
    layer::error_handling::ErrorHandlerLayer,
    matcher::{PathCase, PathDecoding, UriParams},
    service::web::extract::State,
};

fn root_service() -> impl Service<Request, Output = Response, Error = Infallible> {
    service_fn(|_req| async {
        Ok(Response::builder()
            .status(200)
            .body(Body::from("Hello, World!"))
            .unwrap())
    })
}

fn create_user_service() -> impl Service<Request, Output = Response, Error = Infallible> {
    service_fn(|_req| async {
        Ok(Response::builder()
            .status(200)
            .body(Body::from("Create User"))
            .unwrap())
    })
}

fn get_users_service() -> impl Service<Request, Output = Response, Error = Infallible> {
    service_fn(|_req| async {
        Ok(Response::builder()
            .status(200)
            .body(Body::from("List Users"))
            .unwrap())
    })
}

fn get_user_service() -> impl Service<Request, Output = Response, Error = Infallible> {
    service_fn(|req: Request| async move {
        let uri_params = req.extensions().get_ref::<UriParams>().unwrap();
        let id = uri_params.get("user_id").unwrap();
        Ok(Response::builder()
            .status(200)
            .body(Body::from(format!("Get User: {id}")))
            .unwrap())
    })
}

fn delete_user_service() -> impl Service<Request, Output = Response, Error = Infallible> {
    service_fn(|req: Request| async move {
        let uri_params = req.extensions().get_ref::<UriParams>().unwrap();
        let id = uri_params.get("user_id").unwrap();
        Ok(Response::builder()
            .status(200)
            .body(Body::from(format!("Delete User: {id}")))
            .unwrap())
    })
}

fn serve_assets_service() -> impl Service<Request, Output = Response, Error = Infallible> {
    service_fn(|req: Request| async move {
        let uri_params = req.extensions().get_ref::<UriParams>().unwrap();
        let path = uri_params.get("path").unwrap();
        Ok(Response::builder()
            .status(200)
            .body(Body::from(format!("Serve Assets: /{path}")))
            .unwrap())
    })
}

fn not_found_service() -> impl Service<Request, Output = Response, Error = Infallible> {
    service_fn(|_req| async {
        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Not Found"))
            .unwrap())
    })
}

fn label_service(
    label: &'static str,
) -> impl Service<Request, Output = Response, Error = Infallible> {
    service_fn(move |_req| async move { Ok(Response::new(Body::from(label))) })
}

fn capture_service(
    name: &'static str,
) -> impl Service<Request, Output = Response, Error = Infallible> {
    service_fn(move |req: Request| async move {
        let params = req.extensions().get_ref::<UriParams>().unwrap();
        Ok(Response::new(Body::from(
            params.get(name).unwrap().to_owned(),
        )))
    })
}

fn joined_capture_service(
    first: &'static str,
    second: &'static str,
) -> impl Service<Request, Output = Response, Error = Infallible> {
    service_fn(move |req: Request| async move {
        let params = req.extensions().get_ref::<UriParams>().unwrap();
        Ok(Response::new(Body::from(format!(
            "{}|{}",
            params.get(first).unwrap(),
            params.get(second).unwrap()
        ))))
    })
}

async fn get_text<S>(service: &S, path: &str) -> (StatusCode, String)
where
    S: Service<Request, Output = Response, Error = Infallible>,
{
    let response = service
        .serve(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

fn get_user_order_service() -> impl Service<Request, Output = Response, Error = Infallible> {
    service_fn(|req: Request| async move {
        let uri_params = req.extensions().get_ref::<UriParams>().unwrap();
        let user_id = uri_params.get("user_id").unwrap();
        let order_id = uri_params.get("order_id").unwrap();
        Ok(Response::builder()
            .status(200)
            .body(Body::from(format!(
                "Get Order: {order_id} for User: {user_id}",
            )))
            .unwrap())
    })
}

// Echoes the request content back, proving the QUERY body (the query) reaches the handler.
fn query_echo_service() -> impl Service<Request, Output = Response, Error = Infallible> {
    service_fn(|req: Request| async move {
        let body = req.into_body().collect().await.unwrap().to_bytes();
        Ok(Response::builder()
            .status(200)
            .body(Body::from(format!(
                "query: {}",
                String::from_utf8_lossy(&body)
            )))
            .unwrap())
    })
}

#[tokio::test]
async fn test_router() {
    let cases = vec![
        (Method::GET, "/", "Hello, World!", StatusCode::OK),
        (Method::GET, "/users", "List Users", StatusCode::OK),
        (Method::POST, "/users", "Create User", StatusCode::OK),
        (Method::GET, "/users/123", "Get User: 123", StatusCode::OK),
        (
            Method::DELETE,
            "/users/123",
            "Delete User: 123",
            StatusCode::OK,
        ),
        (
            Method::GET,
            "/users/123/orders/456",
            "Get Order: 456 for User: 123",
            StatusCode::OK,
        ),
        (
            Method::PUT,
            "/users/123",
            "",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            Method::GET,
            "/assets/css/style.css",
            "Serve Assets: /css/style.css",
            StatusCode::OK,
        ),
        (
            Method::GET,
            "/not-found",
            "Not Found",
            StatusCode::NOT_FOUND,
        ),
    ];

    for prefix in ["/", ""] {
        let router = Router::new()
            .with_get(prefix, root_service())
            .with_get(format!("{prefix}users"), get_users_service())
            .with_post(format!("{prefix}users"), create_user_service())
            .with_get(format!("{prefix}users/{{user_id}}"), get_user_service())
            .with_delete(format!("{prefix}users/{{user_id}}"), delete_user_service())
            .with_get(
                format!("{prefix}users/{{user_id}}/orders/{{order_id}}"),
                get_user_order_service(),
            )
            .with_get(format!("{prefix}assets/{{*path}}"), serve_assets_service())
            .with_not_found(not_found_service());

        let router = ErrorHandlerLayer::new().layer(router);

        for (method, path, expected_body, expected_status) in cases.iter() {
            let req = match *method {
                Method::GET => Request::get(*path),
                Method::POST => Request::post(*path),
                Method::PUT => Request::put(*path),
                Method::DELETE => Request::delete(*path),
                _ => panic!("Unsupported HTTP method"),
            }
            .body(Body::empty())
            .unwrap();

            let res = router.serve(req).await.unwrap();
            assert_eq!(
                res.status(),
                *expected_status,
                "method: {method} ; path = {path}; prefix = {prefix}"
            );
            let body = res.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(
                body, expected_body,
                "method: {method} ; path = {path}; prefix = {prefix}"
            );
        }
    }
}

#[tokio::test]
async fn test_router_query_method() {
    let router = Router::new()
        .with_query("/search", query_echo_service())
        .with_get("/search", get_users_service())
        .with_not_found(not_found_service());

    let router = ErrorHandlerLayer::new().layer(router);

    // QUERY with a body is routed to the QUERY handler and the body reaches it.
    let req = Request::query("/search")
        .header(header::CONTENT_TYPE, "application/sql")
        .body(Body::from("SELECT 1"))
        .unwrap();
    let res = router.serve(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, "query: SELECT 1");

    // GET on the same path is distinct from QUERY and hits the GET handler.
    let req = Request::get("/search").body(Body::empty()).unwrap();
    let res = router.serve(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, "List Users");

    // A method registered on neither route → 405 listing GET and QUERY in the Allow header.
    let req = Request::post("/search").body(Body::empty()).unwrap();
    let res = router.serve(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        res.headers()
            .get(header::ALLOW)
            .expect("Allow header must be present on 405")
            .to_str()
            .unwrap(),
        "GET, QUERY"
    );
}

#[tokio::test]
async fn test_router_merges_case_insensitive_pattern_registrations() {
    let router = Router::new()
        .with_get("/Users/{user_id}", get_user_service())
        .with_post("/users/{user_id}", create_user_service());

    let router = ErrorHandlerLayer::new().layer(router);

    let req = Request::post("/USERS/123").body(Body::empty()).unwrap();
    let res = router.serve(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, "Create User");

    let req = Request::put("/users/123").body(Body::empty()).unwrap();
    let res = router.serve(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        res.headers().get(header::ALLOW).unwrap().to_str().unwrap(),
        "GET, POST"
    );
}

#[tokio::test]
async fn test_router_method_not_allowed() {
    let router = Router::new()
        .with_get("/users", get_users_service())
        .with_post("/users", create_user_service())
        .with_get("/users/{user_id}", get_user_service())
        .with_delete("/users/{user_id}", delete_user_service())
        .with_not_found(not_found_service());

    let router = ErrorHandlerLayer::new().layer(router);

    // PUT /users/123 → 405: verify status, Allow header, and empty body in one shot
    let req = Request::put("/users/123").body(Body::empty()).unwrap();
    let res = router.serve(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        res.headers()
            .get(header::ALLOW)
            .expect("Allow header must be present on 405")
            .to_str()
            .unwrap(),
        "DELETE, GET"
    );
    let body = res.into_body().collect().await.unwrap().to_bytes();
    assert!(
        body.is_empty(),
        "405 body must be empty, not from not_found service"
    );

    // DELETE /users → 405 with a different Allow set (GET, POST)
    let req = Request::delete("/users").body(Body::empty()).unwrap();
    let res = router.serve(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        res.headers().get(header::ALLOW).unwrap().to_str().unwrap(),
        "GET, POST"
    );

    // Unknown path → 404, no Allow header (not_found service body present)
    let req = Request::get("/nonexistent").body(Body::empty()).unwrap();
    let res = router.serve(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert!(
        res.headers().get(header::ALLOW).is_none(),
        "404 must not carry Allow header"
    );
}

#[tokio::test]
async fn test_router_method_not_allowed_no_not_found_service() {
    // Verify 405 fires correctly when no custom not_found service is registered.
    let router = Router::new()
        .with_get("/users/{user_id}", get_user_service())
        .with_delete("/users/{user_id}", delete_user_service());

    let router = ErrorHandlerLayer::new().layer(router);

    let req = Request::put("/users/123").body(Body::empty()).unwrap();
    let res = router.serve(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        res.headers().get(header::ALLOW).unwrap().to_str().unwrap(),
        "DELETE, GET"
    );

    // Unknown path without not_found service → plain 404, no Allow header
    let req = Request::get("/nonexistent").body(Body::empty()).unwrap();
    let res = router.serve(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert!(res.headers().get(header::ALLOW).is_none());
}

#[tokio::test]
async fn test_router_capture_beats_catch_all_either_order() {
    fn name_svc() -> impl Service<Request, Output = Response, Error = Infallible> {
        service_fn(|req: Request| async move {
            let p = req.extensions().get_ref::<UriParams>().unwrap();
            Ok(Response::builder()
                .status(200)
                .body(Body::from(format!("name:{}", p.get("name").unwrap())))
                .unwrap())
        })
    }
    fn rest_svc() -> impl Service<Request, Output = Response, Error = Infallible> {
        service_fn(|req: Request| async move {
            let p = req.extensions().get_ref::<UriParams>().unwrap();
            Ok(Response::builder()
                .status(200)
                .body(Body::from(format!("rest:{}", p.get("rest").unwrap())))
                .unwrap())
        })
    }

    // `{name}` (rank 1) must win over `{*rest}` (rank 0) on a single-segment
    // path, independent of registration order.
    let routers = [
        Router::new()
            .with_get("/files/{name}", name_svc())
            .with_get("/files/{*rest}", rest_svc()),
        Router::new()
            .with_get("/files/{*rest}", rest_svc())
            .with_get("/files/{name}", name_svc()),
    ];
    for router in routers {
        let router = ErrorHandlerLayer::new().layer(router);
        let req = Request::get("/files/x").body(Body::empty()).unwrap();
        let res = router.serve(req).await.unwrap();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "name:x");
    }

    // A multi-segment path no longer fits `{name}` and falls to the catch-all.
    let router = ErrorHandlerLayer::new().layer(
        Router::new()
            .with_get("/files/{name}", name_svc())
            .with_get("/files/{*rest}", rest_svc()),
    );
    let req = Request::get("/files/a/b").body(Body::empty()).unwrap();
    let res = router.serve(req).await.unwrap();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, "rest:a/b");
}

#[tokio::test]
async fn test_router_affixed_dynamic_beats_plain_dynamic_either_order() {
    fn plain_svc() -> impl Service<Request, Output = Response, Error = Infallible> {
        service_fn(|req: Request| async move {
            let p = req.extensions().get_ref::<UriParams>().unwrap();
            Ok(Response::builder()
                .status(200)
                .body(Body::from(format!("plain:{}", p.get("name").unwrap())))
                .unwrap())
        })
    }
    fn json_svc() -> impl Service<Request, Output = Response, Error = Infallible> {
        service_fn(|req: Request| async move {
            let p = req.extensions().get_ref::<UriParams>().unwrap();
            Ok(Response::builder()
                .status(200)
                .body(Body::from(format!("json:{}", p.get("name").unwrap())))
                .unwrap())
        })
    }

    let routers = [
        Router::new()
            .with_get("/files/{name}", plain_svc())
            .with_get("/files/{name}.json", json_svc()),
        Router::new()
            .with_get("/files/{name}.json", json_svc())
            .with_get("/files/{name}", plain_svc()),
    ];
    for router in routers {
        let router = ErrorHandlerLayer::new().layer(router);
        let req = Request::get("/files/readme.json")
            .body(Body::empty())
            .unwrap();
        let res = router.serve(req).await.unwrap();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "json:readme");
    }
}

#[tokio::test]
async fn test_router_equal_specificity_preserves_registration_order() {
    fn svc(label: &'static str) -> impl Service<Request, Output = Response, Error = Infallible> {
        service_fn(move |_req: Request| async move {
            Ok(Response::builder()
                .status(200)
                .body(Body::from(label))
                .unwrap())
        })
    }

    let router = ErrorHandlerLayer::new().layer(
        Router::new()
            .with_get("/files/{a}", svc("first"))
            .with_get("/files/{b}", svc("second")),
    );
    let req = Request::get("/files/readme").body(Body::empty()).unwrap();
    let res = router.serve(req).await.unwrap();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, "first");
}

#[test]
fn fallback_registration_reuses_an_existing_path_entry() {
    let mut router = Router::new().with_get("/same", root_service());
    router.set_fallback_match_route("/same", HttpMatcher::method_post(), create_user_service());

    assert_eq!(router.routes.len(), 1);
    let matched = router
        .routes
        .match_full(PathRef::from_raw_str("/same"))
        .unwrap();
    assert_eq!(matched.value().handlers.len(), 1);
    assert_eq!(matched.value().fallback_handlers.len(), 1);
}

#[tokio::test]
async fn fallback_routes_keep_specificity_order() {
    fn svc(label: &'static str) -> impl Service<Request, Output = Response, Error = Infallible> {
        service_fn(move |_req: Request| async move { Ok(Response::new(Body::from(label))) })
    }

    let router = Router::new()
        .with_fallback_match_route(
            "/assets/{*path}",
            HttpMatcher::method_get(),
            svc("catch-all"),
        )
        .with_fallback_match_route("/assets/app.js", HttpMatcher::method_get(), svc("static"));
    let response = router
        .serve(Request::get("/assets/app.js").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "static"
    );
}

#[tokio::test]
async fn test_router_anonymous_glob_surfaces_via_uri_params() {
    fn glob_svc() -> impl Service<Request, Output = Response, Error = Infallible> {
        service_fn(|req: Request| async move {
            let p = req.extensions().get_ref::<UriParams>().unwrap();
            // anon `{*}` is the glob, not a named param
            assert!(p.get("rest").is_none());
            Ok(Response::builder()
                .status(200)
                .body(Body::from(format!("glob:{}", p.glob().unwrap())))
                .unwrap())
        })
    }
    let router = ErrorHandlerLayer::new().layer(Router::new().with_get("/assets/{*}", glob_svc()));
    let req = Request::get("/assets/css/app.css")
        .body(Body::empty())
        .unwrap();
    let res = router.serve(req).await.unwrap();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    // glob() is path-style (leading `/`), unlike a named catch-all param.
    assert_eq!(body, "glob:/css/app.css");
}

#[tokio::test]
async fn test_router_invalid_catch_all_mount_is_literal() {
    // RAMA-PR1027-001: `{*bad name}` is an invalid catch-all body, so the
    // matcher treats it as a literal segment. The mount must therefore NOT
    // collapse to `/api`; `/api/users` must not reach the nested service.
    let app = Router::new()
        .with_sub_service(
            "/api/{*bad name}",
            Router::new().with_get("/", root_service()),
        )
        .with_not_found(not_found_service());
    let app = ErrorHandlerLayer::new().layer(app);

    let req = Request::get("/api/users").body(Body::empty()).unwrap();
    let res = app.serve(req).await.unwrap();
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "invalid catch-all must not mount the sub-service at /api"
    );
}

#[tokio::test]
async fn test_sub_service_mount_respects_segment_boundaries() {
    for prefix in ["/api", "/api/{id}"] {
        let app = Router::new()
            .with_sub_service(prefix, Router::new().with_get("/", root_service()))
            .with_not_found(not_found_service());
        let app = ErrorHandlerLayer::new().layer(app);

        let req = Request::get("/apix/123").body(Body::empty()).unwrap();
        let res = app.serve(req).await.unwrap();
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "mount prefix {prefix:?} must not match inside a path segment",
        );
    }
}

#[tokio::test]
#[tracing_test::traced_test]
async fn test_router_nest() {
    let cases = [
        (Method::GET, "/", "Hello, World!", StatusCode::OK),
        (Method::GET, "/api/users", "List Users", StatusCode::OK),
        (Method::POST, "/api/users", "Create User", StatusCode::OK),
        (
            Method::DELETE,
            "/api/users/123",
            "Delete User: 123",
            StatusCode::OK,
        ),
        (
            Method::GET,
            "/api/users/123",
            "Get User: 123",
            StatusCode::OK,
        ),
        (
            Method::GET,
            "/api/users/123/orders/456",
            "Get Order: 456 for User: 123",
            StatusCode::OK,
        ),
        (Method::GET, "/api/state", "state", StatusCode::OK),
        (Method::GET, "/api/users/123/state", "state", StatusCode::OK),
        // to test case insensitive :)
        (Method::GET, "/Api/USERS/123/State", "state", StatusCode::OK),
    ];

    let state = "state".to_owned();

    for prefix in ["/", ""] {
        let api_router = Router::new_with_state(state.clone())
            .with_get(format!("{prefix}users"), get_users_service())
            .with_get(
                format!("{prefix}state"),
                async |State(state): State<String>| state,
            )
            .with_post(format!("{prefix}users"), create_user_service())
            .with_delete(format!("{prefix}users/{{user_id}}"), delete_user_service())
            .with_sub_router_make_fn(
                format!("{prefix}users/{{user_id}}/{{*}}"), // glob should be dropped by nester
                |router| {
                    router
                        .with_get(prefix, get_user_service())
                        .with_get(
                            format!("{prefix}orders/{{order_id}}"),
                            get_user_order_service(),
                        )
                        .with_get(
                            format!("{prefix}/state"),
                            async |State(state): State<String>| state,
                        )
                },
            );

        let app = Router::new()
            .with_sub_service(format!("{prefix}api"), api_router)
            .with_get(prefix, root_service());

        let app = ErrorHandlerLayer::new().layer(app);

        for (method, path, expected_body, expected_status) in cases.iter() {
            let req = match *method {
                Method::GET => Request::get(*path),
                Method::POST => Request::post(*path),
                Method::DELETE => Request::delete(*path),
                _ => panic!("Unsupported HTTP method"),
            }
            .body(Body::empty())
            .unwrap();

            let res = app.serve(req).await.unwrap();
            assert_eq!(
                res.status(),
                *expected_status,
                "method: {method} ; path = {path}; prefix = {prefix}"
            );
            let body = res.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(
                body, expected_body,
                "method: {method} ; path = {path}; prefix = {prefix}"
            );
        }

        // PUT /api/users/123: the api router has DELETE /users/{user_id}, and the
        // sub-router mounted on users/{user_id} has GET /. Neither takes PUT, so the
        // 405 names every method the path does take.
        let req = Request::put("/api/users/123").body(Body::empty()).unwrap();
        let res = app.serve(req).await.unwrap();
        assert_eq!(
            res.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "nested router: PUT /api/users/123 must be 405; prefix = {prefix}"
        );
        assert_eq!(
            res.headers().get(header::ALLOW).unwrap().to_str().unwrap(),
            "DELETE, GET",
            "nested router: Allow header merges the methods of every router on the path; prefix = {prefix}"
        );
    }
}

#[tokio::test]
async fn default_and_strict_path_policy_matrix() {
    assert_eq!(
        PathMatchPolicy::default(),
        PathMatchPolicy::new(PathCase::AsciiInsensitive, PathDecoding::PercentDecoded)
    );

    let default = ErrorHandlerLayer::new().layer(
        Router::new()
            .with_get("/send/{value}", capture_service("value"))
            .with_get("/case", label_service("lower"))
            .with_get("/CASE", label_service("upper"))
            .with_not_found(not_found_service()),
    );
    assert_eq!(
        default.get_ref().path_match_policy(),
        PathMatchPolicy::default()
    );

    for (path, expected) in [
        ("/send/abc", "abc"),
        ("/SEND/abc", "abc"),
        ("/send/a%2Fb", "a/b"),
        ("/send/a%252Fb", "a%2Fb"),
        ("/send/%2e%2e", ".."),
    ] {
        assert_eq!(
            get_text(&default, path).await,
            (StatusCode::OK, expected.into())
        );
    }
    for path in ["/case", "/CASE", "/CaSe"] {
        assert_eq!(
            get_text(&default, path).await,
            (StatusCode::OK, "lower".into())
        );
    }

    let strict = ErrorHandlerLayer::new().layer(
        Router::new_with_path_match_policy(PathMatchPolicy::STRICT)
            .with_get("/send/{value}", capture_service("value"))
            .with_get("/case", label_service("lower"))
            .with_get("/CASE", label_service("upper"))
            .with_get("/encoded/a%2Fb", label_service("upper escape"))
            .with_get("/encoded/a%2fb", label_service("lower escape"))
            .with_not_found(not_found_service()),
    );
    assert_eq!(
        strict.get_ref().path_match_policy(),
        PathMatchPolicy::STRICT
    );

    for (path, expected) in [
        ("/send/abc", "abc"),
        ("/send/a%2Fb", "a%2Fb"),
        ("/send/a%252Fb", "a%252Fb"),
        ("/send/%2e%2e", "%2e%2e"),
        ("/case", "lower"),
        ("/CASE", "upper"),
        ("/encoded/a%2Fb", "upper escape"),
        ("/encoded/a%2fb", "lower escape"),
    ] {
        assert_eq!(
            get_text(&strict, path).await,
            (StatusCode::OK, expected.into())
        );
    }
    for path in ["/SEND/abc", "/CaSe"] {
        assert_eq!(get_text(&strict, path).await.0, StatusCode::NOT_FOUND);
    }

    // The URI retains malformed input for display, but its encoded path
    // view escapes the stray percent sign. Decoded routing reverses that
    // canonical escape once; raw routing preserves the encoded view.
    for (input, decoded, raw) in [
        ("/send/%", "%", "%25"),
        ("/send/%2", "%2", "%252"),
        ("/send/%GG", "%GG", "%25GG"),
    ] {
        let request = Request::get(input).body(Body::empty()).unwrap();
        assert_eq!(request.uri().to_string(), input);
        assert_eq!(
            get_text(&default, input).await,
            (StatusCode::OK, decoded.into())
        );
        assert_eq!(get_text(&strict, input).await, (StatusCode::OK, raw.into()));
    }
}

#[tokio::test]
async fn path_policy_axes_are_independent() {
    let sensitive_decoded = PathMatchPolicy::new(PathCase::Sensitive, PathDecoding::PercentDecoded);
    let router = ErrorHandlerLayer::new().layer(
        Router::new_with_path_match_policy(sensitive_decoded)
            .with_get("/send/{value}", capture_service("value"))
            .with_not_found(not_found_service()),
    );
    assert_eq!(
        get_text(&router, "/send/a%2Fb").await,
        (StatusCode::OK, "a/b".into())
    );
    assert_eq!(
        get_text(&router, "/SEND/a%2Fb").await.0,
        StatusCode::NOT_FOUND
    );

    let insensitive_raw = PathMatchPolicy::new(PathCase::AsciiInsensitive, PathDecoding::Raw);
    let router = ErrorHandlerLayer::new().layer(
        Router::new_with_path_match_policy(insensitive_raw)
            .with_get("/send/{value}", capture_service("value"))
            .with_not_found(not_found_service()),
    );
    assert_eq!(
        get_text(&router, "/SEND/a%2Fb").await,
        (StatusCode::OK, "a%2Fb".into())
    );
}

#[test]
fn stateful_router_policy_is_defaulted_or_explicit() {
    let default = Router::<String>::new_with_state("state".to_owned());
    assert_eq!(default.path_match_policy(), PathMatchPolicy::default());

    let strict = Router::<String>::new_with_state_and_path_match_policy(
        "state".to_owned(),
        PathMatchPolicy::STRICT,
    );
    assert_eq!(strict.path_match_policy(), PathMatchPolicy::STRICT);
}

#[tokio::test]
async fn path_policy_applies_to_wildcards_and_mounted_prefixes() {
    let default = ErrorHandlerLayer::new().layer(
        Router::new()
            .with_get("/assets/{*path}", capture_service("path"))
            .with_sub_service(
                "/tenants/{tenant}",
                Router::new().with_get("/{item}", joined_capture_service("tenant", "item")),
            )
            .with_not_found(not_found_service()),
    );
    assert_eq!(
        get_text(&default, "/ASSETS/a%2Fb/c%2Ed").await,
        (StatusCode::OK, "a/b/c.d".into())
    );
    assert_eq!(
        get_text(&default, "/TENANTS/Acme%2FBlue/Part%2FOne").await,
        (StatusCode::OK, "Acme/Blue|Part/One".into())
    );

    let strict = ErrorHandlerLayer::new().layer(
        Router::new_with_path_match_policy(PathMatchPolicy::STRICT)
            .with_get("/assets/{*path}", capture_service("path"))
            .with_sub_service(
                "/tenants/{tenant}",
                Router::new().with_get("/{item}", joined_capture_service("tenant", "item")),
            )
            .with_not_found(not_found_service()),
    );
    assert_eq!(
        get_text(&strict, "/assets/a%2Fb/c%2Ed").await,
        (StatusCode::OK, "a%2Fb/c%2Ed".into())
    );
    assert_eq!(
        get_text(&strict, "/tenants/Acme%2FBlue/Part%2FOne").await,
        (StatusCode::OK, "Acme%2FBlue|Part/One".into())
    );
    for path in ["/ASSETS/a%2Fb/c%2Ed", "/TENANTS/Acme%2FBlue/Part%2FOne"] {
        assert_eq!(get_text(&strict, path).await.0, StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn nested_and_fallback_routes_inherit_the_router_policy() {
    let router = Router::new_with_path_match_policy(PathMatchPolicy::STRICT)
        .with_sub_router_make_fn("/api", |nested| {
            assert_eq!(nested.path_match_policy(), PathMatchPolicy::STRICT);
            nested.with_get("/Value", label_service("nested"))
        })
        .with_fallback_match_route(
            "/problem/{value}",
            HttpMatcher::method_get(),
            capture_service("value"),
        )
        .with_not_found(not_found_service());
    let router = ErrorHandlerLayer::new().layer(router);

    assert_eq!(
        get_text(&router, "/api/Value").await,
        (StatusCode::OK, "nested".into())
    );
    assert_eq!(
        get_text(&router, "/problem/a%2Fb").await,
        (StatusCode::OK, "a%2Fb".into())
    );
    for path in ["/API/Value", "/api/value", "/PROBLEM/a%2Fb"] {
        assert_eq!(get_text(&router, path).await.0, StatusCode::NOT_FOUND);
    }
}
#[derive(Debug, Clone, Extension)]
struct Leaked;

/// Records match metadata and then declines the request.
struct InsertThenDecline;

impl Matcher<Request> for InsertThenDecline {
    fn matches(&self, ext: Option<&Extensions>, _req: &Request) -> bool {
        if let Some(ext) = ext {
            ext.insert(Leaked);
        }
        false
    }
}

#[tokio::test]
async fn test_router_failed_matcher_leaves_no_extensions() {
    async fn leak_free(req: Request) -> StatusCode {
        if req.extensions().contains::<Leaked>() {
            StatusCode::INTERNAL_SERVER_ERROR
        } else {
            StatusCode::OK
        }
    }

    let router = Router::new()
        .with_match_route(
            "/items/{id}",
            HttpMatcher::custom(InsertThenDecline),
            StatusCode::IM_A_TEAPOT,
        )
        .with_match_route("/items/{id}", HttpMatcher::method_get(), leak_free);

    let req = Request::get("/items/42").body(Body::empty()).unwrap();
    let res = router.serve(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn nested_mounts_keep_the_uri_the_outermost_router_received() {
    let original = service_fn(async |req: Request| {
        let uri = req.extensions().get_ref::<OriginalRouterUri>().unwrap();
        Ok::<_, Infallible>(Response::new(Body::from(format!(
            "{} {}",
            uri.0,
            req.uri()
        ))))
    });
    let router = Router::new().with_sub_router_make_fn("/a", |router| {
        router.with_sub_router_make_fn("/b", |router| router.with_get("/c", original))
    });
    let response = router
        .serve(Request::get("/a/b/c").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, "/a/b/c /c");
}

#[tokio::test]
async fn a_negated_method_set_still_names_the_methods_a_path_takes() {
    let router = ErrorHandlerLayer::new().layer(Router::new().with_match_route(
        "/x",
        HttpMatcher::method_get().or_method_post().negate(),
        root_service(),
    ));
    let serve = async |request: Request| router.serve(request).await.unwrap();
    let refused = serve(Request::get("/x").body(Body::empty()).unwrap()).await;
    assert_eq!(refused.status(), StatusCode::METHOD_NOT_ALLOWED);
    let allow = refused
        .headers()
        .get(header::ALLOW)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(allow.contains("DELETE") && !allow.contains("GET") && !allow.contains("POST"));
    let taken = serve(Request::delete("/x").body(Body::empty()).unwrap()).await;
    assert_eq!(taken.status(), StatusCode::OK);
}

#[tokio::test]
async fn an_optional_trailing_slash_names_the_same_mount_prefix() {
    for prefixes in [["/assets", "/assets/?"], ["/assets/?", "/assets"]] {
        let router = ErrorHandlerLayer::new().layer(
            Router::new()
                .with_sub_router_make_fn(prefixes[0], |router| router)
                .with_endpoint_service(prefixes[1], label_service("second")),
        );
        let (status, body) = get_text(&router, "/assets/missing").await;
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::OK, "second"),
            "{prefixes:?}"
        );
    }
}

#[tokio::test]
async fn an_extension_method_a_negated_method_set_takes_is_no_405() {
    let propfind = || {
        Request::builder()
            .method(Method::from_bytes(b"PROPFIND").unwrap())
            .uri("/x")
    };
    let takes_all = HttpMatcher::method_get().and_method_post().negate();
    let router = ErrorHandlerLayer::new().layer(
        Router::new()
            .with_match_route(
                "/x",
                takes_all.and_header_exists(header::AUTHORIZATION),
                root_service(),
            )
            .with_match_route("/y", HttpMatcher::method_get(), root_service()),
    );
    let serve = async |request: Request| router.serve(request).await.unwrap().status();
    let missing_header = serve(propfind().body(Body::empty()).unwrap()).await;
    assert_eq!(missing_header, StatusCode::NOT_FOUND);
    let taken = propfind().header(header::AUTHORIZATION, "x");
    assert_eq!(
        serve(taken.body(Body::empty()).unwrap()).await,
        StatusCode::OK
    );
    let refused = Request::builder()
        .method(Method::from_bytes(b"PROPFIND").unwrap())
        .uri("/y");
    assert_eq!(
        serve(refused.body(Body::empty()).unwrap()).await,
        StatusCode::METHOD_NOT_ALLOWED
    );
}

#[tokio::test]
async fn a_negated_group_with_another_term_still_names_its_methods() {
    let only_post_without_auth = HttpMatcher::method_post()
        .negate()
        .or_header_exists(header::AUTHORIZATION)
        .negate();
    let router = ErrorHandlerLayer::new().layer(Router::new().with_match_route(
        "/x",
        only_post_without_auth,
        root_service(),
    ));
    let refused = router
        .serve(Request::get("/x").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(refused.headers().get(header::ALLOW).unwrap(), "POST");
}
