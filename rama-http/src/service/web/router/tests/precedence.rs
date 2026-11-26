//! Precedence of the web [`Router`](super::super::Router) across routes, mounts, nested routers and matchers.

use std::{
    cmp::Reverse,
    collections::BTreeSet,
    convert::Infallible,
    env, fs,
    future::{pending, poll_fn},
    path::{Path, PathBuf},
    process,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::Poll,
};

use rama_core::{
    Layer,
    extensions::{Extension, Extensions, ExtensionsRef},
    layer::MapOutputLayer,
    matcher::Matcher,
    service::{Service, service_fn},
};
use rama_http_types::{
    Body, Method, Request, Response, StatusCode,
    body::util::BodyExt,
    header::{self, HeaderName},
    mime,
};
use rama_net::uri::{PathPattern, PathRef};
use rama_utils::thirdparty::regex::Regex;

use super::super::{Router, RouterError};
use crate::{
    layer::error_handling::ErrorHandlerLayer,
    matcher::{HttpMatcher, UriParams},
    service::web::extract::State,
};

const MARK: HeaderName = HeaderName::from_static("x-mark");

fn router() -> Router {
    Router::new()
}

fn reply(
    label: &'static str,
) -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    service_fn(move |_req: Request| async move { Ok(Response::new(Body::from(label))) })
}

fn opaque(
    label: &'static str,
    status: StatusCode,
) -> impl Service<Request, Output = Response, Error = RouterError> + Clone {
    service_fn(move |_req: Request| async move {
        let mut res = Response::new(Body::from(label));
        *res.status_mut() = status;
        Ok(res)
    })
}

fn identity(res: Response) -> Response {
    res
}

/// A directory under the system temp dir, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(files: &[(&str, &str)]) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = env::temp_dir().join(format!("rama-router-tests-{}-{n}", process::id()));
        _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        for (name, content) in files {
            let path = root.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        }
        Self(root)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Reply {
    status: StatusCode,
    body: String,
    allow: Option<String>,
    location: Option<String>,
}

fn ok(body: &str) -> Reply {
    Reply {
        status: StatusCode::OK,
        body: body.to_owned(),
        allow: None,
        location: None,
    }
}

fn not_found() -> Reply {
    Reply {
        status: StatusCode::NOT_FOUND,
        body: String::new(),
        allow: None,
        location: None,
    }
}

fn not_allowed(allow: &str) -> Reply {
    Reply {
        status: StatusCode::METHOD_NOT_ALLOWED,
        body: String::new(),
        allow: Some(allow.to_owned()),
        location: None,
    }
}

async fn send_req<S>(svc: &S, req: Request) -> Reply
where
    S: Service<Request, Output = Response, Error = Infallible>,
{
    let res = svc.serve(req).await.unwrap();
    let status = res.status();
    let header_text = |name| {
        res.headers()
            .get(name)
            .map(|v: &header::HeaderValue| v.to_str().unwrap().to_owned())
    };
    let allow = header_text(header::ALLOW);
    let location = header_text(header::LOCATION);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    Reply {
        status,
        body: String::from_utf8(body.to_vec()).unwrap(),
        allow,
        location,
    }
}

async fn send<S>(svc: &S, method: Method, path: &str, marked: bool) -> Reply
where
    S: Service<Request, Output = Response, Error = Infallible>,
{
    let mut builder = Request::builder().method(method).uri(path);
    if marked {
        builder = builder.header(MARK, "1");
    }
    send_req(svc, builder.body(Body::empty()).unwrap()).await
}

async fn get<S>(svc: &S, path: &str) -> Reply
where
    S: Service<Request, Output = Response, Error = Infallible>,
{
    send(svc, Method::GET, path, false).await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MountStyle {
    MakeFn,
    SubService,
    Layered,
}

const MOUNT_STYLES: [MountStyle; 3] = [
    MountStyle::MakeFn,
    MountStyle::SubService,
    MountStyle::Layered,
];

fn mount_nested(
    parent: Router,
    prefix: &str,
    style: MountStyle,
    configure: impl FnOnce(Router) -> Router,
) -> Router {
    match style {
        MountStyle::MakeFn => parent.with_sub_router_make_fn(prefix, configure),
        MountStyle::SubService => parent.with_sub_service(prefix, configure(router())),
        MountStyle::Layered => parent.with_sub_service(
            prefix,
            MapOutputLayer::new(identity as fn(Response) -> Response)
                .into_layer(configure(router())),
        ),
    }
}

#[tokio::test]
async fn root_mount_receives_requests() {
    let app = ErrorHandlerLayer::new()
        .into_layer(router().with_sub_service("/", opaque("root", StatusCode::OK)));
    assert_eq!(get(&app, "/x").await, ok("root"));
    assert_eq!(get(&app, "/").await, ok("root"));
}

#[tokio::test]
async fn route_beats_mount_in_either_order() {
    let routes_first = router()
        .with_get("/api/users", reply("route"))
        .with_sub_service("/api", opaque("mount", StatusCode::OK));
    let mounts_first = router()
        .with_sub_service("/api", opaque("mount", StatusCode::OK))
        .with_get("/api/users", reply("route"));
    for app in [routes_first, mounts_first] {
        let app = ErrorHandlerLayer::new().into_layer(app);
        assert_eq!(get(&app, "/api/users").await, ok("route"));
        assert_eq!(get(&app, "/api/other").await, ok("mount"));
    }
}

#[tokio::test]
async fn most_specific_route_wins_in_either_order() {
    let forward = router()
        .with_get("/files/{*rest}", reply("rest"))
        .with_get("/files/{name}", reply("name"))
        .with_get("/files/readme", reply("readme"));
    let backward = router()
        .with_get("/files/readme", reply("readme"))
        .with_get("/files/{name}", reply("name"))
        .with_get("/files/{*rest}", reply("rest"));
    for app in [forward, backward] {
        let app = ErrorHandlerLayer::new().into_layer(app);
        assert_eq!(get(&app, "/files/readme").await, ok("readme"));
        assert_eq!(get(&app, "/files/other").await, ok("name"));
        assert_eq!(get(&app, "/files/a/b").await, ok("rest"));
    }
}

#[tokio::test]
async fn most_specific_route_owns_the_path_and_answers_405() {
    let app = ErrorHandlerLayer::new().into_layer(
        router()
            .with_post("/files/{name}", reply("vague"))
            .with_get("/files/readme", reply("readme")),
    );
    assert_eq!(
        send(&app, Method::POST, "/files/readme", false).await,
        not_allowed("GET")
    );
}

#[tokio::test]
async fn same_pattern_first_accepting_handler_wins() {
    let app = ErrorHandlerLayer::new().into_layer(
        router()
            .with_match_route(
                "/x",
                HttpMatcher::method_get().and_header_exists(MARK),
                reply("marked"),
            )
            .with_get("/x", reply("plain"))
            .with_get("/x", reply("shadowed"))
            .with_post("/x", reply("post")),
    );
    assert_eq!(send(&app, Method::GET, "/x", true).await, ok("marked"));
    assert_eq!(send(&app, Method::GET, "/x", false).await, ok("plain"));
    assert_eq!(send(&app, Method::POST, "/x", true).await, ok("post"));
    assert_eq!(
        send(&app, Method::DELETE, "/x", false).await,
        not_allowed("GET, POST")
    );
}

#[tokio::test]
async fn equally_specific_patterns_keep_registration_order() {
    let app = ErrorHandlerLayer::new().into_layer(
        router()
            .with_get("/files/{a}", reply("first"))
            .with_get("/files/{b}", reply("second")),
    );
    assert_eq!(get(&app, "/files/x").await, ok("first"));
}

#[tokio::test]
async fn path_bound_matcher_ranks_as_route() {
    for matcher in [
        HttpMatcher::get("/items/special"),
        HttpMatcher::method_get().and_path("/items/special"),
        HttpMatcher::path("/items/special").and_method_get(),
    ] {
        let app = ErrorHandlerLayer::new().into_layer(
            router()
                .with_get("/items/{id}", reply("vague"))
                .with_matcher(matcher, reply("matcher")),
        );
        assert_eq!(get(&app, "/items/special").await, ok("matcher"));
        assert_eq!(get(&app, "/items/other").await, ok("vague"));
        assert_eq!(
            send(&app, Method::POST, "/items/special", false).await,
            not_allowed("GET")
        );
    }
}

#[tokio::test]
async fn path_only_matcher_ranks_as_route_for_any_method() {
    let app = ErrorHandlerLayer::new().into_layer(
        router()
            .with_get("/items/{id}", reply("vague"))
            .with_matcher(HttpMatcher::path("/items/special"), reply("matcher")),
    );
    assert_eq!(get(&app, "/items/special").await, ok("matcher"));
    assert_eq!(
        send(&app, Method::DELETE, "/items/special", false).await,
        ok("matcher")
    );
}

#[tokio::test]
async fn path_bound_matcher_with_extra_terms_ranks_as_route() {
    let app = ErrorHandlerLayer::new().into_layer(
        router()
            .with_get("/items/{id}", reply("vague"))
            .with_matcher(
                HttpMatcher::method_post()
                    .and_path("/items/special")
                    .and_header_exists(MARK),
                reply("matcher"),
            ),
    );
    assert_eq!(
        send(&app, Method::POST, "/items/special", true).await,
        ok("matcher")
    );
    // the vaguer route does not catch what the more specific one declines
    assert_eq!(
        send(&app, Method::POST, "/items/special", false).await,
        not_found()
    );
    assert_eq!(get(&app, "/items/special").await, not_allowed("POST"));
}

#[tokio::test]
async fn method_refused_by_other_terms_is_not_405() {
    for style in MOUNT_STYLES {
        let top = router().with_match_route(
            "/x",
            HttpMatcher::method_get().and_header_exists(MARK),
            reply("marked"),
        );
        let nested = mount_nested(router(), "/n", style, |nested| {
            nested.with_match_route(
                "/x",
                HttpMatcher::method_get().and_header_exists(MARK),
                reply("marked"),
            )
        });
        for (app, path) in [(top, "/x"), (nested, "/n/x")] {
            let ctx = format!("{style:?} {path}");
            let app = ErrorHandlerLayer::new().into_layer(app);
            assert_eq!(
                send(&app, Method::GET, path, true).await,
                ok("marked"),
                "{ctx}"
            );
            assert_eq!(get(&app, path).await, not_found(), "{ctx}");
            assert_eq!(
                send(&app, Method::POST, path, false).await,
                not_allowed("GET"),
                "{ctx}"
            );
        }
    }
    let with_not_found = ErrorHandlerLayer::new().into_layer(
        router()
            .with_match_route(
                "/x",
                HttpMatcher::method_get().and_header_exists(MARK),
                reply("marked"),
            )
            .with_not_found(reply("nf")),
    );
    assert_eq!(get(&with_not_found, "/x").await, ok("nf"));
}

#[tokio::test]
async fn non_route_matchers_stay_path_less() {
    let app = ErrorHandlerLayer::new().into_layer(
        router()
            .with_matcher(HttpMatcher::path("/a").or_path("/b"), reply("or-path"))
            .with_matcher(HttpMatcher::path("/c").negate(), reply("negated"))
            .with_get("/a", reply("route")),
    );
    assert_eq!(get(&app, "/a").await, ok("route"));
    assert_eq!(get(&app, "/b").await, ok("or-path"));
    assert_eq!(get(&app, "/d").await, ok("negated"));
    assert_eq!(get(&app, "/c").await, not_found());
}

#[tokio::test]
async fn path_less_matchers_run_in_order_after_routes_and_mounts() {
    let app = ErrorHandlerLayer::new().into_layer(
        router()
            .with_matcher(HttpMatcher::header_exists(MARK), reply("first"))
            .with_matcher(HttpMatcher::method_post(), reply("second"))
            .with_get("/r", reply("route"))
            .with_sub_service("/m", opaque("mount", StatusCode::OK))
            .with_not_found(reply("nf")),
    );
    assert_eq!(send(&app, Method::GET, "/r", true).await, ok("route"));
    assert_eq!(send(&app, Method::POST, "/m/x", true).await, ok("mount"));
    assert_eq!(send(&app, Method::GET, "/z", true).await, ok("first"));
    assert_eq!(send(&app, Method::POST, "/z", true).await, ok("first"));
    assert_eq!(send(&app, Method::POST, "/z", false).await, ok("second"));
    assert_eq!(send(&app, Method::GET, "/z", false).await, ok("nf"));
}

#[tokio::test]
async fn dir_mount_serves_files_and_hands_back_misses() {
    let static_dir = TempDir::new(&[("a.txt", "static-a")]);
    let root_dir = TempDir::new(&[("b.txt", "root-b"), ("static/c.txt", "root-static-c")]);
    let app = ErrorHandlerLayer::new().into_layer(
        router()
            .with_dir("/static", static_dir.path())
            .with_dir("/", root_dir.path())
            .with_matcher(HttpMatcher::header_exists(MARK), reply("pathless"))
            .with_not_found(reply("nf")),
    );
    assert_eq!(get(&app, "/static/a.txt").await, ok("static-a"));
    assert_eq!(get(&app, "/b.txt").await, ok("root-b"));
    // the longer mount misses, the shorter dir mount has it
    assert_eq!(get(&app, "/static/c.txt").await, ok("root-static-c"));
    assert_eq!(
        send(&app, Method::GET, "/static/missing", true).await,
        ok("pathless")
    );
    assert_eq!(get(&app, "/static/missing").await, ok("nf"));
    assert_eq!(get(&app, "/missing").await, ok("nf"));
}

#[tokio::test]
async fn dir_mount_hands_back_methods_it_does_not_serve() {
    let root_dir = TempDir::new(&[("a.txt", "file-a")]);
    let app = ErrorHandlerLayer::new().into_layer(
        router()
            .with_dir("/", root_dir.path())
            .with_post("/upload", reply("upload"))
            .with_matcher(HttpMatcher::method_connect(), reply("connect"))
            .with_matcher(HttpMatcher::method_post(), reply("post"))
            .with_fallback_match_route("/a.txt", HttpMatcher::method_delete(), reply("fallback")),
    );
    assert_eq!(get(&app, "/a.txt").await, ok("file-a"));
    assert_eq!(
        send(&app, Method::POST, "/upload", false).await,
        ok("upload")
    );
    assert_eq!(send(&app, Method::POST, "/a.txt", false).await, ok("post"));
    assert_eq!(
        send(&app, Method::CONNECT, "/a.txt", false).await,
        ok("connect")
    );
    assert_eq!(
        send(&app, Method::DELETE, "/a.txt", false).await,
        ok("fallback")
    );
    assert_eq!(
        send(&app, Method::PUT, "/a.txt", false).await,
        not_allowed("DELETE")
    );
    assert_eq!(send(&app, Method::PUT, "/b.txt", false).await, not_found());
}

#[tokio::test]
async fn file_mount_serves_and_hands_back() {
    let dir = TempDir::new(&[("app.js", "app-js"), ("static/app.js", "root-app-js")]);
    let app = ErrorHandlerLayer::new().into_layer(
        router()
            .with_file("/app.js", dir.path().join("app.js"), mime::TEXT_JAVASCRIPT)
            .with_file(
                "/static/app.js",
                dir.path().join("missing.js"),
                mime::TEXT_JAVASCRIPT,
            )
            .with_file(
                "/gone.js",
                dir.path().join("missing.js"),
                mime::TEXT_JAVASCRIPT,
            )
            .with_dir("/", dir.path())
            .with_matcher(HttpMatcher::method_post(), reply("post"))
            .with_not_found(reply("nf")),
    );
    assert_eq!(get(&app, "/app.js").await, ok("app-js"));
    assert_eq!(send(&app, Method::POST, "/app.js", false).await, ok("post"));
    // a missing single file falls to the shorter dir mount
    assert_eq!(get(&app, "/static/app.js").await, ok("root-app-js"));
    assert_eq!(get(&app, "/gone.js").await, ok("nf"));
}

#[tokio::test]
async fn nested_router_hands_back_to_each_parent_tier_in_order() {
    let root_dir = TempDir::new(&[("api/doc.txt", "doc")]);
    for style in MOUNT_STYLES {
        let app = router()
            .with_dir("/", root_dir.path())
            .with_matcher(HttpMatcher::header_exists(MARK), reply("pathless"))
            .with_fallback_match_route("/api/{name}", HttpMatcher::method_get(), reply("fallback"))
            .with_not_found(reply("nf"));
        let app = mount_nested(app, "/api", style, |nested| {
            nested.with_get("/users", reply("nested"))
        });
        let app = ErrorHandlerLayer::new().into_layer(app);
        let ctx = format!("{style:?}");
        assert_eq!(get(&app, "/api/users").await, ok("nested"), "{ctx}");
        assert_eq!(get(&app, "/api/doc.txt").await, ok("doc"), "{ctx}");
        assert_eq!(
            send(&app, Method::GET, "/api/other", true).await,
            ok("pathless"),
            "{ctx}"
        );
        assert_eq!(get(&app, "/api/other").await, ok("fallback"), "{ctx}");
        assert_eq!(get(&app, "/api/other/deeper").await, ok("nf"), "{ctx}");
    }
}

#[tokio::test]
async fn three_levels_of_nesting_hand_back_level_by_level() {
    for style in MOUNT_STYLES {
        let app = mount_nested(router(), "/a", style, |middle| {
            let middle =
                middle.with_matcher(HttpMatcher::header_exists(MARK), reply("middle-pathless"));
            mount_nested(middle, "/b", style, |inner| {
                inner.with_get("/c", reply("inner"))
            })
        })
        .with_not_found(reply("nf"));
        let app = ErrorHandlerLayer::new().into_layer(app);
        let ctx = format!("{style:?}");
        assert_eq!(get(&app, "/a/b/c").await, ok("inner"), "{ctx}");
        assert_eq!(
            send(&app, Method::GET, "/a/b/z", true).await,
            ok("middle-pathless"),
            "{ctx}"
        );
        assert_eq!(get(&app, "/a/b/z").await, ok("nf"), "{ctx}");
        assert_eq!(
            send(&app, Method::POST, "/a/b/c", false).await,
            not_allowed("GET"),
            "{ctx}"
        );
    }
}

#[tokio::test]
async fn nested_router_with_not_found_owns_its_prefix() {
    let root_dir = TempDir::new(&[("api/doc.txt", "doc")]);
    for style in MOUNT_STYLES {
        let app = router()
            .with_dir("/", root_dir.path())
            .with_matcher(HttpMatcher::header_exists(MARK), reply("pathless"))
            .with_not_found(reply("outer-nf"));
        let app = mount_nested(app, "/api", style, |nested| {
            nested
                .with_get("/users", reply("nested"))
                .with_not_found(reply("inner-nf"))
        });
        let app = ErrorHandlerLayer::new().into_layer(app);
        let ctx = format!("{style:?}");
        assert_eq!(
            send(&app, Method::GET, "/api/doc.txt", true).await,
            ok("inner-nf"),
            "{ctx}"
        );
        assert_eq!(
            send(&app, Method::POST, "/api/users", false).await,
            not_allowed("GET"),
            "{ctx}"
        );
        assert_eq!(get(&app, "/other").await, ok("outer-nf"), "{ctx}");
    }
}

#[tokio::test]
async fn opaque_service_owns_its_prefix() {
    let app = ErrorHandlerLayer::new().into_layer(
        router()
            .with_sub_service("/svc", opaque("opaque", StatusCode::NOT_FOUND))
            .with_endpoint_service("/ep", reply("endpoint"))
            .with_get("/{*rest}", reply("catch-all"))
            .with_matcher(HttpMatcher::header_exists(MARK), reply("pathless"))
            .with_not_found(reply("nf")),
    );
    assert_eq!(
        send(&app, Method::POST, "/svc/x", true).await,
        Reply {
            status: StatusCode::NOT_FOUND,
            body: "opaque".to_owned(),
            allow: None,
            location: None,
        }
    );
    assert_eq!(
        send(&app, Method::DELETE, "/ep/x", true).await,
        ok("endpoint")
    );
    // a route still beats the mount
    assert_eq!(get(&app, "/svc/x").await, ok("catch-all"));
}

#[tokio::test]
async fn method_not_allowed_merges_parent_and_nested_methods() {
    for style in MOUNT_STYLES {
        let app = router().with_get("/items", reply("parent"));
        let app = mount_nested(app, "/", style, |nested| {
            nested.with_post("/items", reply("root-nested"))
        });
        let app = mount_nested(app, "/items", style, |nested| {
            nested.with_put("/", reply("items-nested"))
        });
        let app = ErrorHandlerLayer::new().into_layer(app);
        let ctx = format!("{style:?}");
        assert_eq!(get(&app, "/items").await, ok("parent"), "{ctx}");
        assert_eq!(
            send(&app, Method::POST, "/items", false).await,
            ok("root-nested"),
            "{ctx}"
        );
        assert_eq!(
            send(&app, Method::PUT, "/items", false).await,
            ok("items-nested"),
            "{ctx}"
        );
        assert_eq!(
            send(&app, Method::DELETE, "/items", false).await,
            not_allowed("GET, POST, PUT"),
            "{ctx}"
        );
    }
}

#[tokio::test]
async fn path_less_matcher_and_fallback_route_win_over_405() {
    for style in MOUNT_STYLES {
        let app = router()
            .with_get("/items", reply("parent"))
            .with_matcher(HttpMatcher::header_exists(MARK), reply("pathless"))
            .with_fallback_match_route("/items", HttpMatcher::method_delete(), reply("fallback"));
        let app = mount_nested(app, "/items", style, |nested| {
            nested.with_put("/", reply("nested"))
        });
        let app = ErrorHandlerLayer::new().into_layer(app);
        let ctx = format!("{style:?}");
        assert_eq!(
            send(&app, Method::POST, "/items", true).await,
            ok("pathless"),
            "{ctx}"
        );
        assert_eq!(
            send(&app, Method::DELETE, "/items", false).await,
            ok("fallback"),
            "{ctx}"
        );
        assert_eq!(
            send(&app, Method::POST, "/items", false).await,
            not_allowed("DELETE, GET, PUT"),
            "{ctx}"
        );
    }
}

fn report_request() -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    service_fn(|req: Request| async move {
        let uri = req.uri().to_string();
        let params: Vec<String> = match req.extensions().get_ref::<UriParams>() {
            Some(params) => params.iter().map(|(k, v)| format!("{k}={v}")).collect(),
            None => Vec::new(),
        };
        let body = req.into_body().collect().await.unwrap().to_bytes();
        Ok(Response::new(Body::from(format!(
            "{uri}|{}|{}",
            params.join(","),
            String::from_utf8_lossy(&body)
        ))))
    })
}

#[tokio::test]
async fn hand_back_restores_the_request_as_the_parent_received_it() {
    let tenant_dir = TempDir::new(&[("logo.png", "logo")]);
    for style in MOUNT_STYLES {
        let app = router()
            .with_dir("/static/{tenant}", tenant_dir.path())
            .with_matcher(HttpMatcher::method_post(), report_request())
            .with_not_found(report_request());
        let app = mount_nested(app, "/tenants/{tenant}", style, |nested| {
            nested.with_get("/users", reply("users"))
        });
        let app = ErrorHandlerLayer::new().into_layer(app);
        let ctx = format!("{style:?}");
        assert_eq!(get(&app, "/tenants/acme/users").await, ok("users"), "{ctx}");
        assert_eq!(
            get(&app, "/static/acme/logo.png").await,
            ok("logo"),
            "{ctx}"
        );
        for path in ["/tenants/acme/orders", "/static/acme/missing.png"] {
            let expected = ok(&format!("{path}||payload"));
            let req = Request::post(path).body(Body::from("payload")).unwrap();
            assert_eq!(send_req(&app, req).await, expected, "{ctx} POST {path}");
            let req = Request::get(path).body(Body::from("payload")).unwrap();
            assert_eq!(send_req(&app, req).await, expected, "{ctx} GET {path}");
        }
    }
}

#[tokio::test]
async fn root_dir_mount_next_to_routes_serves_index_and_nested_files() {
    let dir = TempDir::new(&[("index.html", "home"), ("style/app.css", "css")]);
    let app = ErrorHandlerLayer::new().into_layer(
        router()
            .with_get("/api/ping", reply("pong"))
            .with_dir("/", dir.path())
            .with_post("/api/items", reply("created")),
    );
    assert_eq!(get(&app, "/").await, ok("home"));
    assert_eq!(get(&app, "/index.html").await, ok("home"));
    assert_eq!(get(&app, "/style/app.css").await, ok("css"));
    assert_eq!(get(&app, "/api/ping").await, ok("pong"));
    assert_eq!(
        send(&app, Method::POST, "/api/items", false).await,
        ok("created")
    );
    assert_eq!(get(&app, "/style/missing.css").await, not_found());
}

#[tokio::test]
async fn not_found_service_on_router_without_routes() {
    let app = ErrorHandlerLayer::new().into_layer(router().with_not_found(reply("nf")));
    assert_eq!(get(&app, "/").await, ok("nf"));
    assert_eq!(send(&app, Method::POST, "/any/path", true).await, ok("nf"));
}

#[derive(Clone)]
struct AppName(&'static str);

async fn app_name(State(name): State<AppName>) -> &'static str {
    name.0
}

#[tokio::test]
async fn sub_router_make_fn_shares_the_parent_state() {
    let app = ErrorHandlerLayer::new().into_layer(
        Router::new_with_state(AppName("shared"))
            .with_get("/name", app_name)
            .with_sub_router_make_fn("/api", |nested| {
                nested.with_sub_router_make_fn("/v1", |inner| inner.with_get("/name", app_name))
            }),
    );
    assert_eq!(get(&app, "/name").await, ok("shared"));
    assert_eq!(get(&app, "/api/v1/name").await, ok("shared"));
}

#[tokio::test]
async fn root_route_and_root_dir_mount() {
    let dir = TempDir::new(&[
        ("a.txt", "file-a"),
        ("index.html", "root-index"),
        ("docs/index.html", "docs-index"),
    ]);
    let with_route = ErrorHandlerLayer::new().into_layer(
        router()
            .with_get("/", reply("root-route"))
            .with_dir("/", dir.path())
            .with_not_found(reply("nf")),
    );
    assert_eq!(get(&with_route, "/").await, ok("root-route"));
    assert_eq!(get(&with_route, "/a.txt").await, ok("file-a"));
    assert_eq!(get(&with_route, "/docs/").await, ok("docs-index"));
    assert_eq!(get(&with_route, "/a.txt/").await, ok("nf"));
    assert_eq!(get(&with_route, "/missing/").await, ok("nf"));

    let dir_only = ErrorHandlerLayer::new().into_layer(
        router()
            .with_dir("/", dir.path())
            .with_get("/route", reply("route"))
            .with_not_found(reply("nf")),
    );
    assert_eq!(get(&dir_only, "/").await, ok("root-index"));
    assert_eq!(get(&dir_only, "/route").await, ok("route"));
    assert_eq!(get(&dir_only, "/route/").await, ok("nf"));

    let empty_dir = TempDir::new(&[]);
    let no_index = ErrorHandlerLayer::new().into_layer(
        router()
            .with_dir("/", empty_dir.path())
            .with_not_found(reply("nf")),
    );
    assert_eq!(get(&no_index, "/").await, ok("nf"));
}

#[tokio::test]
async fn any_method_handler_refused_by_another_term_is_not_405() {
    let app =
        ErrorHandlerLayer::new().into_layer(router().with_get("/x", reply("get")).with_matcher(
            HttpMatcher::path("/x").and_header_exists(MARK),
            reply("marked"),
        ));
    assert_eq!(send(&app, Method::POST, "/x", false).await, not_found());
    assert_eq!(send(&app, Method::POST, "/x", true).await, ok("marked"));
    assert_eq!(get(&app, "/x").await, ok("get"));

    // the state travels with a hand-back
    let nested = ErrorHandlerLayer::new().into_layer(
        router()
            .with_get("/n/{x}", reply("get"))
            .with_sub_router_make_fn("/n", |nested| {
                nested.with_matcher(
                    HttpMatcher::path("/x").and_header_exists(MARK),
                    reply("marked"),
                )
            }),
    );
    assert_eq!(
        send(&nested, Method::POST, "/n/x", false).await,
        not_found()
    );
    assert_eq!(
        send(&nested, Method::POST, "/n/y", false).await,
        not_allowed("GET")
    );

    let restricted = ErrorHandlerLayer::new().into_layer(
        router()
            .with_get("/x", reply("get"))
            .with_delete("/x", reply("delete")),
    );
    assert_eq!(
        send(&restricted, Method::PUT, "/x", false).await,
        not_allowed("DELETE, GET")
    );
}

#[derive(Clone)]
struct CapturedId(&'static str);

impl Matcher<Request> for CapturedId {
    fn matches(&self, ext: Option<&Extensions>, _req: &Request) -> bool {
        ext.and_then(|ext| ext.get_ref::<UriParams>())
            .and_then(|params| params.get("id"))
            .is_some_and(|id| id == self.0)
    }
}

#[tokio::test]
async fn matchers_that_are_not_one_full_path_stay_path_less() {
    let app = ErrorHandlerLayer::new().into_layer(
        router()
            .with_matcher(HttpMatcher::path_prefix("/api"), reply("prefix"))
            .with_matcher(
                HttpMatcher::path("/items/{id}").and_custom(CapturedId("7")),
                reply("custom"),
            )
            .with_matcher(HttpMatcher::path("/a").or_path("/b"), reply("or-path"))
            .with_matcher(HttpMatcher::path("/c").negate(), reply("negated"))
            .with_get("/api/route", reply("api-route"))
            .with_get("/a", reply("route-a")),
    );
    assert_eq!(get(&app, "/api/users").await, ok("prefix"));
    assert_eq!(get(&app, "/api/route").await, ok("api-route"));
    assert_eq!(get(&app, "/items/7").await, ok("custom"));
    assert_eq!(get(&app, "/items/8").await, ok("negated"));
    assert_eq!(get(&app, "/a").await, ok("route-a"));
    assert_eq!(get(&app, "/b").await, ok("or-path"));
    assert_eq!(get(&app, "/c").await, not_found());
}

fn calls_inner_router(
    keep_error: bool,
) -> impl Service<Request, Output = Response, Error = RouterError> + Clone {
    service_fn(move |req: Request| async move {
        match router().serve(req).await {
            Ok(_) => Ok(Response::new(Body::from("inner answered"))),
            Err(err) if keep_error => Err(err),
            Err(_) => Ok(Response::new(Body::from("own"))),
        }
    })
}

#[tokio::test]
async fn service_that_used_a_router_internally_keeps_its_answer() {
    let keeps_answer = ErrorHandlerLayer::new().into_layer(
        router()
            .with_sub_service("/api", calls_inner_router(false))
            .with_not_found(reply("nf")),
    );
    assert_eq!(get(&keeps_answer, "/api/x").await, ok("own"));

    let returns_error = ErrorHandlerLayer::new().into_layer(
        router()
            .with_sub_service("/api", calls_inner_router(true))
            .with_not_found(reply("nf")),
    );
    assert_eq!(get(&returns_error, "/api/x").await, ok("nf"));
}

#[tokio::test]
async fn services_on_one_prefix_answer_in_registration_order() {
    let first = TempDir::new(&[("a.txt", "first-a")]);
    let second = TempDir::new(&[("a.txt", "second-a"), ("b.txt", "second-b")]);

    let dir_first = ErrorHandlerLayer::new().into_layer(
        router()
            .with_dir("/assets", first.path())
            .with_sub_service("/assets", opaque("svc", StatusCode::OK)),
    );
    assert_eq!(get(&dir_first, "/assets/a.txt").await, ok("first-a"));
    assert_eq!(get(&dir_first, "/assets/missing").await, ok("svc"));

    let service_first = ErrorHandlerLayer::new().into_layer(
        router()
            .with_sub_service("/assets", opaque("svc", StatusCode::OK))
            .with_dir("/assets", first.path()),
    );
    assert_eq!(get(&service_first, "/assets/a.txt").await, ok("svc"));

    let two_dirs = ErrorHandlerLayer::new().into_layer(
        router()
            .with_dir("/assets", first.path())
            .with_dir("/assets", second.path())
            .with_not_found(reply("nf")),
    );
    assert_eq!(get(&two_dirs, "/assets/a.txt").await, ok("first-a"));
    assert_eq!(get(&two_dirs, "/assets/b.txt").await, ok("second-b"));
    assert_eq!(get(&two_dirs, "/assets/c.txt").await, ok("nf"));
}

fn echo_path() -> impl Service<Request, Output = Response, Error = RouterError> + Clone {
    service_fn(|req: Request| async move { Ok(Response::new(Body::from(req.uri().to_string()))) })
}

#[tokio::test]
async fn mount_sees_the_remaining_path_as_written() {
    let app = ErrorHandlerLayer::new().into_layer(router().with_sub_service("/api", echo_path()));
    assert_eq!(get(&app, "/api/docs/").await, ok("/docs/"));
    assert_eq!(get(&app, "/api/docs").await, ok("/docs"));
    assert_eq!(get(&app, "/api").await, ok("/"));
    assert_eq!(get(&app, "/api/").await, ok("/"));

    let top = ErrorHandlerLayer::new().into_layer(router().with_get("/docs", reply("docs")));
    let nested = ErrorHandlerLayer::new().into_layer(
        router().with_sub_router_make_fn("/api", |nested| nested.with_get("/docs", reply("docs"))),
    );
    for path in ["/docs", "/docs/"] {
        assert_eq!(
            get(&nested, &format!("/api{path}")).await,
            get(&top, path).await,
            "{path}"
        );
    }
}

#[derive(Clone)]
struct Evaluations(Arc<AtomicUsize>);

impl Matcher<Request> for Evaluations {
    fn matches(&self, _ext: Option<&Extensions>, _req: &Request) -> bool {
        self.0.fetch_add(1, Ordering::Relaxed);
        true
    }
}

#[tokio::test]
async fn fallback_matchers_run_only_in_their_tier() {
    let evaluations = Arc::new(AtomicUsize::new(0));
    let app = ErrorHandlerLayer::new().into_layer(
        router()
            .with_fallback_match_route(
                "/x/{*rest}",
                HttpMatcher::custom(Evaluations(evaluations.clone())),
                reply("fallback"),
            )
            .with_sub_service("/x/mounted", opaque("mount", StatusCode::OK))
            .with_matcher(HttpMatcher::header_exists(MARK), reply("pathless")),
    );
    assert_eq!(get(&app, "/x/mounted/a").await, ok("mount"));
    assert_eq!(
        send(&app, Method::GET, "/x/other", true).await,
        ok("pathless")
    );
    assert_eq!(evaluations.load(Ordering::Relaxed), 0);
    assert_eq!(get(&app, "/x/other").await, ok("fallback"));
    assert_eq!(evaluations.load(Ordering::Relaxed), 1);
}

#[derive(Debug)]
struct DropCount(Arc<AtomicUsize>);

impl Drop for DropCount {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Extension)]
struct DropProbe {
    _count: Arc<DropCount>,
}

#[tokio::test]
async fn cancelling_the_parent_drops_a_handed_back_request() {
    let drops = Arc::new(AtomicUsize::new(0));
    let nested = Arc::new(router().with_get("/only", reply("only")));
    // the nested router hands back, then this layer never returns
    let stalls_after_inner = service_fn(move |req: Request| {
        let nested = nested.clone();
        async move {
            let result = nested.serve(req).await;
            pending::<()>().await;
            result
        }
    });
    let app = router().with_sub_service("/n", stalls_after_inner);
    let req = Request::get("/n/other").body(Body::empty()).unwrap();
    req.extensions().insert(DropProbe {
        _count: Arc::new(DropCount(drops.clone())),
    });

    let mut serving = Box::pin(app.serve(req));
    poll_fn(|cx| {
        assert!(serving.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    drop(serving);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn optional_segment_mount_prefix_calls_the_mount_once() {
    let calls = Arc::new(AtomicUsize::new(0));
    let nested = Arc::new(router().with_get("/b", reply("nested-b")));
    let counted = {
        let calls = calls.clone();
        service_fn(move |req: Request| {
            let nested = nested.clone();
            calls.fetch_add(1, Ordering::Relaxed);
            async move { nested.serve(req).await }
        })
    };
    let app = ErrorHandlerLayer::new().into_layer(
        router()
            .with_sub_service("/a/{id}?", counted)
            .with_not_found(reply("nf")),
    );
    // the longest match strips `/a/b`, so the nested router sees `/`
    assert_eq!(get(&app, "/a/b").await, ok("nf"));
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(get(&app, "/a/x/b").await, ok("nested-b"));
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn affixed_dynamic_beats_plain_dynamic_in_either_order() {
    let forward = router()
        .with_get("/files/{name}", reply("plain"))
        .with_get("/files/{name}.json", reply("json"));
    let backward = router()
        .with_get("/files/{name}.json", reply("json"))
        .with_get("/files/{name}", reply("plain"));
    for app in [forward, backward] {
        let app = ErrorHandlerLayer::new().into_layer(app);
        assert_eq!(get(&app, "/files/a.json").await, ok("json"));
        assert_eq!(get(&app, "/files/a.txt").await, ok("plain"));
    }
}

#[tokio::test]
async fn literal_beats_optional_segment_in_either_order() {
    let forward = router()
        .with_get("/a/{x}?/b", reply("optional"))
        .with_get("/a/b", reply("literal"));
    let backward = router()
        .with_get("/a/b", reply("literal"))
        .with_get("/a/{x}?/b", reply("optional"));
    for app in [forward, backward] {
        let app = ErrorHandlerLayer::new().into_layer(app);
        assert_eq!(get(&app, "/a/b").await, ok("literal"));
        assert_eq!(get(&app, "/a/z/b").await, ok("optional"));
    }
}

#[tokio::test]
async fn dir_mount_redirects_directories_to_the_public_path() {
    let dir = TempDir::new(&[("docs/index.html", "docs-index"), ("a.txt", "file-a")]);
    let redirect = |location: &str| Reply {
        status: StatusCode::TEMPORARY_REDIRECT,
        body: String::new(),
        allow: None,
        location: Some(location.to_owned()),
    };
    let app = ErrorHandlerLayer::new().into_layer(
        router()
            .with_dir("/static", dir.path())
            .with_sub_router_make_fn("/site", |nested| nested.with_dir("/static", dir.path()))
            .with_not_found(reply("nf")),
    );
    assert_eq!(get(&app, "/static").await, redirect("/static/"));
    assert_eq!(get(&app, "/static/docs").await, redirect("/static/docs/"));
    assert_eq!(get(&app, "/static/docs/").await, ok("docs-index"));
    // the mount root has no index.html
    assert_eq!(get(&app, "/static/").await, ok("nf"));
    assert_eq!(
        get(&app, "/site/static/docs").await,
        redirect("/site/static/docs/")
    );
    assert_eq!(get(&app, "/site/static").await, redirect("/site/static/"));
    assert_eq!(get(&app, "/site/static/a.txt").await, ok("file-a"));
}

fn counted_router(
    calls: &Arc<AtomicUsize>,
    nested: Router,
) -> impl Service<Request, Output = Response, Error = RouterError> + Clone {
    let calls = calls.clone();
    let nested = Arc::new(nested);
    service_fn(move |req: Request| {
        let nested = nested.clone();
        calls.fetch_add(1, Ordering::Relaxed);
        async move { nested.serve(req).await }
    })
}

#[tokio::test]
async fn every_mount_is_tried_at_most_once() {
    let optional_calls = Arc::new(AtomicUsize::new(0));
    let deep_calls = Arc::new(AtomicUsize::new(0));
    let app = ErrorHandlerLayer::new().into_layer(
        router()
            .with_sub_service("/a/{id}?", counted_router(&optional_calls, router()))
            .with_sub_service("/a/x/y", counted_router(&deep_calls, router()))
            .with_not_found(reply("nf")),
    );
    assert_eq!(get(&app, "/a/x/y/z").await, ok("nf"));
    assert_eq!(deep_calls.load(Ordering::Relaxed), 1);
    assert_eq!(optional_calls.load(Ordering::Relaxed), 1);
}

fn report_path_and_id() -> impl Service<Request, Output = Response, Error = RouterError> + Clone {
    service_fn(|req: Request| async move {
        let id = req
            .extensions()
            .get_ref::<UriParams>()
            .and_then(|params| params.get("id").map(str::to_owned))
            .unwrap_or_default();
        Ok(Response::new(Body::from(format!("{}|{id}", req.uri()))))
    })
}

#[tokio::test]
async fn mount_captures_come_from_the_segments_it_covered() {
    let app = ErrorHandlerLayer::new().into_layer(
        router()
            .with_sub_service("/a/b", router())
            .with_sub_service("/a/{id}?", report_path_and_id()),
    );
    assert_eq!(get(&app, "/a/b/c").await, ok("/b/c|"));
    assert_eq!(get(&app, "/a/z/c").await, ok("/c|z"));
}

#[tokio::test]
async fn router_mounted_as_endpoint_service_still_hands_back() {
    let app = ErrorHandlerLayer::new().into_layer(
        router()
            .with_endpoint_service("/api", router().with_get("/users", reply("users")))
            .with_endpoint_service("/own", opaque("own-404", StatusCode::NOT_FOUND))
            .with_matcher(HttpMatcher::header_exists(MARK), reply("pathless"))
            .with_fallback_match_route("/api/{name}", HttpMatcher::method_get(), reply("fallback"))
            .with_not_found(reply("nf")),
    );
    assert_eq!(get(&app, "/api/users").await, ok("users"));
    assert_eq!(
        send(&app, Method::GET, "/api/other", true).await,
        ok("pathless")
    );
    assert_eq!(get(&app, "/api/other").await, ok("fallback"));
    assert_eq!(get(&app, "/api/other/deeper").await, ok("nf"));
    assert_eq!(
        send(&app, Method::GET, "/own/x", true).await,
        Reply {
            status: StatusCode::NOT_FOUND,
            body: "own-404".to_owned(),
            allow: None,
            location: None,
        }
    );
}

#[tokio::test]
async fn only_a_single_plain_path_term_promotes_a_matcher() {
    for matcher in [
        HttpMatcher::path("/x").and(HttpMatcher::path("/y").negate()),
        HttpMatcher::method_post()
            .and(HttpMatcher::path("/x").or(HttpMatcher::header_exists(MARK))),
        HttpMatcher::path("/x").and_uri_regex(Regex::new("^/x$").unwrap()),
    ] {
        // a promoted literal route would beat the capture route registered after it
        let app = ErrorHandlerLayer::new().into_layer(
            router()
                .with_matcher(matcher, reply("matcher"))
                .with_get("/{p}", reply("route")),
        );
        assert_eq!(get(&app, "/x").await, ok("route"));
        assert_eq!(send(&app, Method::POST, "/x", false).await, ok("matcher"));
    }
}

#[tokio::test]
async fn trailing_slash_does_not_make_a_new_mount_prefix() {
    let dir = TempDir::new(&[("a.txt", "file-a")]);
    let dir_first = ErrorHandlerLayer::new().into_layer(
        router()
            .with_dir("/assets", dir.path())
            .with_sub_service("/assets/", opaque("svc", StatusCode::OK)),
    );
    assert_eq!(get(&dir_first, "/assets/a.txt").await, ok("file-a"));
    assert_eq!(get(&dir_first, "/assets/missing").await, ok("svc"));

    let service_first = ErrorHandlerLayer::new().into_layer(
        router()
            .with_sub_service("/assets/", opaque("svc", StatusCode::OK))
            .with_dir("/assets", dir.path()),
    );
    assert_eq!(get(&service_first, "/assets/a.txt").await, ok("svc"));
}

#[tokio::test]
async fn negated_method_guard_does_not_restrict_methods() {
    let app = ErrorHandlerLayer::new().into_layer(router().with_match_route(
        "/x",
        HttpMatcher::method_get().and_header_exists(MARK).negate(),
        reply("guarded"),
    ));
    assert_eq!(send(&app, Method::GET, "/x", true).await, not_found());
    assert_eq!(send(&app, Method::GET, "/x", false).await, ok("guarded"));
    assert_eq!(send(&app, Method::POST, "/x", true).await, ok("guarded"));
}

/// Small deterministic xorshift64 generator.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn chance(&mut self, one_in: usize) -> bool {
        self.below(one_in) == 0
    }

    fn pick<T: Clone>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())].clone()
    }
}

const METHODS: [Method; 4] = [Method::GET, Method::HEAD, Method::POST, Method::DELETE];
const PATTERN_SEGMENTS: [&str; 6] = ["a", "b", "api", "{x}", "{y}", "{x}.json"];
// overlapping mount prefixes of equal length are left unordered by the spec
const PREFIXES: [&str; 5] = ["/", "/a", "/api", "/api/", "/a/{x}"];
const REQUEST_SEGMENTS: [&str; 5] = ["a", "b", "api", "c", "a.json"];
const DIR_POOL: [&[&str]; 4] = [&["a"], &["b"], &["a", "b"], &[]];

#[derive(Debug, Clone)]
enum Item {
    Route {
        pattern: String,
        method: Method,
        id: u32,
    },
    MatcherRoute {
        pattern: String,
        method: Option<Method>,
        header: bool,
        id: u32,
    },
    Pathless {
        method: Option<Method>,
        header: bool,
        id: u32,
    },
    Dir {
        prefix: &'static str,
        pool: usize,
    },
    Nested {
        prefix: &'static str,
        def: Def,
        style: MountStyle,
    },
    Opaque {
        prefix: &'static str,
        id: u32,
    },
    Fallback {
        pattern: String,
        method: Method,
        id: u32,
    },
}

impl Item {
    fn pattern(&self) -> Option<&str> {
        match self {
            Self::Route { pattern, .. }
            | Self::MatcherRoute { pattern, .. }
            | Self::Fallback { pattern, .. } => Some(pattern),
            _ => None,
        }
    }

    fn prefix(&self) -> Option<&'static str> {
        match self {
            Self::Dir { prefix, .. }
            | Self::Nested { prefix, .. }
            | Self::Opaque { prefix, .. } => Some(prefix),
            _ => None,
        }
    }

    /// The mount prefix, which a trailing slash does not change.
    fn mount_key(&self) -> Option<&'static str> {
        self.prefix()
            .map(|prefix| match prefix.trim_end_matches('/') {
                "" => "/",
                trimmed => trimmed,
            })
    }
}

#[derive(Debug, Clone)]
struct Def {
    items: Vec<Item>,
    not_found: Option<u32>,
}

#[derive(Debug, Clone)]
struct GenRequest {
    method: Method,
    segments: Vec<&'static str>,
    trailing_slash: bool,
    header: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Answered(String),
    NotFound,
    MethodNotAllowed(Vec<String>),
    Redirect(String),
    Unexpected(u16, String),
}

fn fresh(next_id: &mut u32) -> u32 {
    *next_id += 1;
    *next_id
}

fn gen_pattern(rng: &mut Rng, used: &[String]) -> String {
    if !used.is_empty() && rng.chance(2) {
        return rng.pick(used);
    }
    let len = rng.below(3);
    let mut segments: Vec<&str> = (0..len).map(|_| rng.pick(&PATTERN_SEGMENTS)).collect();
    if rng.chance(4) {
        segments.push("{*rest}");
    }
    format!("/{}", segments.join("/"))
}

fn gen_def(rng: &mut Rng, depth: usize, next_id: &mut u32) -> Def {
    let mut handler_patterns: Vec<String> = Vec::new();
    let mut items = Vec::new();
    let count = rng.below(if depth == 0 { 9 } else { 5 });
    for _ in 0..count {
        let item = match rng.below(12) {
            0..=3 => {
                let pattern = gen_pattern(rng, &handler_patterns);
                handler_patterns.push(pattern.clone());
                Item::Route {
                    pattern,
                    method: rng.pick(&METHODS),
                    id: fresh(next_id),
                }
            }
            4 | 5 => {
                let pattern = gen_pattern(rng, &handler_patterns);
                handler_patterns.push(pattern.clone());
                let method = (!rng.chance(4)).then(|| rng.pick(&METHODS));
                Item::MatcherRoute {
                    pattern,
                    method,
                    header: rng.chance(2),
                    id: fresh(next_id),
                }
            }
            6 => {
                let header = rng.chance(2);
                let method = (!header || rng.chance(2)).then(|| rng.pick(&METHODS));
                Item::Pathless {
                    method,
                    header,
                    id: fresh(next_id),
                }
            }
            // the spec leaves open whether a pattern carrying only fallbacks ranks in tier 1
            7 if !handler_patterns.is_empty() => Item::Fallback {
                pattern: rng.pick(&handler_patterns),
                method: rng.pick(&METHODS),
                id: fresh(next_id),
            },
            8 | 9 => Item::Dir {
                prefix: rng.pick(&PREFIXES),
                pool: rng.below(DIR_POOL.len()),
            },
            10 if depth < 2 => Item::Nested {
                prefix: rng.pick(&PREFIXES),
                def: gen_def(rng, depth + 1, next_id),
                style: rng.pick(&MOUNT_STYLES),
            },
            11 if rng.chance(2) => Item::Opaque {
                prefix: rng.pick(&PREFIXES),
                id: fresh(next_id),
            },
            _ => continue,
        };
        items.push(item);
    }
    let not_found = rng.chance(3).then(|| fresh(next_id));
    Def { items, not_found }
}

fn gen_request(rng: &mut Rng) -> GenRequest {
    let len = rng.below(4);
    GenRequest {
        method: rng.pick(&METHODS),
        segments: (0..len).map(|_| rng.pick(&REQUEST_SEGMENTS)).collect(),
        trailing_slash: len > 0 && rng.chance(4),
        header: rng.chance(2),
    }
}

type Specificity = Vec<(u8, usize)>;

/// Spec ranking read off the generator alphabet: per segment literal > dynamic > catch-all,
/// then more literal bytes.
fn specificity(pattern: &str) -> Specificity {
    pattern
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| match segment.find('}') {
            _ if segment.starts_with("{*") => (0, 0),
            Some(close) if segment.starts_with('{') => (1, segment.len() - close - 1),
            _ => (2, segment.len()),
        })
        .collect()
}

fn path_of(segments: &[&str], trailing_slash: bool) -> String {
    if segments.is_empty() {
        return "/".to_owned();
    }
    let slash = if trailing_slash { "/" } else { "" };
    format!("/{}{slash}", segments.join("/"))
}

fn answer(id: u32) -> Outcome {
    Outcome::Answered(format!("h{id}"))
}

/// What the handlers of the matched path take, merged across hand-backs.
#[derive(Default)]
struct Taken {
    listed: BTreeSet<String>,
    any: bool,
}

enum Eval {
    Answer(Outcome),
    HandBack(Taken),
}

fn model(def: &Def, req: &GenRequest) -> Outcome {
    match eval(def, &req.segments, req.trailing_slash, req, false) {
        Eval::Answer(outcome) => outcome,
        Eval::HandBack(_) => Outcome::Unexpected(0, "model: top-level hand-back".to_owned()),
    }
}

fn accepts(method: Option<&Method>, header: bool, req: &GenRequest) -> bool {
    method.is_none_or(|m| *m == req.method) && (!header || req.header)
}

fn eval(
    def: &Def,
    segments: &[&'static str],
    trailing_slash: bool,
    req: &GenRequest,
    mounted: bool,
) -> Eval {
    let path = path_of(segments, trailing_slash);
    let mut taken = Taken::default();

    // tier 1: most specific pattern, first registered among equals
    let mut best: Option<(Specificity, &str)> = None;
    for item in &def.items {
        let Some(pattern) = item.pattern() else {
            continue;
        };
        if !PathPattern::new(pattern).is_match(PathRef::from_raw_str(&path)) {
            continue;
        }
        let key = specificity(pattern);
        if best.as_ref().is_none_or(|(best_key, _)| key > *best_key) {
            best = Some((key, pattern));
        }
    }
    let winner = best.map(|(_, pattern)| pattern);
    for item in &def.items {
        match item {
            Item::Route {
                pattern,
                method,
                id,
            } if Some(pattern.as_str()) == winner => {
                if accepts(Some(method), false, req) {
                    return Eval::Answer(answer(*id));
                }
                taken.listed.insert(method.to_string());
            }
            Item::MatcherRoute {
                pattern,
                method,
                header,
                id,
            } if Some(pattern.as_str()) == winner => {
                if accepts(method.as_ref(), *header, req) {
                    return Eval::Answer(answer(*id));
                }
                match method {
                    Some(method) => _ = taken.listed.insert(method.to_string()),
                    None => taken.any = true,
                }
            }
            Item::Fallback {
                pattern, method, ..
            } if Some(pattern.as_str()) == winner => {
                taken.listed.insert(method.to_string());
            }
            _ => {}
        }
    }

    // tier 2: mounts by longest prefix, registration order on one prefix
    let mut mounts: Vec<(usize, &Item)> = def
        .items
        .iter()
        .filter_map(|item| {
            let prefix = PathPattern::new_prefix(item.mount_key()?);
            prefix
                .is_match(PathRef::from_raw_str(&path))
                .then(|| (prefix.segment_kinds().len(), item))
        })
        .collect();
    mounts.sort_by_key(|(len, _)| Reverse(*len));
    for (len, item) in mounts {
        let rest = &segments[len..];
        let rest_trailing_slash = trailing_slash && !rest.is_empty();
        match item {
            Item::Dir { pool, .. } => {
                let reads = req.method == Method::GET || req.method == Method::HEAD;
                // the mount root is a directory, named without the slash the client must add
                if reads && rest.is_empty() && !req.segments.is_empty() && !req.trailing_slash {
                    return Eval::Answer(Outcome::Redirect(path_of(&req.segments, true)));
                }
                if reads
                    && !rest_trailing_slash
                    && let [name] = rest
                    && DIR_POOL[*pool].contains(name)
                {
                    // a HEAD response carries no body to identify the file by
                    let body = if req.method == Method::HEAD {
                        String::new()
                    } else {
                        format!("d{pool}{name}")
                    };
                    return Eval::Answer(Outcome::Answered(body));
                }
            }
            Item::Opaque { id, .. } => return Eval::Answer(answer(*id)),
            Item::Nested { def: nested, .. } => {
                match eval(nested, rest, rest_trailing_slash, req, true) {
                    Eval::Answer(outcome) => return Eval::Answer(outcome),
                    Eval::HandBack(nested_taken) => {
                        taken.listed.extend(nested_taken.listed);
                        taken.any |= nested_taken.any;
                    }
                }
            }
            _ => {
                return Eval::Answer(Outcome::Unexpected(
                    0,
                    "model: a non-mount carries a prefix".to_owned(),
                ));
            }
        }
    }

    // tier 3: path-less matchers in registration order
    for item in &def.items {
        if let Item::Pathless { method, header, id } = item
            && accepts(method.as_ref(), *header, req)
        {
            return Eval::Answer(answer(*id));
        }
    }

    // tier 4: fallback handlers of the matched path
    for item in &def.items {
        if let Item::Fallback {
            pattern,
            method,
            id,
        } = item
            && Some(pattern.as_str()) == winner
            && *method == req.method
        {
            return Eval::Answer(answer(*id));
        }
    }

    // tier 5
    if mounted && def.not_found.is_none() {
        return Eval::HandBack(taken);
    }
    if !taken.any && !taken.listed.is_empty() && !taken.listed.contains(req.method.as_str()) {
        return Eval::Answer(Outcome::MethodNotAllowed(
            taken.listed.into_iter().collect(),
        ));
    }
    match def.not_found {
        Some(id) => Eval::Answer(answer(id)),
        None => Eval::Answer(Outcome::NotFound),
    }
}

fn handler(id: u32) -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    service_fn(move |_req: Request| async move { Ok(Response::new(Body::from(format!("h{id}")))) })
}

fn opaque_handler(
    id: u32,
) -> impl Service<Request, Output = Response, Error = RouterError> + Clone {
    service_fn(move |_req: Request| async move { Ok(Response::new(Body::from(format!("h{id}")))) })
}

fn method_matcher(method: &Method) -> HttpMatcher<Body> {
    if *method == Method::GET {
        HttpMatcher::method_get()
    } else if *method == Method::HEAD {
        HttpMatcher::method_head()
    } else if *method == Method::POST {
        HttpMatcher::method_post()
    } else {
        HttpMatcher::method_delete()
    }
}

fn build(def: &Def, dirs: &[TempDir]) -> Router {
    build_into(router(), def, dirs)
}

fn build_into(mut r: Router, def: &Def, dirs: &[TempDir]) -> Router {
    for item in &def.items {
        r = match item {
            Item::Route {
                pattern,
                method,
                id,
            } => {
                if *method == Method::GET {
                    r.with_get(pattern, handler(*id))
                } else if *method == Method::HEAD {
                    r.with_head(pattern, handler(*id))
                } else if *method == Method::POST {
                    r.with_post(pattern, handler(*id))
                } else {
                    r.with_delete(pattern, handler(*id))
                }
            }
            Item::MatcherRoute {
                pattern,
                method,
                header,
                id,
            } => {
                let mut matcher = match method {
                    Some(method) if id % 2 == 0 => method_matcher(method).and_path(pattern),
                    Some(method) => HttpMatcher::path(pattern).and(method_matcher(method)),
                    None => HttpMatcher::path(pattern),
                };
                if *header {
                    matcher = matcher.and_header_exists(MARK);
                }
                r.with_matcher(matcher, handler(*id))
            }
            Item::Pathless { method, header, id } => {
                let matcher = match (method, header) {
                    (Some(method), true) => method_matcher(method).and_header_exists(MARK),
                    (Some(method), false) => method_matcher(method),
                    (None, _) => HttpMatcher::header_exists(MARK),
                };
                r.with_matcher(matcher, handler(*id))
            }
            Item::Dir { prefix, pool } => r.with_dir(prefix, dirs[*pool].path()),
            Item::Nested { prefix, def, style } => {
                mount_nested(r, prefix, *style, |nested| build_into(nested, def, dirs))
            }
            Item::Opaque { prefix, id } => {
                if id % 2 == 0 {
                    r.with_sub_service(prefix, opaque_handler(*id))
                } else {
                    r.with_endpoint_service(prefix, handler(*id))
                }
            }
            Item::Fallback {
                pattern,
                method,
                id,
            } => r.with_fallback_match_route(pattern, method_matcher(method), handler(*id)),
        };
    }
    match def.not_found {
        Some(id) => r.with_not_found(handler(id)),
        None => r,
    }
}

async fn observe<S>(svc: &S, req: &GenRequest) -> Outcome
where
    S: Service<Request, Output = Response, Error = Infallible>,
{
    let reply = send(
        svc,
        req.method.clone(),
        &path_of(&req.segments, req.trailing_slash),
        req.header,
    )
    .await;
    match reply.status {
        StatusCode::OK => Outcome::Answered(reply.body),
        StatusCode::NOT_FOUND if reply.body.is_empty() => Outcome::NotFound,
        StatusCode::METHOD_NOT_ALLOWED => {
            let mut methods: Vec<String> = reply
                .allow
                .unwrap_or_default()
                .split(',')
                .map(|m| m.trim().to_owned())
                .collect();
            methods.sort();
            Outcome::MethodNotAllowed(methods)
        }
        StatusCode::TEMPORARY_REDIRECT if reply.body.is_empty() => {
            Outcome::Redirect(reply.location.unwrap_or_default())
        }
        status => Outcome::Unexpected(status.as_u16(), reply.body),
    }
}

/// Items whose relative order the spec makes observable.
#[derive(PartialEq)]
enum OrderClass {
    Free,
    Pathless,
    Mount(&'static str),
    Ranked(Specificity),
}

fn order_class(item: &Item) -> OrderClass {
    match item {
        Item::Pathless { .. } => OrderClass::Pathless,
        _ => match (item.pattern(), item.mount_key()) {
            (Some(pattern), _) => OrderClass::Ranked(specificity(pattern)),
            (None, Some(prefix)) => OrderClass::Mount(prefix),
            (None, None) => OrderClass::Free,
        },
    }
}

/// A random registration order that keeps every order-sensitive pair in place.
fn shuffle(def: &Def, rng: &mut Rng) -> Def {
    let classes: Vec<OrderClass> = def.items.iter().map(order_class).collect();
    let mut placed = vec![false; def.items.len()];
    let mut items = Vec::with_capacity(def.items.len());
    while items.len() < def.items.len() {
        let ready: Vec<usize> = (0..def.items.len())
            .filter(|&i| {
                !placed[i]
                    && (classes[i] == OrderClass::Free
                        || (0..i).all(|j| placed[j] || classes[j] != classes[i]))
            })
            .collect();
        let next = rng.pick(&ready);
        placed[next] = true;
        items.push(match &def.items[next] {
            Item::Nested { prefix, def, style } => Item::Nested {
                prefix,
                def: shuffle(def, rng),
                style: *style,
            },
            item => item.clone(),
        });
    }
    Def {
        items,
        not_found: def.not_found,
    }
}

#[tokio::test]
async fn router_matches_reference_model() {
    const DEFINITIONS: usize = 4000;
    const REQUESTS: usize = 32;
    const SHUFFLES: usize = 3;

    let dirs: Vec<TempDir> = DIR_POOL
        .iter()
        .enumerate()
        .map(|(pool, names)| {
            let files: Vec<(String, String)> = names
                .iter()
                .map(|name| ((*name).to_owned(), format!("d{pool}{name}")))
                .collect();
            let files: Vec<(&str, &str)> = files
                .iter()
                .map(|(name, content)| (name.as_str(), content.as_str()))
                .collect();
            TempDir::new(&files)
        })
        .collect();

    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for case in 0..DEFINITIONS {
        let mut next_id = 0;
        let def = gen_def(&mut rng, 0, &mut next_id);
        let requests: Vec<GenRequest> = (0..REQUESTS).map(|_| gen_request(&mut rng)).collect();
        let expected: Vec<Outcome> = requests.iter().map(|req| model(&def, req)).collect();

        let mut orders = vec![def.clone()];
        for _ in 0..SHUFFLES {
            orders.push(shuffle(&def, &mut rng));
        }
        for (order, registered) in orders.iter().enumerate() {
            let app = ErrorHandlerLayer::new().into_layer(build(registered, &dirs));
            for (req, expected) in requests.iter().zip(&expected) {
                let actual = observe(&app, req).await;
                assert_eq!(
                    &actual, expected,
                    "case {case}, order {order} (0 = as generated)\nrequest: {req:?}\nregistered: {registered:#?}\ngenerated: {def:#?}"
                );
            }
        }
    }
}
