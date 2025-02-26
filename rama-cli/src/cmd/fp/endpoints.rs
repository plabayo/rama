use super::{
    State,
    data::{
        DataSource, FetchMode, Initiator, RequestInfo, ResourceType, TlsDisplayInfo, UserAgentInfo,
        get_http_info, get_ja4h_info, get_request_info, get_tls_display_info, get_user_agent_info,
    },
};
use crate::cmd::fp::data::TlsDisplayInfoExtensionData;
use rama::{
    Context,
    http::{
        Body, IntoResponse, Request, Response, StatusCode, response::Json,
        service::web::extract::Path,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

type Html = rama::http::response::Html<String>;

fn html<T: Into<String>>(inner: T) -> Html {
    inner.into().into()
}

//------------------------------------------
// endpoints: navigations
//------------------------------------------

pub(super) async fn get_consent() -> impl IntoResponse {
    ([("Set-Cookie", "rama-fp=ready; Max-Age=60")], render_page(
        "🕵️ Fingerprint Consent",
        String::new(),
        r##"<div class="consent">
            <div class="controls">
                <a class="button" href="/report">Get Fingerprint Report</a>
            </div>
            <div class="section">
                <p>
                    This fingerprinting service is available using the following links:
                    <ul>
                        <li><a href="http://fp.ramaproxy.org:80">http://fp.ramaproxy.org</a>: auto HTTP, plain-text</li>
                        <li><a href="https://fp.ramaproxy.org:443">https://fp.ramaproxy.org</a>: auto HTTP, TLS</li>
                        <li><a href="http://h1.fp.ramaproxy.org:80">http://h1.fp.ramaproxy.org</a>: HTTP/1.1 and below only, plain-text</li>
                        <li><a href="https://h1.fp.ramaproxy.org:443">https://h1.fp.ramaproxy.org</a>: HTTP/1.1 and below only, TLS</li>
                    </ul>
                </p>
                </p>
                    You can also make use of the echo service for developers at:
                    <ul>
                        <li><a href="http://echo.ramaproxy.org:80">http://echo.ramaproxy.org</a>: echo service, plain-text</li>
                        <li><a href="https://echo.ramaproxy.org:443">https://echo.ramaproxy.org</a>: echo service, TLS</li>
                    </ul>
                </p>
                <p>You can learn move about rama at in
                    <a href="https://ramaproxy.org/book">the rama book</a>.
                    And the source code for this service is available at
                    <a href="https://github.com/plabayo/rama/tree/main/rama-fp">https://github.com/plabayo/rama/tree/main/rama-fp</a>.
                </p>
            </div>
            <div class="small">
                <p>
                    By clicking on the button above, you agree that we will store fingerprint information about your network traffic. We are only interested in the HTTP and TLS traffic sent by you. This information will be stored in a database for later processing.
                </p>
                <p>
                    Please note that we do not store IP information and we do not use third-party tracking cookies. However, it is possible that the telecom or hosting services used by you or us may track some personalized information, over which we have no control or desire. You can use utilities like the Unix `dig` command to analyze the traffic and determine what might be tracked.
                </p>
                <div>
                <p>
                    Hosting for this service is sponsored by
                    <a href="https://fly.io">fly.io</a>.
                </p>
            </div>
        </div>"##.to_owned()
    ))
}

pub(super) async fn get_report(
    mut ctx: Context<Arc<State>>,
    req: Request,
) -> Result<Html, Response> {
    let ja4h = get_ja4h_info(&req);

    let (mut parts, _) = req.into_parts();

    let user_agent_info = get_user_agent_info(&ctx).await;

    let request_info = get_request_info(
        FetchMode::Navigate,
        ResourceType::Document,
        Initiator::Navigator,
        &mut ctx,
        &parts,
    )
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response())?;

    let http_info = get_http_info(parts.headers, &mut parts.extensions);

    let head = r#"<script src="/assets/script.js"></script>"#.to_owned();

    let mut tables = vec![
        ctx.state().data_source.clone().into(),
        user_agent_info.into(),
        request_info.into(),
        Table {
            title: "🚗 Http Headers".to_owned(),
            rows: http_info.headers,
        },
    ];

    if let Some(ja4h) = ja4h {
        tables.push(Table {
            title: "🆔 Ja4H".to_owned(),
            rows: vec![
                ("HTTP Client Fingerprint".to_owned(), ja4h.hash),
                ("Raw (Debug) String".to_owned(), ja4h.human_str),
            ],
        })
    }

    if let Some(pseudo) = http_info.pseudo_headers {
        tables.push(Table {
            title: "🚗 H2 Pseudo Headers".to_owned(),
            rows: vec![("order".to_owned(), pseudo.join(", "))],
        });
    }

    let tls_info = get_tls_display_info(&ctx);
    if let Some(tls_info) = tls_info {
        let mut tls_tables = tls_info.into();
        tables.append(&mut tls_tables);
    }

    Ok(render_report(
        "🕵️ Fingerprint Report",
        head,
        String::new(),
        tables,
    ))
}

//------------------------------------------
// endpoints: ACME
//------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct AcmeChallengeParams {
    token: String,
}

pub(super) async fn get_acme_challenge(
    Path(params): Path<AcmeChallengeParams>,
    ctx: Context<Arc<State>>,
) -> Response {
    match ctx.state().acme.get_challenge(params.token) {
        Some(challenge) => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain")
            .body(challenge.to_owned().into())
            .expect("build acme challenge response"),
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .expect("build acme challenge response"),
    }
}

//------------------------------------------
// endpoints: XHR
//------------------------------------------

#[derive(Serialize, Deserialize)]
pub(super) struct APINumberParams {
    number: usize,
}

pub(super) async fn get_api_fetch_number(
    mut ctx: Context<Arc<State>>,
    req: Request,
) -> Result<Json<serde_json::Value>, Response> {
    let ja4h = get_ja4h_info(&req);

    let (mut parts, _) = req.into_parts();

    let user_agent_info = get_user_agent_info(&ctx).await;

    let request_info = get_request_info(
        FetchMode::SameOrigin,
        ResourceType::Xhr,
        Initiator::Fetch,
        &mut ctx,
        &parts,
    )
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response())?;

    let http_info = get_http_info(parts.headers, &mut parts.extensions);

    let tls_info = get_tls_display_info(&ctx);

    Ok(Json(json!({
        "number": ctx.state().counter.fetch_add(1, std::sync::atomic::Ordering::AcqRel),
        "fp": {
            "user_agent_info": user_agent_info,
            "request_info": request_info,
            "tls_info": tls_info,
            "http_info": json!({
                "headers": http_info.headers,
                "pseudo_headers": http_info.pseudo_headers,
                "ja4h": ja4h,
            }),
        }
    })))
}

pub(super) async fn post_api_fetch_number(
    Path(params): Path<APINumberParams>,
    mut ctx: Context<Arc<State>>,
    req: Request,
) -> Result<Json<serde_json::Value>, Response> {
    let ja4h = get_ja4h_info(&req);

    let (mut parts, _) = req.into_parts();

    let user_agent_info = get_user_agent_info(&ctx).await;

    let request_info = get_request_info(
        FetchMode::SameOrigin,
        ResourceType::Xhr,
        Initiator::Fetch,
        &mut ctx,
        &parts,
    )
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response())?;

    let http_info = get_http_info(parts.headers, &mut parts.extensions);

    let tls_info = get_tls_display_info(&ctx);

    Ok(Json(json!({
        "number": params.number,
        "fp": {
            "user_agent_info": user_agent_info,
            "request_info": request_info,
            "tls_info": tls_info,
            "http_info": json!({
                "headers": http_info.headers,
                "pseudo_headers": http_info.pseudo_headers,
                "ja4h": ja4h,
            }),
        }
    })))
}

pub(super) async fn get_api_xml_http_request_number(
    mut ctx: Context<Arc<State>>,
    req: Request,
) -> Result<Json<serde_json::Value>, Response> {
    let ja4h = get_ja4h_info(&req);

    let (mut parts, _) = req.into_parts();

    let user_agent_info = get_user_agent_info(&ctx).await;

    let request_info = get_request_info(
        FetchMode::SameOrigin,
        ResourceType::Xhr,
        Initiator::Fetch,
        &mut ctx,
        &parts,
    )
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response())?;

    let http_info = get_http_info(parts.headers, &mut parts.extensions);

    let tls_info = get_tls_display_info(&ctx);

    Ok(Json(json!({
        "number": ctx.state().counter.fetch_add(1, std::sync::atomic::Ordering::AcqRel),
        "fp": {
            "user_agent_info": user_agent_info,
            "request_info": request_info,
            "tls_info": tls_info,
            "http_info": json!({
                "headers": http_info.headers,
                "pseudo_headers": http_info.pseudo_headers,
                "ja4h": ja4h,
            }),
        }
    })))
}

pub(super) async fn post_api_xml_http_request_number(
    Path(params): Path<APINumberParams>,
    mut ctx: Context<Arc<State>>,
    req: Request,
) -> Result<Json<serde_json::Value>, Response> {
    let ja4h = get_ja4h_info(&req);

    let (mut parts, _) = req.into_parts();

    let user_agent_info = get_user_agent_info(&ctx).await;

    let request_info = get_request_info(
        FetchMode::SameOrigin,
        ResourceType::Xhr,
        Initiator::Fetch,
        &mut ctx,
        &parts,
    )
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response())?;

    let http_info = get_http_info(parts.headers, &mut parts.extensions);

    let tls_info = get_tls_display_info(&ctx);

    Ok(Json(json!({
        "number": params.number,
        "fp": {
            "user_agent_info": user_agent_info,
            "request_info": request_info,
            "tls_info": tls_info,
            "http_info": json!({
                "headers": http_info.headers,
                "pseudo_headers": http_info.pseudo_headers,
                "ja4h": ja4h,
            }),
        }
    })))
}

//------------------------------------------
// endpoints: form
//------------------------------------------

pub(super) async fn form(mut ctx: Context<Arc<State>>, req: Request) -> Result<Html, Response> {
    let ja4h = get_ja4h_info(&req);

    let (mut parts, _) = req.into_parts();

    let user_agent_info = get_user_agent_info(&ctx).await;

    let request_info = get_request_info(
        FetchMode::SameOrigin,
        ResourceType::Form,
        Initiator::Form,
        &mut ctx,
        &parts,
    )
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response())?;

    let http_info = get_http_info(parts.headers, &mut parts.extensions);

    let mut content = String::new();

    content.push_str(r##"<a href="/report" title="Back to Home">🏠 Back to Home...</a>"##);

    if parts.method == "POST" {
        content.push_str(
            r##"<div id="input"><form method="GET" action="/form">
    <input type="hidden" name="source" value="web">
    <label for="turtles">Do you like turtles?</label>
    <select id="turtles" name="turtles">
        <option value="yes">Yes</option>
        <option value="no">No</option>
        <option value="maybe">Maybe</option>
    </select>
    <button type="submit">Submit</button>
</form></div>"##,
        );
    }

    let mut tables = vec![
        ctx.state().data_source.clone().into(),
        user_agent_info.into(),
        request_info.into(),
        Table {
            title: "🚗 Http Headers".to_owned(),
            rows: http_info.headers,
        },
    ];

    if let Some(ja4h) = ja4h {
        tables.push(Table {
            title: "🆔 Ja4H".to_owned(),
            rows: vec![
                ("HTTP Client Fingerprint".to_owned(), ja4h.hash),
                ("Raw (Debug) String".to_owned(), ja4h.human_str),
            ],
        })
    }

    if let Some(pseudo) = http_info.pseudo_headers {
        tables.push(Table {
            title: "🚗 H2 Pseudo Headers".to_owned(),
            rows: vec![("order".to_owned(), pseudo.join(", "))],
        });
    }

    let tls_info = get_tls_display_info(&ctx);
    if let Some(tls_info) = tls_info {
        let mut tls_tables = tls_info.into();
        tables.append(&mut tls_tables);
    }

    Ok(render_report(
        "🕵️ Fingerprint Report » Form",
        String::new(),
        content,
        tables,
    ))
}

//------------------------------------------
// endpoints: assets
//------------------------------------------

const STYLE_CSS: &str = include_str!("../../../assets/style.css");

pub(super) async fn get_assets_style() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/css")
        .body(STYLE_CSS.into())
        .expect("build css response")
}

const SCRIPT_JS: &str = include_str!("../../../assets/script.js");

pub(super) async fn get_assets_script() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/javascript")
        .body(SCRIPT_JS.into())
        .expect("build js response")
}

//------------------------------------------
// render utilities
//------------------------------------------

fn render_report(title: &'static str, head: String, mut html: String, tables: Vec<Table>) -> Html {
    html.push_str(r##"<div class="report">"##);
    for table in tables {
        html.push_str(&format!("<h2>{}</h2>", table.title));
        html.push_str("<table>");
        for (key, value) in table.rows {
            html.push_str(&format!(
                r##"<tr><td class="key">{}</td><td><code>{}</code></td></tr>"##,
                key, value
            ));
        }
        html.push_str("</table>");
    }
    html.push_str("</div>");
    render_page(title, head, html)
}

fn render_page(title: &'static str, head: String, content: String) -> Html {
    html(format!(
        r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">

            <title>ラマ | FP</title>

            <link rel="icon"
                href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%2210 0 100 100%22><text y=%22.90em%22 font-size=%2290%22>🦙</text></svg>">

            <meta name="description" content="rama proxy fingerprinting service">
            <meta name="robots" content="none">

            <link rel="canonical" href="https://ramaproxy.org/">

            <meta property="og:title" content="ramaproxy.org" />
            <meta property="og:locale" content="en_US" />
            <meta property="og:type" content="website">
            <meta property="og:description" content="rama proxy fingerprinting service" />
            <meta property="og:url" content="https://ramaproxy.org/" />
            <meta property="og:site_name" content="ramaproxy.org" />
            <meta property="og:image" content="https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_banner.jpeg">

            <meta http-equiv="Accept-CH" content="Width, Downlink, Sec-CH-UA, Sec-CH-UA-Mobile, Sec-CH-UA-Full-Version, ETC, Save-Data, Sec-CH-UA-Platform, Sec-CH-Prefers-Reduced-Motion, Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Model, Sec-CH-UA-Platform-Version, Sec-CH-UA-Prefers-Color-Scheme, Device-Memory, RTT, Sec-GPC" />

            <link rel="stylesheet" type="text/css" href="/assets/style.css">

            {}
        </head>
        <body>
            <main>
                <h1>
                    <a href="/" title="rama-fp home">ラマ</a>
                    &nbsp;
                    |
                    &nbsp;
                    {}
                </h1>
                <div id="content">{}</div>
                <div id="input" hidden></div>
                <div id="banner">
                    <a href="https://ramaproxy.org" title="rama proxy website">
                        <img src="https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_banner.jpeg" alt="rama banner" />
                    </a>
                </div>
            </main>
        </body>
        </html>
    "#,
        head, title, content
    ))
}

impl From<TlsDisplayInfo> for Vec<Table> {
    fn from(info: TlsDisplayInfo) -> Self {
        let mut vec = Vec::with_capacity(info.extensions.len() + 3);
        vec.push(Table {
            title: "🆔 Ja4".to_owned(),
            rows: vec![
                ("TLS Client Fingerprint".to_owned(), info.ja4.hash),
                ("Raw (Debug) String".to_owned(), info.ja4.full),
            ],
        });
        vec.push(Table {
            title: "🆔 Ja3".to_owned(),
            rows: vec![
                ("hash".to_owned(), info.ja3.hash),
                ("full".to_owned(), info.ja3.full),
            ],
        });
        vec.push(Table {
            title: "🔒 TLS Client Hello — Header".to_owned(),
            rows: vec![
                ("Version".to_owned(), info.protocol_version),
                ("Cipher Suites".to_owned(), info.cipher_suites.join(", ")),
                (
                    "Compression Algorithms".to_owned(),
                    info.compression_algorithms.join(", "),
                ),
            ],
        });
        for extension in info.extensions {
            let mut rows = vec![("ID".to_owned(), extension.id)];
            if let Some(data) = extension.data {
                rows.push((
                    "Data".to_owned(),
                    match data {
                        TlsDisplayInfoExtensionData::Single(s) => s,
                        TlsDisplayInfoExtensionData::Multi(v) => v.join(", "),
                    },
                ));
            }
            vec.push(Table {
                title: "🔒 TLS Client Hello — Extension".to_owned(),
                rows,
            });
        }
        vec
    }
}

impl From<UserAgentInfo> for Table {
    fn from(info: UserAgentInfo) -> Self {
        Self {
            title: "👤 User Agent Info".to_owned(),
            rows: vec![
                ("User Agent".to_owned(), info.user_agent),
                ("Kind".to_owned(), info.kind.unwrap_or_default()),
                (
                    "Version".to_owned(),
                    info.version.map(|v| v.to_string()).unwrap_or_default(),
                ),
                ("Platform".to_owned(), info.platform.unwrap_or_default()),
            ],
        }
    }
}

impl From<RequestInfo> for Table {
    fn from(info: RequestInfo) -> Self {
        Self {
            title: "ℹ️ Request Info".to_owned(),
            rows: vec![
                ("Version".to_owned(), info.version),
                ("Method".to_owned(), info.method),
                ("Scheme".to_owned(), info.scheme),
                ("Authority".to_owned(), info.authority),
                ("Path".to_owned(), info.path),
                ("Fetch Mode".to_owned(), info.fetch_mode.to_string()),
                ("Resource Type".to_owned(), info.resource_type.to_string()),
                ("Initiator".to_owned(), info.initiator.to_string()),
                (
                    "Socket Address".to_owned(),
                    info.peer_addr.unwrap_or_default(),
                ),
            ],
        }
    }
}

impl From<DataSource> for Table {
    fn from(data_source: DataSource) -> Self {
        Self {
            title: "📦 Data Source".to_owned(),
            rows: vec![
                ("Name".to_owned(), data_source.name),
                ("Version".to_owned(), data_source.version),
            ],
        }
    }
}

#[derive(Debug, Clone)]
struct Table {
    title: String,
    rows: Vec<(String, String)>,
}
