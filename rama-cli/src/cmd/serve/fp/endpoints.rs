use rama::{
    error::{BoxError, ErrorContext},
    extensions::ExtensionsRef,
    http::{
        BodyExtractExt, Request, Response, StatusCode, Version,
        headers::{ContentType, all_client_hints},
        proto::h2,
        protocols::html::*,
        service::web::{
            extract::{Path, State as StateParam},
            response::{self, ErrorResponse, IntoResponse, Json},
        },
        ws::{
            Utf8Bytes,
            handshake::server::ServerWebSocket,
            protocol::{CloseFrame, frame::coding::CloseCode},
        },
    },
    net::{address::ip::geo::IpGeoInfo, tls::SecureTransport},
    telemetry::tracing,
    ua::profile::{Http2Settings, JsProfileWebApis, UserAgentSourceInfo},
};

use itertools::Itertools as _;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{
    State, StorageAuthorized,
    data::TlsDisplayInfoExtensionData,
    data::{
        DataSource, FetchMode, Initiator, RequestInfo, ResourceType, TlsDisplayInfo, UserAgentInfo,
        get_akamai_h2_info, get_and_store_http_info, get_ja4h_info, get_request_info,
        get_tls_display_info_and_store, get_user_agent_info,
    },
};

//------------------------------------------
// endpoints: navigations
//------------------------------------------

pub(super) async fn get_consent() -> impl IntoResponse {
    (
        [("Set-Cookie", "rama-fp=ready; Max-Age=60; path=/")],
        page("🕵️ Fingerprint Consent", (), consent_body()),
    )
}

fn consent_body() -> impl IntoHtml {
    div!(
        class = "consent",
        div!(
            class = "controls",
            a!(class = "button", href = "/report", "Get Fingerprint Report"),
        ),
        div!(
            class = "section",
            p!(
                "This fingerprinting service is available using the following links:",
                ul!(
                    li!(
                        a!(
                            href = "http://fp.ramaproxy.org:80",
                            "http://fp.ramaproxy.org"
                        ),
                        ": auto HTTP, plain-text",
                    ),
                    li!(
                        a!(
                            href = "https://fp.ramaproxy.org:443",
                            "https://fp.ramaproxy.org"
                        ),
                        ": auto HTTP, TLS",
                    ),
                    li!(
                        a!(
                            href = "http://h1.fp.ramaproxy.org:80",
                            "http://h1.fp.ramaproxy.org"
                        ),
                        ": HTTP/1.1 and below only, plain-text",
                    ),
                    li!(
                        a!(
                            href = "https://h1.fp.ramaproxy.org:443",
                            "https://h1.fp.ramaproxy.org"
                        ),
                        ": HTTP/1.1 and below only, TLS",
                    ),
                ),
            ),
            p!(
                "You can also make use of the echo service for developers at:",
                ul!(
                    li!(
                        a!(
                            href = "http://echo.ramaproxy.org:80",
                            "http://echo.ramaproxy.org"
                        ),
                        ": echo service, plain-text (incl. WS support)",
                    ),
                    li!(
                        a!(
                            href = "https://echo.ramaproxy.org:443",
                            "https://echo.ramaproxy.org"
                        ),
                        ": echo service, TLS (incl. WSS support)",
                    ),
                ),
            ),
            p!(
                "Need to lookup your IP Address in html/txt/json:",
                ul!(
                    li!(
                        a!(
                            href = "https://ipv4.ramaproxy.org",
                            "https://ipv4.ramaproxy.org"
                        ),
                        ": return your pubic IPv4 address",
                    ),
                    li!(
                        a!(
                            href = "https://ipv6.ramaproxy.org",
                            "https://ipv6.ramaproxy.org"
                        ),
                        ": return your pubic IPv6 address",
                    ),
                ),
            ),
            p!(
                "We also have a small HTTP(S) test service:",
                ul!(
                    li!(
                        a!(
                            href = "http://http-test.ramaproxy.org:80",
                            "http://http-test.ramaproxy.org"
                        ),
                        ": http test service, plain-text",
                    ),
                    li!(
                        a!(
                            href = "https://http-test.ramaproxy.org:443",
                            "https://http-test.ramaproxy.org"
                        ),
                        ": https test service, TLS",
                    ),
                ),
            ),
            p!(
                "You can learn move about rama at in ",
                a!(href = "https://ramaproxy.org/book", "the rama book"),
                ". And the source code for this service is available at ",
                a!(
                    href = "https://github.com/plabayo/rama",
                    "https://github.com/plabayo/rama"
                ),
                ".",
            ),
        ),
        div!(
            class = "small",
            p!(
                "By clicking on the button above, you agree that we will store \
                 fingerprint information about your network traffic. We are only \
                 interested in the HTTP and TLS traffic sent by you. This information \
                 will be stored in a database for later processing."
            ),
            p!(
                "Please note that we do not store IP information and we do not use \
                 third-party tracking cookies. However, it is possible that the \
                 telecom or hosting services used by you or us may track some \
                 personalized information, over which we have no control or desire. \
                 You can use utilities like the Unix `dig` command to analyze the \
                 traffic and determine what might be tracked."
            ),
            p!(
                "Hosting for this service is sponsored by ",
                a!(href = "https://fly.io", "fly.io"),
                "."
            ),
        ),
    )
}

pub(super) async fn get_report(
    StateParam(state): StateParam<State>,
    req: Request,
) -> Result<Response, ErrorResponse> {
    let ja4h = get_ja4h_info(&req);

    // resolve from `&req` before `into_parts`: layer-inserted extensions like
    // `Forwarded` (used for geo) live on the request, not the http `Parts`.
    let mut request_info = get_request_info(
        FetchMode::Navigate,
        ResourceType::Document,
        Initiator::Navigator,
        &req,
        state.geo_db.as_deref(),
    )
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response())?;
    // taken out so the merged + per-source geo render as their own tables
    let geo = request_info.geo.take();

    let (parts, _) = req.into_parts();

    let user_agent_info = get_user_agent_info(&parts.extensions).await;

    let user_agent = user_agent_info.user_agent.clone();

    let http_info = get_and_store_http_info(
        &state,
        parts.headers,
        &parts.extensions,
        parts.version,
        user_agent.clone(),
        Initiator::Navigator,
    )
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response())?;

    let mut tables = vec![
        state.data_source.clone().into(),
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

    if parts.version == Version::HTTP_2
        && let Some(akamai_h2) = get_akamai_h2_info(&parts.extensions)
    {
        tables.push(Table {
            title: "🆔 Akamai h2".to_owned(),
            rows: vec![
                ("Akamai h2 Client Fingerprint".to_owned(), akamai_h2.hash),
                ("Raw (Debug) String".to_owned(), akamai_h2.human_str),
            ],
        })
    }

    if let Some(h2_settings) = http_info.h2_settings {
        extend_tables_with_h2_settings(h2_settings, &mut tables);
    }

    let tls_info = get_tls_display_info_and_store(&state, &parts.extensions, user_agent)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response())?;

    if let Some(tls_info) = tls_info {
        let mut tls_tables = tls_info.into();
        tables.append(&mut tls_tables);
    }

    if let Some(geo) = &geo {
        tables.extend(geo_tables(geo));
    }
    let geo_comment = rama::cli::service::geo::geo_attribution_html_comment(
        &state
            .geo_db
            .as_ref()
            .map(|db| db.attributions().collect::<Vec<_>>())
            .unwrap_or_default(),
    )
    .map(PreEscaped);

    Ok(page(
        "🕵️ Fingerprint Report",
        script!(src = "/assets/script.js"),
        (geo_comment, report_body(None::<&str>, tables)),
    )
    .into_response())
}

fn extend_tables_with_h2_settings(h2_settings: Http2Settings, tables: &mut Vec<Table>) {
    if let Some(pseudo) = h2_settings.http_pseudo_headers {
        tables.push(Table {
            title: "🚗 H2 Pseudo Headers".to_owned(),
            rows: vec![("order".to_owned(), pseudo.iter().join(", "))],
        });
    }
    if let Some(early_frames) = &h2_settings.early_frames {
        for (index, early_frame) in early_frames.iter().enumerate() {
            tables.push(match early_frame {
                h2::frame::EarlyFrame::Priority(priority) => Table {
                    title: format!("🚗 H2 Early Frame #{} - priority", index + 1),
                    rows: vec![
                        (
                            "stream id".to_owned(),
                            u32::from(priority.stream_id).to_string(),
                        ),
                        (
                            "dependency id".to_owned(),
                            u32::from(priority.dependency.dependency_id).to_string(),
                        ),
                        (
                            "weight".to_owned(),
                            u32::from(priority.dependency.weight).to_string(),
                        ),
                        (
                            "is exclusive".to_owned(),
                            priority.dependency.is_exclusive.to_string(),
                        ),
                    ],
                },
                h2::frame::EarlyFrame::Settings(settings) => Table {
                    title: format!("🚗 H2 Early Frame #{} - settings", index + 1),
                    rows: {
                        let mut rows = Vec::with_capacity(9);
                        rows.push(("Flags".to_owned(), format!("{:?}", settings.flags)));
                        let order = settings.config.setting_order.clone().unwrap_or_default();
                        for setting_id in order {
                            match setting_id {
                                h2::frame::SettingId::HeaderTableSize => {
                                    if let Some(value) = settings.config.header_table_size {
                                        rows.push((
                                            "Header Table Size".to_owned(),
                                            value.to_string(),
                                        ));
                                    }
                                }
                                h2::frame::SettingId::EnablePush => {
                                    if let Some(value) = settings.config.enable_push.map(|v| v != 0)
                                    {
                                        rows.push(("Enable Push".to_owned(), value.to_string()));
                                    }
                                }
                                h2::frame::SettingId::MaxConcurrentStreams => {
                                    if let Some(value) = settings.config.max_concurrent_streams {
                                        rows.push((
                                            "Max Concurrent Streams".to_owned(),
                                            value.to_string(),
                                        ));
                                    }
                                }
                                h2::frame::SettingId::InitialWindowSize => {
                                    if let Some(value) = settings.config.initial_window_size {
                                        rows.push((
                                            "Initial Window Size".to_owned(),
                                            value.to_string(),
                                        ));
                                    }
                                }
                                h2::frame::SettingId::MaxFrameSize => {
                                    if let Some(value) = settings.config.max_frame_size {
                                        rows.push(("Max Frame Size".to_owned(), value.to_string()));
                                    }
                                }
                                h2::frame::SettingId::MaxHeaderListSize => {
                                    if let Some(value) = settings.config.max_header_list_size {
                                        rows.push((
                                            "Max Header List Size".to_owned(),
                                            value.to_string(),
                                        ));
                                    }
                                }
                                h2::frame::SettingId::EnableConnectProtocol => {
                                    if let Some(value) =
                                        settings.config.enable_connect_protocol.map(|v| v != 0)
                                    {
                                        rows.push((
                                            "Enable Connect Protocol".to_owned(),
                                            value.to_string(),
                                        ));
                                    }
                                }
                                h2::frame::SettingId::NoRfc7540Priorities => {
                                    if let Some(value) = settings.config.no_rfc7540_priorities {
                                        rows.push((
                                            "No RFC 7540 Priorities".to_owned(),
                                            value.to_string(),
                                        ));
                                    }
                                }
                                h2::frame::SettingId::Unknown(id) => {
                                    tracing::debug!(
                                        h2.settings.id = %id,
                                        "ignore unknown h2 setting",
                                    )
                                }
                            }
                        }

                        rows
                    },
                },
                h2::frame::EarlyFrame::WindowUpdate(window_update) => Table {
                    title: format!("🚗 H2 Early Frame #{} - windows update", index + 1),
                    rows: vec![
                        (
                            "stream id".to_owned(),
                            u32::from(window_update.stream_id).to_string(),
                        ),
                        (
                            "size increment".to_owned(),
                            window_update.size_increment.to_string(),
                        ),
                    ],
                },
            });
        }
    }
}

//------------------------------------------
// endpoints: XHR
//------------------------------------------

#[derive(Serialize, Deserialize)]
pub(super) struct APINumberParams {
    number: usize,
}

#[derive(Serialize, Deserialize)]
pub(super) struct APINumberRequest {
    number: usize,
    #[serde(alias = "sourceInfo")]
    source_info: Option<UserAgentSourceInfo>,
    #[serde(alias = "jsWebApis")]
    js_web_apis: Option<JsProfileWebApis>,
}

pub(super) async fn post_api_fetch_number(
    StateParam(state): StateParam<State>,
    Path(params): Path<APINumberParams>,
    req: Request,
) -> Result<Json<serde_json::Value>, ErrorResponse> {
    let ja4h = get_ja4h_info(&req);

    let request_info = get_request_info(
        FetchMode::SameOrigin,
        ResourceType::Xhr,
        Initiator::Fetch,
        &req,
        state.geo_db.as_deref(),
    )
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response())?;

    let (parts, body) = req.into_parts();

    let user_agent_info = get_user_agent_info(parts.extensions()).await;

    let user_agent = user_agent_info.user_agent.clone();

    let http_info = get_and_store_http_info(
        &state,
        parts.headers,
        &parts.extensions,
        parts.version,
        user_agent.clone(),
        Initiator::Fetch,
    )
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response())?;

    let request: APINumberRequest = body
        .try_into_json()
        .await
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()).into_response())?;

    if let Some(storage) = state.storage.as_ref() {
        let auth = parts.extensions.contains::<StorageAuthorized>();
        if let Some(js_web_apis) = request.js_web_apis.clone() {
            storage
                .store_js_web_apis(user_agent.clone(), auth, js_web_apis)
                .await
                .map_err(|err| {
                    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
                })?;
        }

        if let Some(source_info) = request.source_info.clone() {
            storage
                .store_source_info(user_agent.clone(), auth, source_info)
                .await
                .map_err(|err| {
                    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
                })?;
        }
    }

    let tls_info = get_tls_display_info_and_store(&state, &parts.extensions, user_agent)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response())?;

    Ok(Json(json!({
        "number": params.number,
        "body_number": request.number,
        "fp": {
            "user_agent_info": user_agent_info,
            "request_info": request_info,
            "tls_info": tls_info,
            "http_info": json!({
                "headers": http_info.headers,
                "h2": http_info.h2_settings,
                "ja4h": ja4h,
            }),
            "js_web_apis": request.js_web_apis,
            "source_info": request.source_info,
        }
    })))
}

pub(super) async fn post_api_xml_http_request_number(
    StateParam(state): StateParam<State>,
    Path(params): Path<APINumberParams>,
    req: Request,
) -> Result<Json<serde_json::Value>, ErrorResponse> {
    let ja4h = get_ja4h_info(&req);

    let request_info = get_request_info(
        FetchMode::SameOrigin,
        ResourceType::Xhr,
        Initiator::Fetch,
        &req,
        state.geo_db.as_deref(),
    )
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response())?;

    let (parts, _) = req.into_parts();

    let user_agent_info = get_user_agent_info(&parts.extensions).await;

    let user_agent = user_agent_info.user_agent.clone();

    let http_info = get_and_store_http_info(
        &state,
        parts.headers,
        &parts.extensions,
        parts.version,
        user_agent.clone(),
        Initiator::XMLHttpRequest,
    )
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response())?;

    let tls_info = get_tls_display_info_and_store(&state, &parts.extensions, user_agent)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response())?;

    Ok(Json(json!({
        "number": params.number,
        "fp": {
            "user_agent_info": user_agent_info,
            "request_info": request_info,
            "tls_info": tls_info,
            "http_info": json!({
                "headers": http_info.headers,
                "h2": http_info.h2_settings,
                "ja4h": ja4h,
            }),
        }
    })))
}

//------------------------------------------
// endpoints: form
//------------------------------------------

pub(super) async fn form(
    StateParam(state): StateParam<State>,
    req: Request,
) -> Result<Response, ErrorResponse> {
    let ja4h = get_ja4h_info(&req);

    let mut request_info = get_request_info(
        FetchMode::SameOrigin,
        ResourceType::Form,
        Initiator::Form,
        &req,
        state.geo_db.as_deref(),
    )
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response())?;
    // taken out so the merged + per-source geo render as their own tables
    let geo = request_info.geo.take();

    let (parts, _) = req.into_parts();

    let user_agent_info = get_user_agent_info(&parts.extensions).await;

    let user_agent = user_agent_info.user_agent.clone();

    let http_info = get_and_store_http_info(
        &state,
        parts.headers,
        &parts.extensions,
        parts.version,
        user_agent.clone(),
        Initiator::Form,
    )
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response())?;

    let mut tables = vec![
        state.data_source.clone().into(),
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

    if parts.version == Version::HTTP_2
        && let Some(akamai_h2) = get_akamai_h2_info(&parts.extensions)
    {
        tables.push(Table {
            title: "🆔 Akamai h2".to_owned(),
            rows: vec![
                ("Akamai h2 Client Fingerprint".to_owned(), akamai_h2.hash),
                ("Raw (Debug) String".to_owned(), akamai_h2.human_str),
            ],
        })
    }

    if let Some(h2_settings) = http_info.h2_settings {
        extend_tables_with_h2_settings(h2_settings, &mut tables);
    }

    let tls_info = get_tls_display_info_and_store(&state, &parts.extensions, user_agent)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response())?;

    if let Some(tls_info) = tls_info {
        let mut tls_tables = tls_info.into();
        tables.append(&mut tls_tables);
    }

    if let Some(geo) = &geo {
        tables.extend(geo_tables(geo));
    }
    let geo_comment = rama::cli::service::geo::geo_attribution_html_comment(
        &state
            .geo_db
            .as_ref()
            .map(|db| db.attributions().collect::<Vec<_>>())
            .unwrap_or_default(),
    )
    .map(PreEscaped);

    let show_form = parts.method == "POST";

    Ok(page(
        "🕵️ Fingerprint Report » Form",
        (),
        (geo_comment, report_body(Some(form_top(show_form)), tables)),
    )
    .into_response())
}

fn form_top(show_form: bool) -> impl IntoHtml {
    (
        a!(
            href = "/report",
            title = "Back to Home",
            "🏠 Back to Home..."
        ),
        if show_form {
            Some(div!(
                id = "input",
                form!(
                    method = "GET",
                    action = "/form",
                    input!(r#type = "hidden", name = "source", value = "web"),
                    label!(r#for = "turtles", "Do you like turtles?"),
                    select!(
                        id = "turtles",
                        name = "turtles",
                        option!(value = "yes", "Yes"),
                        option!(value = "no", "No"),
                        option!(value = "maybe", "Maybe"),
                    ),
                    button!(r#type = "submit", "Submit"),
                ),
            ))
        } else {
            None
        },
    )
}

//------------------------------------------
// endpoints: WS(S)
//------------------------------------------

pub(super) async fn ws_api(state: State, ws: ServerWebSocket) -> Result<(), BoxError> {
    tracing::debug!("ws api called");
    let (mut ws, parts) = ws.into_parts();

    let user_agent_info = get_user_agent_info(&parts.extensions).await;

    let user_agent = user_agent_info.user_agent.clone();

    _ = get_and_store_http_info(
        &state,
        parts.headers,
        &parts.extensions,
        parts.version,
        user_agent.clone(),
        Initiator::Ws,
    )
    .await?;
    tracing::debug!("ws api: http info stored");

    if let Some(hello) = parts
        .extensions
        .get_ref::<SecureTransport>()
        .and_then(|st| st.client_hello())
        && let Some(storage) = state.storage.as_ref()
    {
        let auth = parts.extensions.contains::<StorageAuthorized>();
        storage
            .store_tls_ws_client_overwrites_from_client_hello(user_agent, auth, hello.clone())
            .await
            .context("store tls client hello as ws client overwrites")?;
        tracing::debug!("ws api: tls overwrite info stored");
    }

    ws.send_message("hello".into())
        .await
        .context("send hello msg")?;

    tracing::debug!("ws api: hello sent");

    ws.close(Some(CloseFrame {
        code: CloseCode::Normal,
        reason: Utf8Bytes::from_static("finished"),
    }))
    .await
    .context("close ws frame")?;

    let result = ws.recv_message().await;
    tracing::debug!("ws api: socket closed with result: {result:?}");

    Ok(())
}

//------------------------------------------
// endpoints: assets
//------------------------------------------

const STYLE_CSS: &str = include_str!("../../../../assets/style.css");

pub(super) async fn get_assets_style() -> impl IntoResponse {
    (
        response::Headers::single(ContentType::css_utf8()),
        STYLE_CSS,
    )
}

const SCRIPT_JS: &str = include_str!("../../../../assets/script.js");

pub(super) async fn get_assets_script() -> impl IntoResponse {
    (
        response::Headers::single(ContentType::javascript_utf8()),
        SCRIPT_JS,
    )
}

//------------------------------------------
// render utilities
//------------------------------------------

/// Inline SVG llama, served as a `data:` URL for the page favicon.
const FAVICON_DATA_URL: PreEscaped<&str> = PreEscaped(
    "data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%2210 0 100 100%22>\
     <text y=%22.90em%22 font-size=%2290%22>🦙</text></svg>",
);

/// Render the standard page chrome (head + body shell) with the given
/// per-page h1 title, optional extra `<head>` content, and body content.
///
/// All `IntoHtml` inputs are escaped automatically by virtue of the
/// `html!`-macro family. Static literals come through `PreEscaped`.
fn page<H, B>(
    h1_title: &'static str,
    extra_head: H,
    body_content: B,
) -> impl IntoHtml + IntoResponse
where
    H: IntoHtml,
    B: IntoHtml,
{
    html!(
        lang = "en",
        head!(
            meta!(charset = "UTF-8"),
            meta!(
                name = "viewport",
                content = "width=device-width, initial-scale=1.0"
            ),
            title!("ラマ | FP"),
            link!(rel = "icon", href = FAVICON_DATA_URL),
            meta!(
                name = "description",
                content = "rama proxy fingerprinting service"
            ),
            meta!(name = "robots", content = "none"),
            link!(rel = "canonical", href = "https://ramaproxy.org/"),
            meta!(property = "og:title", content = "ramaproxy.org"),
            meta!(property = "og:locale", content = "en_US"),
            meta!(property = "og:type", content = "website"),
            meta!(
                property = "og:description",
                content = "rama proxy fingerprinting service"
            ),
            meta!(property = "og:url", content = "https://ramaproxy.org/"),
            meta!(property = "og:site_name", content = "ramaproxy.org"),
            meta!(
                property = "og:image",
                content =
                    "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_banner.jpeg"
            ),
            meta!(
                "http-equiv" = "Accept-CH",
                // advertise every spelling each hint answers to (Sec-CH-* + any
                // legacy bare alias), matching the `Accept-CH` response header
                content = join_display(
                    all_client_hints().flat_map(|h| h.header_name_strs().iter().copied()),
                    ", ",
                )
            ),
            link!(
                rel = "stylesheet",
                r#type = "text/css",
                href = "/assets/style.css"
            ),
            extra_head,
        ),
        body!(main!(
            h1!(
                a!(href = "/", title = "rama-fp home", "ラマ"),
                PreEscaped(" &nbsp; | &nbsp; "),
                h1_title,
            ),
            div!(id = "content", body_content),
            // `#input` is populated dynamically by `script.js`; we keep it
            // present-but-hidden so the JS' `getElementById("input")` lookup
            // works on every page.
            div!(id = "input", hidden? = true),
            div!(
                id = "banner",
                a!(
                    href = "https://ramaproxy.org",
                    title = "rama proxy website",
                    img!(
                        src = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_banner.jpeg",
                        alt = "rama banner",
                    ),
                ),
            ),
        )),
    )
}

/// Wraps optional top-of-content (e.g. the form's back-link + submit form)
/// and the rendered fingerprint tables inside the standard `report`
/// container.
fn report_body<T>(top: Option<T>, tables: Vec<Table>) -> impl IntoHtml
where
    T: IntoHtml,
{
    (top, div!(class = "report", render_tables(tables)))
}

/// Render a list of [`Table`]s as a flat sequence of `<h2>` + `<table>`
/// pairs. All user-supplied table titles, keys, and values are emitted
/// through the `html!`-macro escape pipeline.
fn render_tables(tables: Vec<Table>) -> impl IntoHtml {
    tables
        .into_iter()
        .map(|t| {
            let rows = t
                .rows
                .into_iter()
                .map(|(key, value)| tr!(td!(class = "key", key), td!(code!(value)),));
            (h2!(t.title), table!(rows.collect::<Vec<_>>()))
        })
        .collect::<Vec<_>>()
}

impl From<TlsDisplayInfo> for Vec<Table> {
    fn from(info: TlsDisplayInfo) -> Self {
        let mut vec = Self::with_capacity(info.extensions.len() + 3);
        vec.push(Table {
            title: "🆔 Ja4".to_owned(),
            rows: vec![
                ("TLS Client Fingerprint".to_owned(), info.ja4.hash),
                ("Raw (Debug) String".to_owned(), info.ja4.full),
            ],
        });
        vec.push(Table {
            title: "🆔 Peetprint".to_owned(),
            rows: vec![
                ("hash".to_owned(), info.peet.hash),
                ("full".to_owned(), info.peet.full),
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

/// Build the geolocation report tables: a merged table plus one per source,
/// side-by-side. Attribution is carried in the `x-geo-attribution` header.
fn geo_tables(info: &IpGeoInfo) -> Vec<Table> {
    let rows = |loc: &rama::net::address::ip::geo::GeoLocation| {
        rama::cli::service::geo::geo_location_rows(loc)
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect::<Vec<_>>()
    };
    let mut tables = vec![Table {
        title: format!("🌍 Geolocation ({})", info.ip),
        rows: rows(&info.location),
    }];
    for source in &info.by_source {
        tables.push(Table {
            title: format!("🌍 {} (source)", source.label),
            rows: rows(&source.location),
        });
    }
    tables
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Header values, table titles, and table row keys/values all flow into
    /// HTML via the `html!`-macro pipeline, which escapes `<`, `>`, `&`,
    /// `"`, and `'`. Verifies an attacker controlling any of these cannot
    /// break out of the surrounding text node into executable JS.
    #[test]
    fn render_tables_escapes_text_content_xss_payloads() {
        let tables = vec![Table {
            title: "<script>alert('title')</script>".to_owned(),
            rows: vec![
                (
                    "<img src=x onerror=alert(1)>".to_owned(),
                    "value & co".to_owned(),
                ),
                (
                    "key with \"quote\"".to_owned(),
                    "</code><script>alert('val')</script>".to_owned(),
                ),
            ],
        }];

        let out = render_tables(tables).into_string();

        // No live tags should appear from user input.
        assert!(!out.contains("<script>"));
        assert!(!out.contains("<img"));
        // The escaped forms must be present.
        assert!(out.contains("&lt;script&gt;"));
        assert!(out.contains("&lt;img"));
        assert!(out.contains("&amp;"));
        assert!(out.contains("&quot;"));
    }

    /// The fingerprint page wraps tables inside a `<div class="report">` and
    /// is served from the `/report` endpoint via `page(...)`. This check
    /// pins the surrounding structure so a regression in either the chrome
    /// or the table rendering surfaces immediately.
    #[test]
    fn report_body_wraps_tables_in_report_div() {
        let tables = vec![Table {
            title: "T".to_owned(),
            rows: vec![("k".to_owned(), "v".to_owned())],
        }];
        let out = report_body(None::<&str>, tables).into_string();
        assert!(out.contains(r#"<div class="report">"#));
        assert!(out.contains("<h2>T</h2>"));
        assert!(out.contains(r#"<tr><td class="key">k</td><td><code>v</code></td></tr>"#));
    }

    /// Unicode (the 🦙 emoji and friends) must pass through the escape
    /// pipeline unchanged — only `<>&"'` are rewritten.
    #[test]
    fn render_tables_unicode_passes_through() {
        let tables = vec![Table {
            title: "🦙".to_owned(),
            rows: vec![("世界".to_owned(), "🕵️".to_owned())],
        }];
        let out = render_tables(tables).into_string();
        assert!(out.contains("🦙"));
        assert!(out.contains("世界"));
        assert!(out.contains("🕵️"));
    }

    /// Sanity check that `page(...)` produces a valid HTML5 document with
    /// the per-page h1 title and that the body content slot receives the
    /// supplied content.
    #[test]
    fn page_emits_doctype_and_renders_h1_title() {
        let out = page("My Title", (), p!("body")).into_string();
        assert!(out.starts_with("<!DOCTYPE html><html lang=\"en\">"));
        assert!(out.contains("<title>ラマ | FP</title>"));
        assert!(out.contains("My Title"));
        assert!(out.contains(r#"<div id="content"><p>body</p></div>"#));
        assert!(out.contains(r#"<div id="input" hidden></div>"#));
    }

    /// h1 titles are static (compile-time `&'static str`) and so cannot be
    /// attacker-supplied — but verify any future change that funnels
    /// untrusted titles into `page(...)` would still be escaped.
    #[test]
    fn page_escapes_dynamic_title_slot() {
        let evil = "<script>alert(1)</script>";
        // page takes `&'static str` so we leak — only for the test.
        let leaked: &'static str = Box::leak(evil.to_owned().into_boxed_str());
        let out = page(leaked, (), ()).into_string();
        assert!(!out.contains("<script>alert(1)</script>"));
        assert!(out.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    /// The form-top fragment toggles a visible submission form when the
    /// caller signals a POST request. Verify both rendered shapes.
    #[test]
    fn form_top_includes_form_when_post() {
        let out = form_top(true).into_string();
        assert!(out.contains(r#"<a href="/report""#));
        assert!(out.contains(r#"<form method="GET" action="/form">"#));
        assert!(out.contains(r#"<select id="turtles" name="turtles">"#));

        let out_get = form_top(false).into_string();
        assert!(out_get.contains(r#"<a href="/report""#));
        assert!(!out_get.contains("<form"));
        assert!(!out_get.contains("<select"));
    }
}
