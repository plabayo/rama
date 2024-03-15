use super::data::{
    get_headers, get_request_info, DataSource, FetchMode, RequestInfo, ResourceType,
};
use rama::http::{Request, Response, StatusCode};

type Html = rama::http::response::Html<String>;

fn html<T: Into<String>>(inner: T) -> Html {
    inner.into().into()
}

pub async fn get_root(req: Request) -> Html {
    let data_source = DataSource::default();
    // TODO: get TLS Info (for https access only)
    // TODO: support HTTP1, HTTP2 and AUTO (for now we are only doing auto)
    let request_info = get_request_info(FetchMode::Navigate, ResourceType::Document, &req);
    let headers = get_headers(&req);

    render_report(
        "🕵️ Fingerprint Report",
        vec![
            data_source.into(),
            request_info.into(),
            Table {
                title: "🚗 Http Headers".to_owned(),
                rows: headers,
            },
        ],
    )
}

const STYLE_CSS: &str = include_str!("../assets/style.css");

pub async fn get_assets_style() -> Response {
    // TODO: do we need to also track this? As What?!

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/css")
        .body(STYLE_CSS.into())
        .expect("build css response")
}

fn render_report(title: &'static str, tables: Vec<Table>) -> Html {
    let mut html = String::from(r##"<div class="report">"##);
    for table in tables {
        html.push_str(&format!("<h2>{}</h2>", table.title));
        html.push_str("<table>");
        for (key, value) in table.rows {
            html.push_str(&format!(
                r##"<tr><td class="key">{}</td><td>{}</td></tr>"##,
                key, value
            ));
        }
        html.push_str("</table>");
    }
    html.push_str("</div>");
    render_page(title, html)
}

fn render_page(title: &'static str, content: String) -> Html {
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
            <meta property="og:image" content="https://raw.githubusercontent.com/plabayo/rama/main/docs/img/banner.svg">

            <link rel="stylesheet" type="text/css" href="/assets/style.css">
        </head>
        <body>
            <main>
                <h1>
                    <a href="https://ramaproxy.org" title="rama proxy website">ラマ</a>
                    &nbsp;
                    |
                    &nbsp;
                    {}
                </h1>
                <div>{}</div>
                <div id="banner">
                    <a href="https://ramaproxy.org" title="rama proxy website">
                        <img src="https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_banner.jpeg" alt="rama banner" />
                    </a>
                </div>
            </main>
        </body>
        </html>
    "#,
        title, content
    ))
}

impl From<RequestInfo> for Table {
    fn from(info: RequestInfo) -> Self {
        Self {
            title: "ℹ️ Request Info".to_owned(),
            rows: vec![
                ("User Agent".to_owned(), info.user_agent.unwrap_or_default()),
                ("Method".to_owned(), info.method),
                ("Fetch Mode".to_owned(), info.fetch_mode.to_string()),
                ("Resource Type".to_owned(), info.resource_type.to_string()),
                ("Path".to_owned(), info.path),
                ("Version".to_owned(), info.version),
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
