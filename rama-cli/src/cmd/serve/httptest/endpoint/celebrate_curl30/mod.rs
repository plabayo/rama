//! A community tribute to 30 years of curl, served as text, HTML or JSON.

use std::convert::Infallible;

use rama::{
    Service,
    bytes::Bytes,
    futures::stream,
    http::{
        Body, HeaderValue, Method, Request, Response,
        header::{CACHE_CONTROL, CONTENT_TYPE, VARY},
        headers::{Accept, ContentSecurityPolicy, HeaderMapExt as _, SourceList},
        mime,
        protocols::html::*,
    },
    service::service_fn,
};

const HOMEPAGE: &str = "https://curl.se";
const HOMEPAGE_HOST: &str = "curl.se";
const ANNIVERSARY: &str =
    "https://daniel.haxx.se/blog/2026/11/11/30-years-of-internet-transfers-with-curl/";
const ANNIVERSARY_HOST: &str = "daniel.haxx.se";

const EVENT: &str = "30 years of curl";
const ANNIVERSARY_DATE: &str = "2026-11-11";
const TITLE: &str = "curl turns 30!";
const YEARS: &str = "1996 — 2026";
const SUMMARY: [&str; 3] = [
    "From a little over 100 lines of C to an estimated",
    "30 billion installations. From a tiny HTTP download",
    "tool to lending a hand in a Mars landing.",
];
const MOTTO: &str = "30 years. One command. Endless connections.";
const THANKS: &str = "Thank you Daniel, Rafael and all contributors ♥";

const ORIGIN_NAME: &str = "httpget";
const ORIGIN_VERSION: &str = "0.1";
const ORIGIN_YEAR: &str = "1996";
const ORIGIN_AUTHOR: &str = "Rafael Sagula";
const ORIGIN_LINES_OF_CODE: &str = "a little over 100";

const INSTALLATIONS: &str = "30000000000";
const INSTALLATIONS_SHORT: &str = "30 billion";
const INSTALLATIONS_NOTE: &str = "a rough estimate by Daniel Stenberg";
const USERS_1996: &str = "36000000";
const USERS_1996_SHORT: &str = "36 million";
const USERS_2026: &str = "6–7 billion";

struct Milestone {
    year: &'static str,
    date: &'static str,
    event: &'static str,
    note: &'static str,
}

const MILESTONES: [Milestone; 4] = [
    Milestone {
        year: "1996",
        date: "1996-11-11",
        event: "httpget 0.1",
        note: "A tiny HTTP download tool is born",
    },
    Milestone {
        year: "1998",
        date: "1998-03-20",
        event: "curl 4.0",
        note: "A new name and three protocols",
    },
    Milestone {
        year: "2000",
        date: "2000-08",
        event: "libcurl",
        note: "The library the world builds on",
    },
    Milestone {
        year: "2026",
        date: "2026-11-11",
        event: "30 years",
        note: "Still connecting",
    },
];

/// The URL schemes listed on the curl homepage.
const PROTOCOLS: [&str; 25] = [
    "DICT", "FILE", "FTP", "FTPS", "GOPHER", "GOPHERS", "HTTP", "HTTPS", "IMAP", "IMAPS", "LDAP",
    "LDAPS", "MQTT", "MQTTS", "POP3", "POP3S", "RTSP", "SCP", "SFTP", "SMTP", "SMTPS", "TELNET",
    "TFTP", "WS", "WSS",
];
const SCHEME_COUNT: &str = "25";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Text,
    Html,
    Json,
}

impl Format {
    /// In server preference order, which settles equally acceptable formats.
    const ALL: [Self; 3] = [Self::Text, Self::Html, Self::Json];

    fn media_type(self) -> (mime::Name<'static>, mime::Name<'static>) {
        match self {
            Self::Text => (mime::TEXT, mime::PLAIN),
            Self::Html => (mime::TEXT, mime::HTML),
            Self::Json => (mime::APPLICATION, mime::JSON),
        }
    }

    fn content_type(self) -> HeaderValue {
        HeaderValue::from_static(match self {
            Self::Text => "text/plain; charset=utf-8",
            Self::Html => "text/html; charset=utf-8",
            Self::Json => "application/json; charset=utf-8",
        })
    }

    fn body(self) -> Body {
        match self {
            Self::Text => streamed(text_pieces()),
            Self::Json => streamed(json_pieces()),
            Self::Html => render_html().into(),
        }
    }
}

/// Streams the static pieces as they are, without copying them into a buffer.
fn streamed(pieces: impl Iterator<Item = &'static str> + Send + 'static) -> Body {
    Body::from_stream(stream::iter(
        pieces
            .filter(|piece| !piece.is_empty())
            .map(|piece| Ok::<_, Infallible>(Bytes::from_static(piece.as_bytes()))),
    ))
}

/// Plain text unless the client prefers one of the other formats.
fn negotiate(accept: Option<&Accept>) -> Format {
    let Some(Accept(ranges)) = accept else {
        return Format::Text;
    };
    let mut best = (Format::Text, 0);
    for format in Format::ALL {
        let (ty, subtype) = format.media_type();
        // The most specific matching media range decides the quality.
        let quality = ranges
            .iter()
            .filter_map(|range| {
                let mime = &range.value;
                let specificity = if mime.type_() == ty && mime.subtype() == subtype {
                    2
                } else if mime.type_() == ty && mime.subtype() == mime::STAR {
                    1
                } else if mime.type_() == mime::STAR {
                    0
                } else {
                    return None;
                };
                Some((specificity, range.quality.as_u16()))
            })
            .max()
            .map_or(0, |(_, quality)| quality);
        if quality > best.1 {
            best = (format, quality);
        }
    }
    best.0
}

pub(in crate::cmd::serve::httptest) fn service()
-> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    service_fn(async |req: Request| {
        let format = negotiate(req.headers().typed_get::<Accept>().as_ref());
        Ok::<_, Infallible>(respond(req.method(), format))
    })
}

fn respond(method: &Method, format: Format) -> Response {
    let mut response = Response::new(if method == Method::HEAD {
        Body::empty()
    } else {
        format.body()
    });
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, format.content_type());
    headers.insert(VARY, HeaderValue::from_static("accept"));
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    if format == Format::Html {
        // The page is self-contained, so only its inline stylesheet is allowed.
        headers.typed_insert(
            ContentSecurityPolicy::empty()
                .with_default_src(SourceList::none())
                .with_style_src(SourceList::empty().with_unsafe_inline())
                .with_form_action(SourceList::none())
                .with_base_uri(SourceList::none())
                .with_frame_ancestors(SourceList::none()),
        );
    }
    response
}

/// Columns of the text celebration, excluding the two column indent.
const TEXT_WIDTH: usize = 53;
const TEXT_COLUMNS: usize = 5;
const BOX_TOP: &str = "  ╭───────────────────────────────────────────────────╮\n";
const BOX_EMPTY: &str = "  │                                                   │\n";
const BOX_BOTTOM: &str = "  ╰───────────────────────────────────────────────────╯\n";
const RULE: &str = "  ─────────────────────────────────────────────────────\n";
const ACES: &str = "                                                   ";

fn pad(columns: usize) -> &'static str {
    &ACES[..columns]
}

fn centered(text: &'static str) -> [&'static str; 5] {
    let space = TEXT_WIDTH - 2 - text.chars().count();
    ["  │", pad(space / 2), text, pad(space - space / 2), "│\n"]
}

fn text_pieces() -> impl Iterator<Item = &'static str> + Send + 'static {
    [BOX_TOP, BOX_EMPTY]
        .into_iter()
        .chain(centered(TITLE))
        .chain(centered(YEARS))
        .chain([BOX_EMPTY, BOX_BOTTOM, "\n"])
        .chain(SUMMARY.into_iter().flat_map(|line| ["  ", line, "\n"]))
        .chain(["\n"])
        .chain(MILESTONES.iter().flat_map(|milestone| {
            [
                "  ",
                milestone.year,
                "  ",
                milestone.event,
                pad(13 - milestone.event.len()),
                milestone.note,
                "\n",
            ]
        }))
        .chain([
            "\n",
            RULE,
            "  ",
            SCHEME_COUNT,
            " URL schemes on ",
            HOMEPAGE_HOST,
            ". Countless connections.\n",
            RULE,
            "\n",
        ])
        .chain(PROTOCOLS.into_iter().enumerate().flat_map(|(index, name)| {
            let row_ends = index % TEXT_COLUMNS == TEXT_COLUMNS - 1 || index + 1 == PROTOCOLS.len();
            [
                "  ",
                name,
                pad(7 - name.len()),
                " ✓",
                if row_ends { "\n" } else { "" },
            ]
        }))
        .chain([
            "\n",
            RULE,
            "\n  1996  ",
            USERS_1996_SHORT,
            " people online\n  2026  ",
            USERS_2026,
            " people online\n\n  ",
            MOTTO,
            "\n\n  ",
            THANKS,
            "\n\n  ",
            HOMEPAGE_HOST,
            "  |  ",
            ANNIVERSARY_HOST,
            "\n",
        ])
}

fn json_pieces() -> impl Iterator<Item = &'static str> + Send + 'static {
    [
        "{\n  \"event\": \"",
        EVENT,
        "\",\n  \"anniversary_date\": \"",
        ANNIVERSARY_DATE,
        "\",\n  \"origin\": {\n    \"name\": \"",
        ORIGIN_NAME,
        "\",\n    \"version\": \"",
        ORIGIN_VERSION,
        "\",\n    \"year\": ",
        ORIGIN_YEAR,
        ",\n    \"author\": \"",
        ORIGIN_AUTHOR,
        "\",\n    \"initial_lines_of_code\": \"",
        ORIGIN_LINES_OF_CODE,
        "\"\n  },\n  \"milestones\": [",
    ]
    .into_iter()
    .chain(
        MILESTONES
            .iter()
            .enumerate()
            .flat_map(|(index, milestone)| {
                [
                    if index == 0 { "" } else { "," },
                    "\n    { \"year\": ",
                    milestone.year,
                    ", \"date\": \"",
                    milestone.date,
                    "\", \"event\": \"",
                    milestone.event,
                    "\", \"note\": \"",
                    milestone.note,
                    "\" }",
                ]
            }),
    )
    .chain([
        "\n  ],\n  \"statistics\": {\n    \"estimated_installations\": ",
        INSTALLATIONS,
        ",\n    \"estimated_installations_note\": \"",
        INSTALLATIONS_NOTE,
        "\",\n    \"url_scheme_count\": ",
        SCHEME_COUNT,
        ",\n    \"used_on_mars\": true,\n    \"internet_users_1996\": ",
        USERS_1996,
        ",\n    \"internet_users_2026_estimate\": \"",
        USERS_2026,
        "\"\n  },\n  \"protocols\": [",
    ])
    .chain(PROTOCOLS.into_iter().enumerate().flat_map(|(index, name)| {
        let separator = match index {
            0 => "\n    \"",
            _ if index % 4 == 0 => ",\n    \"",
            _ => ", \"",
        };
        [separator, name, "\""]
    }))
    .chain([
        "\n  ],\n  \"links\": {\n    \"homepage\": \"",
        HOMEPAGE,
        "\",\n    \"anniversary\": \"",
        ANNIVERSARY,
        "\"\n  }\n}\n",
    ])
}

fn render_html() -> String {
    let homepage = HOMEPAGE;
    let anniversary = ANNIVERSARY;
    html!(
        lang = "en",
        head!(
            meta!(charset = "utf-8"),
            meta!(
                name = "viewport",
                content = "width=device-width, initial-scale=1"
            ),
            title!(TITLE),
            style!(PreEscaped(include_str!("style.css"))),
        ),
        body!(
            header!(
                b!("curl://"),
                a!(href = homepage, HOMEPAGE_HOST),
                a!(href = anniversary, "30 years of Internet transfers"),
            ),
            main!(
                h1!(TITLE),
                p!(class = "subtitle", YEARS),
                p!(SUMMARY.map(|line| (line, " "))),
                html_milestones(),
                html_schemes(),
                html_statistics(),
                html_thanks(),
            ),
            footer!(
                a!(href = homepage, HOMEPAGE_HOST),
                a!(href = anniversary, ANNIVERSARY_HOST),
            ),
        ),
    )
    .into_string()
}

fn html_milestones() -> impl IntoHtml {
    (
        h2!("Milestones"),
        ol!(MILESTONES.iter().map(|milestone| li!(
            time!(datetime = milestone.date, milestone.year),
            strong!(milestone.event),
            " — ",
            milestone.note,
        ))),
    )
}

fn html_schemes() -> impl IntoHtml {
    let homepage = HOMEPAGE;
    (
        h2!(SCHEME_COUNT, " URL schemes"),
        p!(
            "As listed on ",
            a!(href = homepage, HOMEPAGE_HOST),
            "; a given build may enable fewer.",
        ),
        ul!(PROTOCOLS.map(|name| li!(name))),
    )
}

fn html_statistics() -> impl IntoHtml {
    (
        h2!("Then and now"),
        dl!(
            div!(
                dt!("100+"),
                dd!(
                    "lines of C in ",
                    ORIGIN_NAME,
                    " ",
                    ORIGIN_VERSION,
                    ", ",
                    ORIGIN_YEAR
                ),
            ),
            div!(
                dt!(INSTALLATIONS_SHORT),
                dd!("installations, ", INSTALLATIONS_NOTE),
            ),
            div!(dt!(USERS_1996_SHORT), dd!("people online in 1996"),),
            div!(dt!(USERS_2026), dd!("people online in 2026"),),
            div!(dt!("Mars"), dd!("curl helped a landing mission")),
        ),
    )
}

fn html_thanks() -> impl IntoHtml {
    (
        h2!("Thank you"),
        p!(
            ORIGIN_NAME,
            " began with ",
            ORIGIN_AUTHOR,
            " in ",
            ORIGIN_YEAR,
            ". Daniel Stenberg turned it into curl and has led it ever since, \
             together with thousands of contributors.",
        ),
        p!(strong!(MOTTO)),
        p!(THANKS),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::http::{BodyExtractExt as _, header::ACCEPT};

    async fn rendered(format: Format) -> String {
        Response::new(format.body())
            .try_into_string()
            .await
            .unwrap()
    }

    fn negotiated(accept: &str) -> Format {
        let mut req = Request::new(Body::empty());
        req.headers_mut()
            .insert(ACCEPT, HeaderValue::from_str(accept).unwrap());
        negotiate(req.headers().typed_get::<Accept>().as_ref())
    }

    #[test]
    fn negotiates_format_from_accept() {
        assert_eq!(Format::Text, negotiate(None));
        for (accept, expected) in [
            ("*/*", Format::Text),
            ("text/plain", Format::Text),
            ("text/*", Format::Text),
            ("image/png", Format::Text),
            ("not a media type", Format::Text),
            ("text/html", Format::Html),
            ("application/json", Format::Json),
            ("application/*", Format::Json),
            (
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                Format::Html,
            ),
            ("text/html;q=0.5, application/json", Format::Json),
            ("application/json;q=0.2, text/html;q=0.7", Format::Html),
            ("text/plain;q=0, */*", Format::Html),
            ("text/html;q=0, application/json;q=0", Format::Text),
            ("application/json, */*;q=0.1", Format::Json),
        ] {
            assert_eq!(expected, negotiated(accept), "accept: {accept}");
        }
    }

    #[tokio::test]
    async fn text_fits_a_terminal_screenshot() {
        let text = rendered(Format::Text).await;
        assert!(text.ends_with('\n') && !text.ends_with("\n\n"));
        assert!(!text.contains('\u{1b}'), "no ANSI escapes");
        for line in text.lines() {
            assert!(line.chars().count() <= TEXT_WIDTH + 2, "too wide: {line:?}");
            assert_eq!(line, line.trim_end(), "trailing whitespace: {line:?}");
        }
        let frame: Vec<_> = text.lines().take(6).map(|l| l.chars().count()).collect();
        assert!(
            frame.iter().all(|&width| width == TEXT_WIDTH + 2),
            "{frame:?}"
        );
        let rules = text.lines().filter(|line| line.starts_with("  ──"));
        assert!(
            rules.clone().count() == 3
                && rules.clone().all(|l| l.chars().count() == TEXT_WIDTH + 2)
        );
        assert_eq!(1, text.lines().filter(|line| line.contains("WSS")).count());
    }

    #[tokio::test]
    async fn every_format_lists_all_schemes_without_branding() {
        for format in Format::ALL {
            let content = rendered(format).await;
            for scheme in PROTOCOLS {
                let listed = content
                    .split(|c: char| !c.is_ascii_alphanumeric())
                    .any(|word| word == scheme);
                assert!(listed, "{format:?} misses {scheme}");
            }
            let lowered = content.to_lowercase();
            for brand in ["rama", "plabayo"] {
                assert!(!lowered.contains(brand), "{format:?} mentions {brand}");
            }
        }
    }

    #[tokio::test]
    async fn json_is_structured() {
        let json = rendered(Format::Json).await;
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let protocols: Vec<_> = value["protocols"]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| name.as_str().unwrap())
            .collect();
        assert_eq!(PROTOCOLS.as_slice(), protocols);
        let statistics = &value["statistics"];
        assert_eq!(PROTOCOLS.len() as u64, statistics["url_scheme_count"]);
        assert_eq!(30_000_000_000_u64, statistics["estimated_installations"]);
        assert_eq!(1996, value["origin"]["year"]);
        let milestones = value["milestones"].as_array().unwrap();
        assert_eq!(MILESTONES.len(), milestones.len());
        assert!(milestones.iter().all(|m| m["year"].is_u64()));
        assert_eq!(ANNIVERSARY, value["links"]["anniversary"]);
    }

    #[test]
    fn html_is_self_contained() {
        let html = render_html();
        for external in ["<script", "<link", "<img", "src=", "@import", "url("] {
            assert!(!html.contains(external), "found {external}");
        }
        assert!(html.contains("<style>") && html.contains(HOMEPAGE));
        assert!(html.contains(SUMMARY[2]) && html.contains("<li>GOPHERS</li>"));
    }

    #[tokio::test]
    async fn head_matches_get_without_body() {
        for accept in ["*/*", "text/html", "application/json"] {
            let request = |method: Method| {
                let mut req = Request::new(Body::empty());
                *req.method_mut() = method;
                req.headers_mut()
                    .insert(ACCEPT, HeaderValue::from_static(accept));
                req
            };
            let get = service().serve(request(Method::GET)).await.unwrap();
            let head = service().serve(request(Method::HEAD)).await.unwrap();
            for name in [CONTENT_TYPE, VARY, CACHE_CONTROL] {
                assert_eq!(get.headers()[&name], head.headers()[&name], "{name}");
            }
            assert!(!get.try_into_string().await.unwrap().is_empty());
            assert!(head.try_into_string().await.unwrap().is_empty());
        }
    }
}
