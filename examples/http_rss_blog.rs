//! RSS 2.0 blog feed example.
//!
//! Demonstrates how to serve an RSS 2.0 feed and an Atom 1.0 feed from the
//! same router, using `Rss2Feed` and `AtomFeed` as `IntoResponse` types.
//! Also shows how a client can parse a feed via `Feed::from_body`.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_rss_blog --features=http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62050`. You can fetch the feeds with:
//!
//! ```sh
//! curl http://127.0.0.1:62050/feed.rss
//! curl http://127.0.0.1:62050/feed.atom
//! ```

use std::{sync::Arc, time::Duration};

use jiff::Timestamp;
use rama::{
    Layer,
    http::{
        layer::trace::TraceLayer,
        protocols::rss::{
            AtomContent, AtomEntry, AtomFeed, AtomLink, AtomPerson, AtomText, Rss2Feed,
            Rss2Guid, Rss2Item,
            feed_ext::{Content, ItemExtensions},
        },
        server::HttpServer,
        service::web::{Router, response::IntoResponse},
    },
    net::address::SocketAddress,
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
};

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn rss2_feed() -> impl IntoResponse {
    Rss2Feed::builder()
        .title("The Rama Blog")
        .link("https://ramaproxy.org/blog")
        .description("News and articles from the Rama project")
        .language("en")
        .generator("rama/http_rss_blog example")
        .items(BLOG_POSTS.iter().map(|p| {
            Rss2Item::new()
                .with_title(p.title)
                .with_link(p.url)
                .with_description(p.summary)
                .with_author("team@ramaproxy.org")
                .with_guid(Rss2Guid::permalink(p.url))
                .with_extensions(ItemExtensions {
                    content: Some(Content {
                        encoded: Some(format!("<p>{}</p>", p.body)),
                    }),
                    ..Default::default()
                })
        }))
        .build()
}

async fn atom_feed() -> impl IntoResponse {
    let ts = Timestamp::now();
    AtomFeed::builder()
        .id("https://ramaproxy.org/feed.atom")
        .title("The Rama Blog")
        .updated(ts)
        .author(AtomPerson::new("Rama Team").with_email("team@ramaproxy.org"))
        .link(AtomLink::alternate("https://ramaproxy.org/blog"))
        .link(AtomLink::self_link("https://ramaproxy.org/feed.atom"))
        .subtitle(AtomText::text("News and articles from the Rama project"))
        .entries(BLOG_POSTS.iter().map(|p| {
            AtomEntry::new(p.url, p.title, ts)
                .with_author(AtomPerson::new("Rama Team"))
                .with_link(AtomLink::alternate(p.url))
                .with_summary(AtomText::text(p.summary))
                .with_content(AtomContent::html(format!("<p>{}</p>", p.body)))
        }))
        .build()
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let graceful = rama::graceful::Shutdown::default();
    let exec = Executor::graceful(graceful.guard());

    let listener = TcpListener::bind_address(SocketAddress::default_ipv4(62050), exec.clone())
        .await
        .expect("bind address");
    let bind_address = listener.local_addr().expect("local addr");

    tracing::info!(
        network.local.address = %bind_address.ip(),
        network.local.port = %bind_address.port(),
        "http rss blog listening",
    );
    tracing::info!(
        "fetch rss: curl http://{bind_address}/feed.rss  |  atom: curl http://{bind_address}/feed.atom"
    );

    graceful.spawn_task(async move {
        let app = TraceLayer::new_for_http().into_layer(Arc::new(
            Router::new()
                .with_get("/feed.rss", rss2_feed)
                .with_get("/feed.atom", atom_feed),
        ));
        listener.serve(HttpServer::auto(exec).service(app)).await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

// ---------------------------------------------------------------------------
// Sample data
// ---------------------------------------------------------------------------

struct BlogPost {
    title: &'static str,
    url: &'static str,
    summary: &'static str,
    body: &'static str,
}

static BLOG_POSTS: &[BlogPost] = &[
    BlogPost {
        title: "Introducing Rama",
        url: "https://ramaproxy.org/blog/introducing-rama",
        summary: "An overview of the Rama modular service framework.",
        body: "Rama is a modular service framework for building proxies and web services in Rust.",
    },
    BlogPost {
        title: "RSS Support in Rama",
        url: "https://ramaproxy.org/blog/rss-support",
        summary: "How to serve and consume RSS 2.0 and Atom 1.0 feeds with Rama.",
        body: "Rama now ships built-in RSS 2.0 and Atom 1.0 support with type-state builders, extensions, and streaming writers.",
    },
    BlogPost {
        title: "Streaming HTTP Responses",
        url: "https://ramaproxy.org/blog/streaming-responses",
        summary: "A guide to streaming large HTTP responses using Rama.",
        body: "Rama provides first-class streaming support for SSE, ndjson, and now RSS/Atom feeds.",
    },
];
