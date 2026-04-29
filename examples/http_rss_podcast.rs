//! RSS 2.0 podcast feed example with iTunes and Podcasting 2.0 extensions.
//!
//! Demonstrates serving a podcast RSS feed with episode enclosures, iTunes
//! metadata, and Podcasting 2.0 extension fields.  Also shows how a streaming
//! writer can produce the feed without buffering all items in memory.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_rss_podcast --features=http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62051`. You can fetch the feeds with:
//!
//! ```sh
//! curl http://127.0.0.1:62051/podcast.rss
//! curl http://127.0.0.1:62051/podcast-stream.rss
//! ```

use std::{convert::Infallible, sync::Arc, time::Duration};

use jiff::Timestamp;
use rama::{
    Layer,
    futures::async_stream::stream_fn,
    http::{
        Body,
        headers::ContentType,
        layer::trace::TraceLayer,
        protocols::rss::{
            Rss2Enclosure, Rss2Feed, Rss2FeedMeta, Rss2Guid, Rss2Item, Rss2StreamWriter,
            feed_ext::{
                FeedExtensions, ITunes, ITunesFeed, ItemExtensions, Podcast, PodcastEpisode,
                PodcastFeed, PodcastSeason,
            },
        },
        server::HttpServer,
        service::web::{
            Router,
            response::{Headers, IntoResponse},
        },
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

async fn podcast_feed() -> impl IntoResponse {
    Rss2Feed::builder()
        .title("Netstack.FM")
        .link("https://netstack.fm")
        .description("The podcast about Rust networking and systems programming.")
        .language("en")
        .generator("rama/http_rss_podcast example")
        .feed_extensions(FeedExtensions {
            itunes: Some(ITunesFeed {
                author: Some("Netstack.FM".into()),
                owner_name: Some("Glen De Cauwsemaecker".into()),
                owner_email: Some("glen@plabayo.tech".into()),
                categories: vec!["Technology".into(), "Software How-To".into()],
                explicit: Some(false),
                type_: Some("episodic".into()),
                summary: Some("The podcast about Rust networking and systems programming.".into()),
                ..Default::default()
            }),
            podcast: Some(PodcastFeed {
                locked: Some(false),
                medium: Some("podcast".into()),
                ..Default::default()
            }),
            ..Default::default()
        })
        .items(EPISODES.iter().map(|ep| make_episode_item(ep)))
        .build()
}

async fn podcast_stream() -> impl IntoResponse {
    let meta = Rss2FeedMeta {
        title: "Netstack.FM (streaming)".into(),
        link: "https://netstack.fm".into(),
        description: "Streamed podcast feed.".into(),
        language: Some("en".into()),
        generator: Some("rama Rss2StreamWriter".into()),
    };

    let item_stream = stream_fn(move |mut yielder| async move {
        for ep in EPISODES {
            let item = make_episode_item(ep);
            yielder.yield_item(Ok::<_, Infallible>(item)).await;
        }
    });

    (
        Headers::single(ContentType::rss()),
        Body::from_stream(Rss2StreamWriter::new(meta, item_stream)),
    )
}

fn make_episode_item(ep: &Episode) -> Rss2Item {
    Rss2Item::new()
        .with_title(ep.title)
        .with_description(ep.description)
        .with_guid(Rss2Guid::permalink(ep.url))
        .with_link(ep.url)
        .with_pub_date(ep.pub_date)
        .with_enclosure(Rss2Enclosure::new(ep.audio_url, ep.audio_bytes, ep.audio_type))
        .with_extensions(ItemExtensions {
            itunes: Some(ITunes {
                title: Some(ep.title.into()),
                duration: Some(ep.duration.into()),
                episode: Some(ep.episode_number),
                season: Some(ep.season),
                episode_type: Some("full".into()),
                explicit: Some(false),
                ..Default::default()
            }),
            podcast: Some(Podcast {
                season: Some(PodcastSeason {
                    number: ep.season,
                    name: Some(format!("Season {}", ep.season)),
                }),
                episode: Some(PodcastEpisode {
                    number: ep.episode_number as f64,
                    display: None,
                }),
                ..Default::default()
            }),
            ..Default::default()
        })
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

    let listener = TcpListener::bind_address(SocketAddress::default_ipv4(62051), exec.clone())
        .await
        .expect("bind address");
    let bind_address = listener.local_addr().expect("local addr");

    tracing::info!(
        network.local.address = %bind_address.ip(),
        network.local.port = %bind_address.port(),
        "http rss podcast listening",
    );
    tracing::info!(
        "one-shot: curl http://{bind_address}/podcast.rss  |  streamed: curl http://{bind_address}/podcast-stream.rss"
    );

    graceful.spawn_task(async move {
        let app = TraceLayer::new_for_http().into_layer(Arc::new(
            Router::new()
                .with_get("/podcast.rss", podcast_feed)
                .with_get("/podcast-stream.rss", podcast_stream),
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

struct Episode {
    title: &'static str,
    description: &'static str,
    url: &'static str,
    audio_url: &'static str,
    audio_bytes: u64,
    audio_type: &'static str,
    duration: &'static str,
    pub_date: Timestamp,
    episode_number: u64,
    season: u64,
}

static EPISODES: &[Episode] = &[
    Episode {
        title: "Episode 1 - Hello Networking",
        description: "We kick off the show with an overview of Rust networking.",
        url: "https://netstack.fm/episodes/1",
        audio_url: "https://cdn.netstack.fm/audio/ep001.mp3",
        audio_bytes: 48_000_000,
        audio_type: "audio/mpeg",
        duration: "50:12",
        pub_date: Timestamp::UNIX_EPOCH,
        episode_number: 1,
        season: 1,
    },
    Episode {
        title: "Episode 2 - TCP Deep Dive",
        description: "A deep dive into TCP internals and how Rama models them.",
        url: "https://netstack.fm/episodes/2",
        audio_url: "https://cdn.netstack.fm/audio/ep002.mp3",
        audio_bytes: 52_000_000,
        audio_type: "audio/mpeg",
        duration: "55:40",
        pub_date: Timestamp::UNIX_EPOCH,
        episode_number: 2,
        season: 1,
    },
    Episode {
        title: "Episode 3 - Proxies Demystified",
        description: "Everything you need to know about building proxies in Rust.",
        url: "https://netstack.fm/episodes/3",
        audio_url: "https://cdn.netstack.fm/audio/ep003.mp3",
        audio_bytes: 61_000_000,
        audio_type: "audio/mpeg",
        duration: "63:18",
        pub_date: Timestamp::UNIX_EPOCH,
        episode_number: 3,
        season: 1,
    },
];
