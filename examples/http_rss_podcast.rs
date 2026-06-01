//! RSS 2.0 podcast feed example with iTunes and Podcasting 2.0 extensions.
//!
//! Two routes:
//!
//! * `/podcast.rss` — one-shot: build a whole [`Rss2Feed`] in-memory and let
//!   `IntoResponse` stream it out. Fine when the catalogue fits in memory.
//! * `/podcast-stream.rss` — streamed: build a [`Rss2Channel`] header up front,
//!   then pipe episodes from a faux paginated store through
//!   [`Rss2StreamWriter`] so the response starts flowing before every item is
//!   materialised. Mirrors the shape of "fetch a page of episodes from the
//!   database at a time, no buffering" that a real podcast backend needs.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_rss_podcast --features=http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62054`. You can fetch the feeds with:
//!
//! ```sh
//! curl http://127.0.0.1:62054/podcast.rss
//! curl http://127.0.0.1:62054/podcast-stream.rss
//! ```

#![expect(
    clippy::expect_used,
    reason = "example/test/bench: panic-on-error and print-for-output are the standard patterns for demos and harnesses"
)]

use std::{convert::Infallible, sync::Arc, time::Duration};

use jiff::Timestamp;
use rama::{
    Layer,
    futures::async_stream::stream_fn,
    http::{
        Body,
        headers::ContentType,
        layer::{error_handling::ErrorHandlerLayer, trace::TraceLayer},
        protocols::rss::{
            Rss2Channel, Rss2Enclosure, Rss2Feed, Rss2Guid, Rss2Item, Rss2StreamWriter,
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
        .with_language("en")
        .with_generator("rama/http_rss_podcast example")
        .with_feed_extensions(FeedExtensions {
            itunes: Some(Box::new(ITunesFeed {
                author: Some("Netstack.FM".into()),
                owner_name: Some("Glen De Cauwsemaecker".into()),
                owner_email: Some("glen@plabayo.tech".into()),
                categories: vec!["Technology".into(), "Software How-To".into()],
                explicit: Some(false),
                type_: Some("episodic".into()),
                summary: Some("The podcast about Rust networking and systems programming.".into()),
                ..Default::default()
            })),
            podcast: Some(Box::new(PodcastFeed {
                locked: Some(false),
                medium: Some("podcast".into()),
                ..Default::default()
            })),
            ..Default::default()
        })
        .with_items(EPISODES.iter().map(make_episode_item))
        .build()
}

async fn podcast_stream() -> impl IntoResponse {
    // The channel header is the same type the reader produces — same shape
    // both ways, so the construct ↔ drain path round-trips through one model.
    let channel = Rss2Channel {
        title: "Netstack.FM (streaming)".into(),
        link: "https://netstack.fm".into(),
        description: "Streamed podcast feed.".into(),
        language: Some("en".into()),
        generator: Some("rama Rss2StreamWriter".into()),
        ..Default::default()
    };

    // Simulate paginated fetches from a backing store (e.g. a database that
    // returns 2 episodes at a time). Items are yielded as each page arrives;
    // the writer never sees the whole catalogue at once.
    let item_stream = stream_fn(move |mut yielder| async move {
        let store = EpisodeStore::new(EPISODES, 2);
        let mut offset = 0;
        while let Some(page) = store.page(offset).await {
            offset += page.len();
            for ep in page {
                yielder
                    .yield_item(Ok::<_, Infallible>(make_episode_item(ep)))
                    .await;
            }
        }
    });

    (
        Headers::single(ContentType::rss()),
        Body::from_stream(Rss2StreamWriter::new(channel, item_stream)),
    )
}

/// Faux paginated catalogue store. Stands in for a database or external
/// service the streaming endpoint reads from one page at a time.
struct EpisodeStore<'a> {
    episodes: &'a [Episode],
    page_size: usize,
}

impl<'a> EpisodeStore<'a> {
    fn new(episodes: &'a [Episode], page_size: usize) -> Self {
        Self {
            episodes,
            page_size,
        }
    }

    /// Fetch the next page starting at `offset`. Returns `None` once the end
    /// of the catalogue has been reached. The `await` is symbolic — a real
    /// implementation would await an actual I/O round-trip here.
    async fn page(&self, offset: usize) -> Option<&'a [Episode]> {
        if offset >= self.episodes.len() {
            return None;
        }
        let end = (offset + self.page_size).min(self.episodes.len());
        Some(&self.episodes[offset..end])
    }
}

fn make_episode_item(ep: &Episode) -> Rss2Item {
    Rss2Item::new()
        .with_title(ep.title)
        .with_description(ep.description)
        .with_guid(Rss2Guid::permalink(ep.url))
        .with_link(ep.url)
        .with_pub_date(ep.pub_date)
        .with_enclosure(Rss2Enclosure::new(
            ep.audio_url,
            ep.audio_bytes,
            ep.audio_type,
        ))
        .with_extensions(ItemExtensions {
            itunes: Some(Box::new(ITunes {
                title: Some(ep.title.into()),
                duration: Some(ep.duration.into()),
                episode: Some(ep.episode_number),
                season: Some(ep.season),
                episode_type: Some("full".into()),
                explicit: Some(false),
                ..Default::default()
            })),
            podcast: Some(Box::new(Podcast {
                season: Some(PodcastSeason {
                    number: ep.season,
                    name: Some(format!("Season {}", ep.season)),
                }),
                episode: Some(PodcastEpisode {
                    number: ep.episode_number as f64,
                    display: None,
                }),
                ..Default::default()
            })),
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

    let listener = TcpListener::bind_address(SocketAddress::default_ipv4(62054), exec.clone())
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
        let middlewares = (TraceLayer::new_for_http(), ErrorHandlerLayer::new());
        let app = middlewares.into_layer(Arc::new(
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
