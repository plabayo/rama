# RSS and Atom Feeds

<div class="book-article-intro">
    <div>
        Rama has built-in support for <strong>RSS 2.0</strong> and <strong>Atom 1.0</strong>
        feeds — both for serving them from a web handler and for consuming them on the client
        side.  Extensions (iTunes, Podcasting 2.0, Dublin Core, Media RSS,
        <code>content:encoded</code>) are supported out of the box.
    </div>
</div>

## Overview

| Goal | API |
|------|-----|
| Serve an RSS 2.0 feed | Return `Rss2Feed` from a handler (implements `IntoResponse`) |
| Serve an Atom feed | Return `AtomFeed` from a handler (implements `IntoResponse`) |
| Stream a feed without buffering | Wrap an item stream in `Rss2StreamWriter` / `AtomStreamWriter` |
| Parse any feed on the client side | `Feed::from_body(response.into_body()).await` |
| Format-agnostic code | Use the `Feed` umbrella enum |

All types live under `rama_http::protocols::rss` (or `rama::http::protocols::rss` via the top-level crate).

## Serving feeds

### RSS 2.0

`Rss2Feed` uses a type-state builder that enforces the three required fields
(`title`, `link`, `description`) at compile time — the compiler prevents
calling `.build()` until all three are present:

```rust,ignore
use rama::http::protocols::rss::{Rss2Feed, Rss2Item, Rss2Guid};

async fn feed_handler() -> impl IntoResponse {
    Rss2Feed::builder()
        .title("My Blog")
        .link("https://example.com")
        .description("Latest articles")
        .item(
            Rss2Item::new()
                .with_title("Hello World")
                .with_guid(Rss2Guid::permalink("https://example.com/hello"))
                .with_description("My first post"),
        )
        .build()
}
```

The response will have `Content-Type: application/rss+xml`.

### Atom 1.0

`AtomFeed` follows the same type-state pattern (required: `id`, `title`,
`updated`):

```rust,ignore
use rama::http::protocols::rss::{AtomFeed, AtomEntry, AtomText, AtomLink, AtomPerson};
use jiff::Timestamp;

async fn atom_handler() -> impl IntoResponse {
    let now = Timestamp::now();
    AtomFeed::builder()
        .id("https://example.com/feed.atom")
        .title("My Blog")
        .updated(now)
        .author(AtomPerson::new("Alice"))
        .link(AtomLink::alternate("https://example.com"))
        .entry(
            AtomEntry::new("https://example.com/hello", "Hello World", now)
                .with_summary(AtomText::text("My first post")),
        )
        .build()
}
```

## Streaming feeds

For feeds with many items — or items produced by an async data source — use the
streaming writers to avoid buffering the entire document:

```rust,ignore
use std::convert::Infallible;
use rama::{
    futures::async_stream::stream_fn,
    http::{Body, headers::ContentType, protocols::rss::{Rss2FeedMeta, Rss2Item, Rss2StreamWriter},
           service::web::response::{Headers, IntoResponse}},
};

async fn streamed_feed() -> impl IntoResponse {
    let meta = Rss2FeedMeta {
        title: "My Blog".into(),
        link: "https://example.com".into(),
        description: "Latest articles".into(),
        language: None,
        generator: None,
    };
    let items = stream_fn(|mut y| async move {
        for i in 0..100u64 {
            let item = Rss2Item::new()
                .with_title(format!("Post {i}"))
                .with_link(format!("https://example.com/{i}"));
            y.yield_item(Ok::<_, Infallible>(item)).await;
        }
    });
    (
        Headers::single(ContentType::rss()),
        Body::from_stream(Rss2StreamWriter::new(meta, items)),
    )
}
```

## Podcast feeds with extensions

Use the `feed_ext` sub-module for iTunes, Podcasting 2.0, and other extension
fields.  Items expose both inherent shortcuts (`.itunes()`, `.podcast()`, …)
and a generic `.extension::<T>()` method:

```rust,ignore
use rama::http::protocols::rss::feed_ext::{
    FeedExtensions, ITunes, ITunesFeed, ItemExtensions, Podcast, PodcastEpisode,
};

let feed = Rss2Feed::builder()
    .title("My Podcast")
    .link("https://example.com/podcast")
    .description("A weekly show")
    .feed_extensions(FeedExtensions {
        itunes: Some(ITunesFeed {
            author: Some("Alice".into()),
            explicit: Some(false),
            type_: Some("episodic".into()),
            ..Default::default()
        }),
        ..Default::default()
    })
    .item(
        Rss2Item::new()
            .with_title("Episode 1")
            .with_extensions(ItemExtensions {
                itunes: Some(ITunes {
                    episode: Some(1),
                    season: Some(1),
                    duration: Some("45:00".into()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
    )
    .build();

// Access extension data on the parsed item:
let item = &feed.items[0];
assert!(item.itunes().is_some());
assert_eq!(item.itunes().unwrap().episode, Some(1));
```

## Client-side parsing

```rust,ignore
use rama::http::{client::EasyHttpWebClient, protocols::rss::Feed,
                  service::client::HttpClientExt};

let client = EasyHttpWebClient::default();
let response = client
    .get("https://example.com/feed.rss")
    .send()
    .await?;
let feed = Feed::from_body(response.into_body()).await?;
println!("Feed title: {}", feed.title());
```

`Feed::from_body` detects the format automatically (RSS 2.0 vs Atom) and
parses leniently.  Use `Feed::from_body_strict` if you need structural errors
to surface.

## Examples

- [`http_rss_blog`](https://github.com/plabayo/rama/blob/main/examples/http_rss_blog.rs) — RSS 2.0 and Atom blog feed server
- [`http_rss_podcast`](https://github.com/plabayo/rama/blob/main/examples/http_rss_podcast.rs) — podcast feed with iTunes + Podcasting 2.0 extensions, one-shot and streaming
