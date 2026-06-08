//! Streaming HTML response for [Chrome declarative partial updates].
//!
//! Flushes a shell (with `<?marker name="…">` placeholders) immediately,
//! then emits one `<template for="name">…</template>` body chunk per
//! fragment as each fragment future resolves — in completion order, not
//! declaration order. Each chunk is followed by `\n<wbr>` so the [official
//! polyfill] can swap every fragment at its own arrival rather than one
//! step behind: it defers a swap while the template has no
//! `nextElementSibling`, and `<wbr>` (an invisible HTMLElement) is the
//! smallest thing that satisfies that check. Mirrors the spirit of
//! [Google's photo-album demo].
//!
//! [Chrome declarative partial updates]: https://developer.chrome.com/blog/declarative-partial-updates
//! [official polyfill]: https://github.com/GoogleChromeLabs/template-for-polyfill
//! [Google's photo-album demo]: https://github.com/GoogleChromeLabs/web-perf-demos/blob/main/patching-demos/server.js

use rama_core::bytes::Bytes;
use rama_core::error::BoxError;
use rama_core::futures::FutureExt;
use rama_core::futures::future::BoxFuture;
use rama_core::futures::stream::{self, StreamExt};
use rama_http_headers::ContentType;
use rama_http_types::{Body, Response};

use crate::protocols::html::{IntoHtml, template};

use super::{Headers, IntoResponse};

/// A streaming HTML response that fills `<?marker name="…">` placeholders
/// out-of-order as fragment futures complete.
///
/// Pair the shell with [`crate::protocols::html::marker`] to emit the processing
/// instructions; this response wraps each fragment's rendered HTML in a
/// `<template for="name">…</template>` block as it resolves.
#[must_use]
pub struct PartialUpdates<H> {
    shell: H,
    fragments: Vec<Fragment>,
}

/// Type-erased renderer: a closure that writes the rendered HTML of a
/// resolved fragment into a target buffer. Implements [`IntoHtml`] (via
/// the blanket impl for `FnOnce(&mut String)`), so it slots straight into
/// the `template!` macro at chunk-emit time — no early `into_string()`,
/// no manual escaping.
type FragmentRender = Box<dyn FnOnce(&mut String) + Send + 'static>;

struct Fragment {
    name: &'static str,
    future: BoxFuture<'static, Result<FragmentRender, BoxError>>,
}

impl<H: IntoHtml> PartialUpdates<H> {
    /// Wrap an HTML `shell` for streaming.
    pub fn new(shell: H) -> Self {
        Self {
            shell,
            fragments: Vec::new(),
        }
    }

    /// Add a fragment whose rendered HTML will be flushed inside a
    /// `<template for="name">…</template>` block once `fut` resolves.
    ///
    /// Whatever the future yields is rendered through [`IntoHtml`] — i.e.
    /// scalar strings are HTML-escaped, [`PreEscaped`] passes through verbatim,
    /// and macro-built nodes compose normally.
    ///
    /// [`PreEscaped`]: crate::protocols::html::PreEscaped
    pub fn fragment<F, T>(mut self, name: &'static str, fut: F) -> Self
    where
        F: Future<Output = T> + Send + 'static,
        T: IntoHtml + Send + 'static,
    {
        self.fragments.push(Fragment {
            name,
            future: async move {
                let value = fut.await;
                let render: FragmentRender = Box::new(move |buf| value.escape_and_write(buf));
                Ok(render)
            }
            .boxed(),
        });
        self
    }

    /// Like [`Self::fragment`] but the future returns a `Result`; on `Err`
    /// the body stream terminates with that error.
    pub fn try_fragment<F, T, E>(mut self, name: &'static str, fut: F) -> Self
    where
        F: Future<Output = Result<T, E>> + Send + 'static,
        T: IntoHtml + Send + 'static,
        E: Into<BoxError> + Send + 'static,
    {
        self.fragments.push(Fragment {
            name,
            future: async move {
                let value = fut.await.map_err(Into::into)?;
                let render: FragmentRender = Box::new(move |buf| value.escape_and_write(buf));
                Ok(render)
            }
            .boxed(),
        });
        self
    }
}

impl<H> IntoResponse for PartialUpdates<H>
where
    H: IntoHtml + Send + 'static,
{
    fn into_response(self) -> Response {
        let shell = self.shell.into_string();
        let shell_chunk = stream::once(async move { Ok::<_, BoxError>(Bytes::from(shell)) });

        let frag_count = self.fragments.len().max(1);
        let fragment_chunks = stream::iter(self.fragments)
            .map(|Fragment { name, future }| async move {
                let render = future.await?;
                let mut s = template!(r#for = name, render).into_string();
                s.push_str("\n<wbr>");
                Ok::<_, BoxError>(Bytes::from(s))
            })
            .buffer_unordered(frag_count);

        (
            Headers::single(ContentType::html_utf8()),
            Body::from_stream(shell_chunk.chain(fragment_chunks)),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::html::{html, marker, p};
    use std::time::Duration;
    use tokio::time::{Instant, sleep};

    #[tokio::test(start_paused = true)]
    async fn shell_arrives_before_slowest_fragment() {
        let shell = html!(p!(marker("slow")));
        let res = PartialUpdates::new(shell)
            .fragment("slow", async {
                sleep(Duration::from_millis(500)).await;
                "ok"
            })
            .into_response();

        let mut body = res.into_body();
        let t0 = Instant::now();
        let first = body.chunk().await.unwrap().unwrap();
        let t_first = t0.elapsed();

        assert!(
            t_first < Duration::from_millis(50),
            "shell should flush immediately, got {t_first:?}"
        );
        let first = std::str::from_utf8(&first).unwrap();
        assert!(first.contains(r#"<?marker name="slow">"#));
        assert!(!first.contains("<template for="));

        let second = body.chunk().await.unwrap().unwrap();
        let t_second = t0.elapsed();
        assert!(
            t_second >= Duration::from_millis(500),
            "fragment should wait for its delay, got {t_second:?}"
        );
        assert_eq!(
            std::str::from_utf8(&second).unwrap(),
            "<template for=\"slow\">ok</template>\n<wbr>"
        );

        assert!(body.chunk().await.unwrap().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn fragment_macro_node_keeps_tags() {
        // A macro-built node must NOT have its element tags escaped — only
        // the dynamic string content inside should be escaped.
        let shell = html!(p!(marker("x")));
        let res = PartialUpdates::new(shell)
            .fragment("x", async { p!("<not-a-tag>") })
            .into_response();
        let mut body = res.into_body();
        let _shell = body.chunk().await.unwrap().unwrap();
        let tpl = body.chunk().await.unwrap().unwrap();
        assert_eq!(
            std::str::from_utf8(&tpl).unwrap(),
            "<template for=\"x\"><p>&lt;not-a-tag&gt;</p></template>\n<wbr>"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn fragment_name_is_html_escaped() {
        let shell = html!(p!(marker("a<b")));
        let res = PartialUpdates::new(shell)
            .fragment("a<b", async { "ok" })
            .into_response();
        let mut body = res.into_body();
        let _shell = body.chunk().await.unwrap().unwrap();
        let tpl = body.chunk().await.unwrap().unwrap();
        assert_eq!(
            std::str::from_utf8(&tpl).unwrap(),
            "<template for=\"a&lt;b\">ok</template>\n<wbr>"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn fragments_stream_in_completion_order() {
        let shell = html!(p!(marker("a"), marker("b"), marker("c")));
        let res = PartialUpdates::new(shell)
            .fragment("a", async {
                sleep(Duration::from_millis(600)).await;
                "A"
            })
            .fragment("b", async {
                sleep(Duration::from_millis(100)).await;
                "B"
            })
            .fragment("c", async {
                sleep(Duration::from_millis(300)).await;
                "C"
            })
            .into_response();

        let mut body = res.into_body();
        let t0 = Instant::now();

        let mut chunks: Vec<(Duration, String)> = Vec::new();
        while let Some(chunk) = body.chunk().await.unwrap() {
            chunks.push((
                t0.elapsed(),
                String::from_utf8(chunk.to_vec()).expect("utf8"),
            ));
        }

        assert_eq!(chunks.len(), 4, "shell + 3 fragments");
        assert!(chunks[0].1.contains(r#"<?marker name="a">"#));
        assert_eq!(chunks[1].1, "<template for=\"b\">B</template>\n<wbr>");
        assert_eq!(chunks[2].1, "<template for=\"c\">C</template>\n<wbr>");
        assert_eq!(chunks[3].1, "<template for=\"a\">A</template>\n<wbr>");

        let spread = chunks[3].0.checked_sub(chunks[1].0).unwrap();
        assert!(
            spread >= Duration::from_millis(400),
            "fragment chunks must arrive spread out over time, got {spread:?}"
        );
    }
}
