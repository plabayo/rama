//! Type-safe HTML templating support.
//!
//! Enabled via the `html` feature. The core idea: every HTML5 element gets
//! its own proc-macro (`html!`, `body!`, `div!`, ...) that constructs a
//! type implementing both [`IntoHtml`] (for composition) and
//! [`IntoResponse`](crate::service::web::response::IntoResponse) (so the
//! result can be returned directly from a web handler). For runtime tag
//! names — typically [web components] — see the [`custom!`] macro.
//!
//! ```ignore
//! use rama_http::html::*;
//! use rama_http::service::web::response::IntoResponse;
//!
//! async fn handler() -> impl IntoResponse {
//!     html!(
//!         head!(title!("Hi")),
//!         body!(
//!             h1!("Hello, ", "world!"),
//!             custom!("my-icon", name = "smile"),
//!         ),
//!     )
//! }
//! ```
//!
//! `<html>` is always the document root, so [`html!`] automatically
//! prepends `<!DOCTYPE html>` to its output — i.e. `html!(...)` returns
//! a complete page that can be returned from a handler as-is. If you
//! really need a bare `<html>` element without the doctype, use
//! `custom!("html", ...)`.
//!
//! ## What gets escaped, what does not
//!
//! Anything spliced in via an expression (`{name}`, `self.value`, etc.)
//! goes through HTML escaping by virtue of [`IntoHtml`]. The static parts
//! emitted by the macros themselves are wrapped in [`PreEscaped`] and
//! written verbatim. If you have *trusted* HTML you want to splice in
//! raw — e.g. an SVG icon or a pre-rendered fragment — wrap it in
//! `PreEscaped(...)` yourself.
//!
//! ## Custom (user-defined) types
//!
//! Implementing [`IntoHtml`] on your own type lets it participate in
//! templates just like the built-in scalars. For composite types, simply
//! return another [`IntoHtml`] from `into_html`; for "leaf" types, return
//! `self` and override `escape_and_write`.
//!
//! This is the main path for adding type-safe support for custom HTML
//! shapes — e.g. components with strongly-typed required attributes —
//! built on top of the macro layer:
//!
//! ```ignore
//! use rama_http::html::*;
//!
//! struct UserIcon { user_id: u64, size: IconSize }
//! enum IconSize { Sm, Md, Lg }
//!
//! impl IntoHtml for UserIcon {
//!     fn into_html(self) -> impl IntoHtml {
//!         let size = match self.size { IconSize::Sm => "sm", IconSize::Md => "md", IconSize::Lg => "lg" };
//!         custom!("user-icon", "data-user-id" = self.user_id, size = size)
//!     }
//! }
//! ```
//!
//! [web components]: https://developer.mozilla.org/en-US/docs/Web/API/Web_components
//! [`custom!`]: rama_http_macros::custom

mod core;
mod either_impls;
mod rama_impls;
mod response;

#[doc(inline)]
pub use self::core::{IntoHtml, PreEscaped, escape, escape_into};
#[doc(inline)]
pub use self::response::HtmlBuf;

// Re-exported so the proc-macros emitted by `rama-http-macros` can refer
// to them via a single root path (`rama_http::html::Either{,3..9}`),
// without depending on the user knowing where `rama-core` lives.
//
// In practice the user normally only encounters these via `if`/`else if`
// chains inside element macros — the Either chain is generated for them.
#[doc(inline)]
pub use rama_core::combinators::{
    Either, Either3, Either4, Either5, Either6, Either7, Either8, Either9,
};

#[doc(inline)]
pub use rama_http_macros::custom;

// One re-exported proc-macro per known HTML5 element.
//
// Kept in alphabetical order to match the canonical list at MDN
// (<https://developer.mozilla.org/en-US/docs/Web/HTML/Element>).
#[doc(inline)]
pub use rama_http_macros::{
    a, abbr, address, area, article, aside, audio, b, base, bdi, bdo, blockquote, body, br, button,
    canvas, caption, cite, code, col, colgroup, data, datalist, dd, del, details, dfn, dialog, div,
    dl, dt, em, embed, fieldset, figcaption, figure, footer, form, h1, h2, h3, h4, h5, h6, head,
    header, hgroup, hr, html, i, iframe, img, input, ins, kbd, label, legend, li, link, main, map,
    mark, menu, meta, meter, nav, noscript, object, ol, optgroup, option, output, p, param,
    picture, pre, progress, q, rp, rt, ruby, s, samp, script, search, section, select, small,
    source, span, strong, style, sub, summary, sup, svg, table, tbody, td, template, textarea,
    tfoot, th, thead, time, title, tr, track, u, ul, var, video, wbr,
};

#[cfg(test)]
mod tests;
