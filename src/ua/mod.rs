//! User Agent (UA) parser and types.
//!
//! This module provides a parser (`"...".parse::<UserAgent>()`) for User Agents
//! as well as a classifier ([`UserAgentClassifierLayer`]) that can be used to
//! classify incoming requests based on their [User Agent (header)](crate::http::headers::UserAgent).
//!
//! Learn more about User Agents (UA) and why Rama supports it
//! at <https://ramaproxy.org/book/intro/user_agent.html>.
//!
//! # Remarks
//!
//! We classify only the majority User Agents, and we do not classify all User Agents:
//!
//! - All _Chromium_ User Agents are classified as [`UserAgentKind::Chromium`] (including _Google Chrome_);
//! - All _Firefox_ User Agents are classified as [`UserAgentKind::Firefox`];
//! - All _Safari_ User Agents are classified as [`UserAgentKind::Safari`];
//!
//! The only platforms recognised are `Windows`, `MacOS`, `Linux`, `Android`, and `iOS`.
//!
//! User Agent versions are parsed only their most significant version number (major),
//! we do not parse the version for platforms as these are no longer advertised in contemporary User Agents.
//!
//! Please open an [issue](https://github.com/plabayo/rama/issues) in case you need support for more User Agents,
//! and have a good case to make for it. For example we might also support the default user agents used by mobile
//! application SDKs. This makes however only sense if we can provide Http and Tls emulation for it.
//!
//! # Example
//!
//! ```
//! use rama::{
//!     http::{client::HttpClientExt, IntoResponse, Request, Response, StatusCode},
//!     service::{Context, ServiceBuilder},
//!     ua::{PlatformKind, UserAgent, UserAgentClassifierLayer, UserAgentKind, UserAgentInfo},
//! };
//! use std::convert::Infallible;
//!
//! const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.67";
//!
//! async fn handle<S>(ctx: Context<S>, _req: Request) -> Result<Response, Infallible> {
//!     let ua: &UserAgent = ctx.get().unwrap();
//!
//!     assert_eq!(ua.header_str(), UA);
//!     assert_eq!(ua.info(), Some(UserAgentInfo{ kind: UserAgentKind::Chromium, version: Some(124) }));
//!     assert_eq!(ua.platform(), Some(PlatformKind::Windows));
//!
//!     Ok(StatusCode::OK.into_response())
//! }
//!
//! # #[tokio::main]
//! # async fn main() {
//! let service = ServiceBuilder::new()
//!     .layer(UserAgentClassifierLayer::new())
//!     .service_fn(handle);
//!
//! let _ = service
//!     .get("http://www.example.com")
//!     .typed_header(headers::UserAgent::from_static(UA))
//!     .send(Context::default())
//!     .await
//!     .unwrap();
//! # }
//! ```

mod info;
pub use info::{
    DeviceKind, HttpAgent, PlatformKind, TlsAgent, UserAgent, UserAgentInfo, UserAgentKind,
};

mod parse;
use parse::parse_http_user_agent_header;

mod layer;
pub use layer::{UserAgentClassifier, UserAgentClassifierLayer, UserAgentOverwrites};

#[cfg(test)]
mod parse_tests;
