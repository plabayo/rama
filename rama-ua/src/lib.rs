//! User Agent (UA) parser and profiles.
//!
//! This crate provides a parser ([`UserAgent::new`]) for User Agents
//! as well as a classifier (`UserAgentClassifierLayer` in `rama_http`) that can be used to
//! classify incoming requests based on their User Agent (header).
//!
//! These can be used to know what UA is connecting to a server,
//! but it can also be used to emulate the UA from a client
//! via the profiles that are found in this crate as well,
//! be it builtin modules or custom ones.
//!
//! Learn more about User Agents (UA) and why Rama supports it
//! at <https://ramaproxy.org/book/intro/user_agent.html>.
//!
//! # Rama
//!
//! Crate used by the end-user `rama` crate and `rama` crate authors alike.
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>
//!
//! # Remarks
//!
//! We classify only the majority User Agents, and we do not classify all User Agents:
//!
//! - All _Chromium_ User Agents are classified as [`UserAgentKind::Chromium`] (including _Google Chrome_);
//! - All _Firefox_ User Agents are classified as [`UserAgentKind::Firefox`];
//! - All _Safari_ User Agents are classified as [`UserAgentKind::Safari`];
//!
//! The only [`Platform`](PlatformKind)s recognised are [`Windows`](PlatformKind::Windows),
//! [`MacOS`](PlatformKind::MacOS), [`Linux`](PlatformKind::Linux),
//! [`Android`](PlatformKind::Android), and [`iOS`](PlatformKind::IOS).
//!
//! User Agent versions are parsed only their most significant version number (e.g. `124` for `Chrome/124.0.0`
//! and `1704` for `Safari Version/17.4`). We do not parse the version for platforms as
//! these are no longer advertised in contemporary User Agents.
//!
//! For UA Classification one can overwrite the [`HttpAgent`] and [`TlsAgent`] advertised by the [`UserAgent`],
//! using the [`UserAgent::with_http_agent`] and [`UserAgent::with_tls_agent`] methods.
//!
//! UA Emulators are advised to interpret the [`UserAgent`] in the following order:
//!
//! 1. first try to find an emulation match using [`UserAgent::header_str`];
//! 2. otherwise try to find an emulation match using [`UserAgent::info`]: where the [`UserAgentKind`] and [`PlatformKind`] should be matched,
//!    and the version should be as close as possible to the version of the [`UserAgent`].
//! 3. otherwise match the [`DeviceKind`] using [`UserAgent::device`].
//! 4. final fallback is to find emulation data for [`DeviceKind::Desktop`].
//!
//! Please open an [issue](https://github.com/plabayo/rama/issues) in case you need support for more User Agents,
//! and have a good case to make for it. For example we might also support the default user agents used by mobile
//! application SDKs. This makes however only sense if we can provide Http and Tls emulation for it.

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(not(test), warn(clippy::print_stdout, clippy::dbg_macro))]

mod ua;
pub use ua::*;

mod profile;
pub use profile::*;

mod emulate;
pub use emulate::*;
