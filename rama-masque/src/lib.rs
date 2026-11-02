//! MASQUE support for rama: proxying traffic other than TCP through HTTP.
//!
//! It implements UDP proxying ([RFC 9298], CONNECT-UDP) and IP proxying
//! ([RFC 9484], CONNECT-IP). [`connect_ip`] exposes packet/control sessions and
//! explicit forwarding policy using `rama_net::ip`, without host interface changes.
//! CONNECT-UDP runs over every HTTP version: HTTP/1.1 upgrades a `GET` request,
//! HTTP/2 and HTTP/3 use Extended CONNECT. UDP payloads travel as HTTP Datagrams,
//! in QUIC DATAGRAM frames on HTTP/3 when both peers support them and in
//! DATAGRAM capsules otherwise. This crate owns the tunnel semantics (targets,
//! URI templates, Context IDs, target policy), the proxy service, the client
//! connector and the tunnel socket; Capsules, HTTP Datagrams and Extended CONNECT
//! live in the rama HTTP crates and sockets in `rama-udp`.
//!
//! [RFC 9484]: https://www.rfc-editor.org/rfc/rfc9484.html
//! [RFC 9298]: https://datatracker.ietf.org/doc/html/rfc9298
//!
//! # Rama
//!
//! Crate used by the end-user `rama` crate and `rama` crate authors alike.
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod connect_ip;
pub mod connect_udp;

/// Shared rates and principal budgets.
pub mod budget;

pub mod limits;

pub mod context;

mod time;

mod refusal;
