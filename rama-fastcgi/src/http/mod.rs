//! HTTP adaptive layers for FastCGI.
//!
//! Bridges the HTTP and FastCGI worlds in both directions:
//!
//! - **Client side** ([`FastCgiHttpClient`], [`FastCgiHttpClientConnector`]): send
//!   HTTP requests to a FastCGI backend, with automatic CGI environment construction
//!   and CGI stdout parsing.
//!
//! - **Server side** ([`FastCgiHttpService`]): wrap any HTTP
//!   `Service<Request, Output=Response>` as a FastCGI application service, so it can
//!   be deployed behind nginx/Apache without changes.

mod client;
mod convert;
mod service;

pub use client::{FastCgiHttpClient, FastCgiHttpClientConnector};
pub use service::FastCgiHttpService;
