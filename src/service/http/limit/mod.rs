//! Middleware for limiting requests in one way or another.
//!
//! Examples include rate limit on host and/or path,
//! as well as rate limit based on anythng else in the request.
//!
//! Other forms of limiting are limits in how many bytes a
//! request body is allowed to contain.

pub use tower_async_http::limit::{RequestBodyLimit, RequestBodyLimitLayer, ResponseBody};

mod rate;
