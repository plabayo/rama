//! [`service::Matcher]s implementations to match on [`http::Request`]s.
//!
//! See [`service::matcher` module] for more information.
//!
//! [`service::Matcher`]: crate::service::Matcher
//! [`http::Request`]: crate::http::Request
//! [`service::matcher` module]: crate::service::matcher

mod method;
pub use method::MethodFilter;

mod domain;
pub use domain::DomainFilter;

pub mod uri;
pub use uri::UriFilter;

mod path;
pub use path::{PathFilter, UriParams, UriParamsDeserializeError};
