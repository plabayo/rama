use crate::BoxError;

pub type ServeResult = Result<(), BoxError>;

pub use crate::http::Response;
pub type Request = crate::http::Request<HyperBody>;

mod service;
pub use service::HttpServer;

mod executor;
pub use executor::GlobalExecutor;

mod io;
pub use io::HyperIo;

mod hyper_conn;

mod hyper_body;
pub use hyper_body::Body as HyperBody;
