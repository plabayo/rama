mod request;
pub use request::{RequestVersionAdapter, RequestVersionAdapterLayer, adapt_request_version};

mod response;
pub use response::{ResponseVersionAdapter, ResponseVersionAdapterLayer, adapt_response_version};
