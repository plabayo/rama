mod request;
pub use request::{
    RequestVersionAdapter, RequestVersionAdapterLayer, adapt_request_version,
    ensure_h1_host_header, ensure_h2_or_h3_uri_authority, ensure_valid_h1_request,
    ensure_valid_h2_or_h3_request, ensure_valid_request_for_version,
};

mod response;
pub use response::{
    ResponseVersionAdaptCtx, ResponseVersionAdapter, ResponseVersionAdapterLayer,
    adapt_response_version,
};
