//! Middleware to support the reading and writing of Forwarded headers.

use crate::Version;
use rama_net::forwarded::ForwardedVersion;

mod get_forwarded;
#[doc(inline)]
pub use get_forwarded::{GetForwardedHeaderLayer, GetForwardedHeaderService};

mod get_forwarded_multi;
#[doc(inline)]
pub use get_forwarded_multi::{GetForwardedHeadersLayer, GetForwardedHeadersService};

mod set_forwarded;
#[doc(inline)]
pub use set_forwarded::{SetForwardedHeaderLayer, SetForwardedHeaderService};

mod set_forwarded_multi;
#[doc(inline)]
pub use set_forwarded_multi::{SetForwardedHeadersLayer, SetForwardedHeadersService};

fn forwarded_version(version: Version) -> ForwardedVersion {
    match version {
        Version::HTTP_09 => ForwardedVersion::HTTP_09,
        Version::HTTP_10 => ForwardedVersion::HTTP_10,
        Version::HTTP_11 => ForwardedVersion::HTTP_11,
        Version::HTTP_2 => ForwardedVersion::HTTP_2,
        Version::HTTP_3 => ForwardedVersion::HTTP_3,
    }
}

#[cfg(test)]
mod version_tests {
    use super::*;
    use crate::{Request, Version, headers::forwarded::Via};
    use core::convert::Infallible;
    use rama_core::{Layer, Service, service::service_fn};

    #[tokio::test]
    async fn via_reports_received_version_for_single_and_multi_header_layers() {
        for (version, expected) in [
            (Version::HTTP_10, "1.0 rama"),
            (Version::HTTP_11, "1.1 rama"),
            (Version::HTTP_2, "2 rama"),
            (Version::HTTP_3, "3 rama"),
        ] {
            let sink = service_fn(async |req: Request<()>| Ok::<_, Infallible>(req));
            let single = SetForwardedHeaderLayer::via().into_layer(sink.clone());
            let multi = SetForwardedHeadersLayer::<(Via,)>::new().into_layer(sink);
            for req in [
                single
                    .serve(
                        Request::builder()
                            .uri("https://example.com/")
                            .version(version)
                            .body(())
                            .unwrap(),
                    )
                    .await
                    .unwrap(),
                multi
                    .serve(
                        Request::builder()
                            .uri("https://example.com/")
                            .version(version)
                            .body(())
                            .unwrap(),
                    )
                    .await
                    .unwrap(),
            ] {
                assert_eq!(req.headers()["via"], expected);
            }
        }
    }
}
