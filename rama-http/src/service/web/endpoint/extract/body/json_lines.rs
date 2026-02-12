use std::convert::Infallible;

use rama_core::stream::json::JsonReadStream;
use rama_http_types::{BodyDataStream, header};

use crate::Request;
use crate::service::web::extract::{FromRequest, OptionalFromRequest};

pub type JsonLines<T> = JsonReadStream<T, BodyDataStream>;

impl<T> FromRequest for JsonLines<T>
where
    T: serde::de::DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = Infallible;

    async fn from_request(req: Request) -> Result<Self, Self::Rejection> {
        Ok(req.into_body().into_json_stream())
    }
}

impl<T> OptionalFromRequest for JsonLines<T>
where
    T: serde::de::DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = Infallible;

    async fn from_request(req: Request) -> Result<Option<Self>, Self::Rejection> {
        if req.headers().get(header::CONTENT_TYPE).is_some() {
            let v = <Self as FromRequest>::from_request(req).await?;
            Ok(Some(v))
        } else {
            Ok(None)
        }
    }
}
#[cfg(test)]
mod tests {
    use crate::service::{client::HttpClientExt as _, web::Router};

    use super::JsonLines;
    use http::StatusCode;
    use rama_core::stream::StreamExt as _;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    struct User {
        id: i32,
    }

    #[tokio::test]
    async fn extractor() {
        let app = Router::new().with_post("/", |mut stream: JsonLines<User>| async move {
            assert_eq!(stream.next().await.unwrap().unwrap(), User { id: 1 });
            assert_eq!(stream.next().await.unwrap().unwrap(), User { id: 2 });
            assert_eq!(stream.next().await.unwrap().unwrap(), User { id: 3 });

            // sources are downcastable to `serde_json::Error`
            let err = stream.next().await.unwrap().unwrap_err();
            let _: &serde_json::Error = err
                .source()
                .unwrap()
                .downcast_ref::<serde_json::Error>()
                .unwrap();
        });

        let res = app
            .post("http://example.com")
            .body(
                [
                    "{\"id\":1}",
                    "{\"id\":2}",
                    "{\"id\":3}",
                    // to trigger an error for source downcasting
                    "{\"id\":false}",
                ]
                .join("\n"),
            )
            .send()
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }
}
