use super::BytesRejection;
use crate::dep::http_body_util::BodyExt;
use crate::service::web::extract::FromRequest;
use crate::utils::macros::{composite_http_rejection, define_http_rejection};
use crate::Request;
use bytes::Buf;
use csv::{self, StringRecord};
use serde_json::json;

pub use crate::response::Csv;

define_http_rejection! {
    #[status = UNSUPPORTED_MEDIA_TYPE]
    #[body = "Csv requests must have `Content-Type: text/csv`"]
    /// Rejection type for [`Csv`]
    /// used if the `Content-Type` header is missing
    /// or its value is not `text/csv`.
    pub struct InvalidCsvContentType;
}

define_http_rejection! {
    #[status = BAD_REQUEST]
    #[body = "Failed to deserialize csv payload"]
    /// Rejection type used if the [`Csv`]
    /// deserialize the payload into the target type.
    pub struct FailedToDeserializeCsv(Error);
}

composite_http_rejection! {
    /// Rejection used for [`Json`]
    ///
    /// Contains one variant for each way the [`Csv`] extractor
    /// can fail.
    pub enum CsvRejection {
        InvalidCsvContentType,
        FailedToDeserializeCsv,
        BytesRejection,
    }
}

impl<T> FromRequest for Csv<T>
where
    T: serde::de::DeserializeOwned + Send + Sync + 'static + std::fmt::Debug,
{
    type Rejection = CsvRejection;

    async fn from_request(req: Request) -> Result<Self, Self::Rejection> {
        if !crate::service::web::extract::has_any_content_type(req.headers(), &[&mime::TEXT_CSV]) {
            return Err(InvalidCsvContentType.into());
        }

        let body = req.into_body();
        match body.collect().await {
            Ok(c) => {
                let b = c.to_bytes();

                println!("from_request {:?}", b);

                let mut rdr = csv::Reader::from_reader(b.clone().reader());
                println!("rdr {:?}", rdr.headers());
                // let headers = rdr.headers();
                let mut out = vec![];
                for result in rdr.deserialize() {
                    let record: Result<T, _> = result;
                    match record {
                        Ok(r) => out.push(r),
                        Err(err) => return Err(FailedToDeserializeCsv::from_err(err).into()),
                    }
                }
                println!("out: {:?}\n", out);
                let out = out.pop().unwrap();
                Ok(Self(out))
                // match serde_json::from_slice(&b) {
                //     Ok(s) => Ok(Self(s)),
                //     Err(err) => Err(FailedToDeserializeCsv::from_err(err).into()),
                // }
            }
            Err(err) => Err(BytesRejection::from_err(err).into()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::service::web::WebService;
    use crate::StatusCode;
    use rama_core::{Context, Service};

    #[tokio::test]
    async fn test_csv() {
        #[derive(Debug, serde::Deserialize)]
        struct Input {
            name: String,
            age: u8,
            alive: Option<bool>,
        }

        let service = WebService::default().post("/", |Csv(body): Csv<Input>| async move {
            println!("in test {:?}", body);
            // body should be like Vec<Input>
            assert_eq!(body.name, "glen");
            assert_eq!(body.age, 42);
            assert_eq!(body.alive, None);
            StatusCode::IM_A_TEAPOT
        });

        let req = http::Request::builder()
            .method(http::Method::POST)
            .header(http::header::CONTENT_TYPE, "text/csv; charset=utf-8")
            .body("name,age,alive\nglen,42,".into())
            .unwrap();
        let resp = service.serve(Context::default(), req).await.unwrap();
        println!("debug {:?}", resp);
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // #[tokio::test]
    // #[ignore]
    // async fn test_json_missing_content_type() {
    //     #[derive(Debug, serde::Deserialize)]
    //     struct Input {
    //         _name: String,
    //         _age: u8,
    //         _alive: Option<bool>,
    //     }
    //
    //     let service =
    //         WebService::default().post("/", |Csv(_): Csv<Input>| async move { StatusCode::OK });
    //
    //     let req = http::Request::builder()
    //         .method(http::Method::POST)
    //         .header(http::header::CONTENT_TYPE, "text/plain")
    //         .body(r#"{"name": "glen", "age": 42}"#.into())
    //         .unwrap();
    //     let resp = service.serve(Context::default(), req).await.unwrap();
    //     assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    // }
    //
    // #[tokio::test]
    // #[ignore]
    // async fn test_json_invalid_body_encoding() {
    //     #[derive(Debug, serde::Deserialize)]
    //     struct Input {
    //         _name: String,
    //         _age: u8,
    //         _alive: Option<bool>,
    //     }
    //
    //     let service =
    //         WebService::default().post("/", |Csv(_): Csv<Input>| async move { StatusCode::OK });
    //
    //     let req = http::Request::builder()
    //         .method(http::Method::POST)
    //         .header(http::header::CONTENT_TYPE, "text/csv; charset=utf-8")
    //         .body(r#"deal with it, or not?!"#.into())
    //         .unwrap();
    //     let resp = service.serve(Context::default(), req).await.unwrap();
    //     assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    // }
}
