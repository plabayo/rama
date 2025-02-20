use super::BytesRejection;
use crate::Request;
use crate::dep::http_body_util::BodyExt;
use crate::service::web::extract::FromRequest;
use crate::utils::macros::{composite_http_rejection, define_http_rejection};
use bytes::Buf;

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
    /// Rejection used for [`Csv`]
    ///
    /// Contains one variant for each way the [`Csv`] extractor
    /// can fail.
    pub enum CsvRejection {
        InvalidCsvContentType,
        FailedToDeserializeCsv,
        BytesRejection,
    }
}

impl<T> FromRequest for Csv<Vec<T>>
where
    T: serde::de::DeserializeOwned + Send + Sync + 'static,
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
                let mut rdr = csv::Reader::from_reader(b.clone().reader());

                let out: Result<Vec<T>, _> = rdr
                    .deserialize()
                    .map(|rec| {
                        let record: Result<T, _> = rec;
                        record
                    })
                    .collect();

                match out {
                    Ok(s) => Ok(Self(s)),
                    Err(err) => Err(FailedToDeserializeCsv::from_err(err).into()),
                }
            }
            Err(err) => Err(BytesRejection::from_err(err).into()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::StatusCode;
    use crate::service::web::WebService;
    use rama_core::{Context, Service};

    #[tokio::test]
    async fn test_csv() {
        #[derive(serde::Deserialize)]
        struct Input {
            name: String,
            age: u8,
            alive: Option<bool>,
        }

        let service = WebService::default().post("/", |Csv(body): Csv<Vec<Input>>| async move {
            assert_eq!(body.len(), 2);

            assert_eq!(body[0].name, "glen");
            assert_eq!(body[0].age, 42);
            assert_eq!(body[0].alive, None);

            assert_eq!(body[1].name, "adr");
            assert_eq!(body[1].age, 40);
            assert_eq!(body[1].alive, Some(true));
            StatusCode::OK
        });

        let req = http::Request::builder()
            .method(http::Method::POST)
            .header(http::header::CONTENT_TYPE, "text/csv; charset=utf-8")
            .body("name,age,alive\nglen,42,\nadr,40,true\n".into())
            .unwrap();
        let resp = service.serve(Context::default(), req).await.unwrap();
        println!("debug {:?}", resp);
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_csv_missing_content_type() {
        #[derive(Debug, serde::Deserialize)]
        struct Input {
            _name: String,
            _age: u8,
            _alive: Option<bool>,
        }

        let service = WebService::default()
            .post("/", |Csv(_): Csv<Vec<Input>>| async move { StatusCode::OK });

        let req = http::Request::builder()
            .method(http::Method::POST)
            .header(http::header::CONTENT_TYPE, "text/plain")
            .body(r#"{"name": "glen", "age": 42}"#.into())
            .unwrap();
        let resp = service.serve(Context::default(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn test_csv_invalid_body() {
        #[derive(Debug, serde::Deserialize)]
        struct Input {
            _name: String,
            _age: u8,
            _alive: Option<bool>,
        }

        let service = WebService::default()
            .post("/", |Csv(_): Csv<Vec<Input>>| async move { StatusCode::OK });

        let req = http::Request::builder()
            .method(http::Method::POST)
            .header(http::header::CONTENT_TYPE, "text/csv; charset=utf-8")
            // the missing column last line should trigger an error
            .body("name,age,alive\nglen,42,\nadr,40\n".into())
            .unwrap();
        let resp = service.serve(Context::default(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
