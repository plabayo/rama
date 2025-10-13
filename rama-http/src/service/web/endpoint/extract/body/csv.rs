use super::BytesRejection;
use crate::Request;
use crate::body::util::BodyExt;
use crate::service::web::extract::FromRequest;
use crate::utils::macros::{composite_http_rejection, define_http_rejection};
use rama_core::bytes::{Buf, Bytes};

pub use crate::service::web::endpoint::response::Csv;

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
        // Extracted into separate fn so it's only compiled once for all T.
        async fn req_to_csv_bytes(req: Request) -> Result<Bytes, CsvRejection> {
            if !crate::service::web::extract::has_any_content_type(
                req.headers(),
                &[&crate::mime::TEXT_CSV],
            ) {
                return Err(InvalidCsvContentType.into());
            }

            let body = req.into_body();
            let bytes = body.collect().await.map_err(BytesRejection::from_err)?;

            Ok(bytes.to_bytes())
        }

        let b = req_to_csv_bytes(req).await?;
        let mut rdr = csv::Reader::from_reader(b.reader());

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
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::StatusCode;
    use crate::service::web::WebService;
    use rama_core::Service;

    #[tokio::test]
    async fn test_csv() {
        #[derive(serde::Deserialize)]
        struct Input {
            name: String,
            age: u8,
            alive: Option<bool>,
        }

        let service = WebService::default().post("/", async |Csv(body): Csv<Vec<Input>>| {
            assert_eq!(body.len(), 2);

            assert_eq!(body[0].name, "glen");
            assert_eq!(body[0].age, 42);
            assert_eq!(body[0].alive, None);

            assert_eq!(body[1].name, "adr");
            assert_eq!(body[1].age, 40);
            assert_eq!(body[1].alive, Some(true));
            StatusCode::OK
        });

        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .header(
                rama_http_types::header::CONTENT_TYPE,
                "text/csv; charset=utf-8",
            )
            .body("name,age,alive\nglen,42,\nadr,40,true\n".into())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        println!("debug {resp:?}");
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

        let service =
            WebService::default().post("/", async |Csv(_): Csv<Vec<Input>>| StatusCode::OK);

        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .header(rama_http_types::header::CONTENT_TYPE, "text/plain")
            .body(r#"{"name": "glen", "age": 42}"#.into())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
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

        let service =
            WebService::default().post("/", async |Csv(_): Csv<Vec<Input>>| StatusCode::OK);

        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .header(
                rama_http_types::header::CONTENT_TYPE,
                "text/csv; charset=utf-8",
            )
            // the missing column last line should trigger an error
            .body("name,age,alive\nglen,42,\nadr,40\n".into())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
