use super::FromRequest;
use crate::Request;
use std::convert::Infallible;

impl FromRequest for Request {
    type Rejection = Infallible;

    async fn from_request(req: Request) -> Result<Self, Self::Rejection> {
        Ok(req)
    }
}
