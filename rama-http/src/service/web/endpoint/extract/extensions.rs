use super::FromRequest;
use crate::Request;
use rama_core::extensions::Extensions;
use std::convert::Infallible;

impl FromRequest for Extensions {
    type Rejection = Infallible;

    async fn from_request(req: Request) -> Result<Self, Self::Rejection> {
        Ok(req.into_parts().0.extensions)
    }
}
