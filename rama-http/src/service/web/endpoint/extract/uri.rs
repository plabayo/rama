use std::convert::Infallible;

use super::FromRequest;
use crate::Uri;

impl FromRequest for Uri {
    type Rejection = Infallible;

    async fn from_request(req: crate::Request) -> Result<Self, Self::Rejection> {
        Ok(req.into_parts().0.uri)
    }
}
