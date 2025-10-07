use std::convert::Infallible;

use crate::Service;

impl<Request> Service<Request> for ()
where
    Request: Send + 'static,
{
    type Error = Infallible;
    type Response = Request;

    async fn serve(&self, req: Request) -> Result<Request, Self::Error> {
        Ok(req)
    }
}
