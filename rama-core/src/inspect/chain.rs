use crate::error::BoxError;
use crate::{Context, Service};

use super::RequestInspector;

impl<I1, RequestIn> Service<RequestIn> for (I1,)
where
    I1: RequestInspector<RequestIn, Error: Into<BoxError>>,
    RequestIn: Send + 'static,
{
    type Error = BoxError;
    type Response = (Context, I1::RequestOut);

    async fn serve(&self, ctx: Context, req: RequestIn) -> Result<Self::Response, Self::Error> {
        self.0.inspect_request(ctx, req).await.map_err(Into::into)
    }
}

impl<I1, I2, RequestIn> Service<RequestIn> for (I1, I2)
where
    I1: RequestInspector<RequestIn, Error: Into<BoxError>>,
    I2: RequestInspector<I1::RequestOut, Error: Into<BoxError>>,
    RequestIn: Send + 'static,
{
    type Error = BoxError;
    type Response = (Context, I2::RequestOut);

    async fn serve(&self, ctx: Context, req: RequestIn) -> Result<Self::Response, Self::Error> {
        let (ctx, req) = self.0.inspect_request(ctx, req).await.map_err(Into::into)?;
        self.1.inspect_request(ctx, req).await.map_err(Into::into)
    }
}

impl<I1, I2, I3, RequestIn> Service<RequestIn> for (I1, I2, I3)
where
    I1: RequestInspector<RequestIn, Error: Into<BoxError>>,
    I2: RequestInspector<I1::RequestOut, Error: Into<BoxError>>,
    I3: RequestInspector<I2::RequestOut, Error: Into<BoxError>>,
    RequestIn: Send + 'static,
{
    type Error = BoxError;
    type Response = (Context, I3::RequestOut);

    async fn serve(&self, ctx: Context, req: RequestIn) -> Result<Self::Response, Self::Error> {
        let (ctx, req) = self.0.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.1.inspect_request(ctx, req).await.map_err(Into::into)?;
        self.2.inspect_request(ctx, req).await.map_err(Into::into)
    }
}

impl<I1, I2, I3, I4, RequestIn> Service<RequestIn> for (I1, I2, I3, I4)
where
    I1: RequestInspector<RequestIn, Error: Into<BoxError>>,
    I2: RequestInspector<I1::RequestOut, Error: Into<BoxError>>,
    I3: RequestInspector<I2::RequestOut, Error: Into<BoxError>>,
    I4: RequestInspector<I3::RequestOut, Error: Into<BoxError>>,
    RequestIn: Send + 'static,
{
    type Error = BoxError;
    type Response = (Context, I4::RequestOut);

    async fn serve(&self, ctx: Context, req: RequestIn) -> Result<Self::Response, Self::Error> {
        let (ctx, req) = self.0.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.1.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.2.inspect_request(ctx, req).await.map_err(Into::into)?;
        self.3.inspect_request(ctx, req).await.map_err(Into::into)
    }
}

impl<I1, I2, I3, I4, I5, RequestIn> Service<RequestIn> for (I1, I2, I3, I4, I5)
where
    I1: RequestInspector<RequestIn, Error: Into<BoxError>>,
    I2: RequestInspector<I1::RequestOut, Error: Into<BoxError>>,
    I3: RequestInspector<I2::RequestOut, Error: Into<BoxError>>,
    I4: RequestInspector<I3::RequestOut, Error: Into<BoxError>>,
    I5: RequestInspector<I4::RequestOut, Error: Into<BoxError>>,
    RequestIn: Send + 'static,
{
    type Error = BoxError;
    type Response = (Context, I5::RequestOut);

    async fn serve(&self, ctx: Context, req: RequestIn) -> Result<Self::Response, Self::Error> {
        let (ctx, req) = self.0.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.1.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.2.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.3.inspect_request(ctx, req).await.map_err(Into::into)?;
        self.4.inspect_request(ctx, req).await.map_err(Into::into)
    }
}

impl<I1, I2, I3, I4, I5, I6, RequestIn> Service<RequestIn> for (I1, I2, I3, I4, I5, I6)
where
    I1: RequestInspector<RequestIn, Error: Into<BoxError>>,
    I2: RequestInspector<I1::RequestOut, Error: Into<BoxError>>,
    I3: RequestInspector<I2::RequestOut, Error: Into<BoxError>>,
    I4: RequestInspector<I3::RequestOut, Error: Into<BoxError>>,
    I5: RequestInspector<I4::RequestOut, Error: Into<BoxError>>,
    I6: RequestInspector<I5::RequestOut, Error: Into<BoxError>>,
    RequestIn: Send + 'static,
{
    type Error = BoxError;
    type Response = (Context, I6::RequestOut);

    async fn serve(&self, ctx: Context, req: RequestIn) -> Result<Self::Response, Self::Error> {
        let (ctx, req) = self.0.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.1.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.2.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.3.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.4.inspect_request(ctx, req).await.map_err(Into::into)?;
        self.5.inspect_request(ctx, req).await.map_err(Into::into)
    }
}

impl<I1, I2, I3, I4, I5, I6, I7, RequestIn> Service<RequestIn> for (I1, I2, I3, I4, I5, I6, I7)
where
    I1: RequestInspector<RequestIn, Error: Into<BoxError>>,
    I2: RequestInspector<I1::RequestOut, Error: Into<BoxError>>,
    I3: RequestInspector<I2::RequestOut, Error: Into<BoxError>>,
    I4: RequestInspector<I3::RequestOut, Error: Into<BoxError>>,
    I5: RequestInspector<I4::RequestOut, Error: Into<BoxError>>,
    I6: RequestInspector<I5::RequestOut, Error: Into<BoxError>>,
    I7: RequestInspector<I6::RequestOut, Error: Into<BoxError>>,
    RequestIn: Send + 'static,
{
    type Error = BoxError;
    type Response = (Context, I7::RequestOut);

    async fn serve(&self, ctx: Context, req: RequestIn) -> Result<Self::Response, Self::Error> {
        let (ctx, req) = self.0.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.1.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.2.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.3.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.4.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.5.inspect_request(ctx, req).await.map_err(Into::into)?;
        self.6.inspect_request(ctx, req).await.map_err(Into::into)
    }
}

impl<I1, I2, I3, I4, I5, I6, I7, I8, RequestIn> Service<RequestIn>
    for (I1, I2, I3, I4, I5, I6, I7, I8)
where
    I1: RequestInspector<RequestIn, Error: Into<BoxError>>,
    I2: RequestInspector<I1::RequestOut, Error: Into<BoxError>>,
    I3: RequestInspector<I2::RequestOut, Error: Into<BoxError>>,
    I4: RequestInspector<I3::RequestOut, Error: Into<BoxError>>,
    I5: RequestInspector<I4::RequestOut, Error: Into<BoxError>>,
    I6: RequestInspector<I5::RequestOut, Error: Into<BoxError>>,
    I7: RequestInspector<I6::RequestOut, Error: Into<BoxError>>,
    I8: RequestInspector<I7::RequestOut, Error: Into<BoxError>>,
    RequestIn: Send + 'static,
{
    type Error = BoxError;
    type Response = (Context, I8::RequestOut);

    async fn serve(&self, ctx: Context, req: RequestIn) -> Result<Self::Response, Self::Error> {
        let (ctx, req) = self.0.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.1.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.2.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.3.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.4.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.5.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.6.inspect_request(ctx, req).await.map_err(Into::into)?;
        self.7.inspect_request(ctx, req).await.map_err(Into::into)
    }
}

impl<I1, I2, I3, I4, I5, I6, I7, I8, I9, RequestIn> Service<RequestIn>
    for (I1, I2, I3, I4, I5, I6, I7, I8, I9)
where
    I1: RequestInspector<RequestIn, Error: Into<BoxError>>,
    I2: RequestInspector<I1::RequestOut, Error: Into<BoxError>>,
    I3: RequestInspector<I2::RequestOut, Error: Into<BoxError>>,
    I4: RequestInspector<I3::RequestOut, Error: Into<BoxError>>,
    I5: RequestInspector<I4::RequestOut, Error: Into<BoxError>>,
    I6: RequestInspector<I5::RequestOut, Error: Into<BoxError>>,
    I7: RequestInspector<I6::RequestOut, Error: Into<BoxError>>,
    I8: RequestInspector<I7::RequestOut, Error: Into<BoxError>>,
    I9: RequestInspector<I8::RequestOut, Error: Into<BoxError>>,
    RequestIn: Send + 'static,
{
    type Error = BoxError;
    type Response = (Context, I9::RequestOut);

    async fn serve(&self, ctx: Context, req: RequestIn) -> Result<Self::Response, Self::Error> {
        let (ctx, req) = self.0.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.1.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.2.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.3.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.4.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.5.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.6.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.7.inspect_request(ctx, req).await.map_err(Into::into)?;
        self.8.inspect_request(ctx, req).await.map_err(Into::into)
    }
}

impl<I1, I2, I3, I4, I5, I6, I7, I8, I9, I10, RequestIn> Service<RequestIn>
    for (I1, I2, I3, I4, I5, I6, I7, I8, I9, I10)
where
    I1: RequestInspector<RequestIn, Error: Into<BoxError>>,
    I2: RequestInspector<I1::RequestOut, Error: Into<BoxError>>,
    I3: RequestInspector<I2::RequestOut, Error: Into<BoxError>>,
    I4: RequestInspector<I3::RequestOut, Error: Into<BoxError>>,
    I5: RequestInspector<I4::RequestOut, Error: Into<BoxError>>,
    I6: RequestInspector<I5::RequestOut, Error: Into<BoxError>>,
    I7: RequestInspector<I6::RequestOut, Error: Into<BoxError>>,
    I8: RequestInspector<I7::RequestOut, Error: Into<BoxError>>,
    I9: RequestInspector<I8::RequestOut, Error: Into<BoxError>>,
    I10: RequestInspector<I9::RequestOut, Error: Into<BoxError>>,
    RequestIn: Send + 'static,
{
    type Error = BoxError;
    type Response = (Context, I10::RequestOut);

    async fn serve(&self, ctx: Context, req: RequestIn) -> Result<Self::Response, Self::Error> {
        let (ctx, req) = self.0.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.1.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.2.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.3.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.4.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.5.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.6.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.7.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.8.inspect_request(ctx, req).await.map_err(Into::into)?;
        self.9.inspect_request(ctx, req).await.map_err(Into::into)
    }
}

impl<I1, I2, I3, I4, I5, I6, I7, I8, I9, I10, I11, RequestIn> Service<RequestIn>
    for (I1, I2, I3, I4, I5, I6, I7, I8, I9, I10, I11)
where
    I1: RequestInspector<RequestIn, Error: Into<BoxError>>,
    I2: RequestInspector<I1::RequestOut, Error: Into<BoxError>>,
    I3: RequestInspector<I2::RequestOut, Error: Into<BoxError>>,
    I4: RequestInspector<I3::RequestOut, Error: Into<BoxError>>,
    I5: RequestInspector<I4::RequestOut, Error: Into<BoxError>>,
    I6: RequestInspector<I5::RequestOut, Error: Into<BoxError>>,
    I7: RequestInspector<I6::RequestOut, Error: Into<BoxError>>,
    I8: RequestInspector<I7::RequestOut, Error: Into<BoxError>>,
    I9: RequestInspector<I8::RequestOut, Error: Into<BoxError>>,
    I10: RequestInspector<I9::RequestOut, Error: Into<BoxError>>,
    I11: RequestInspector<I10::RequestOut, Error: Into<BoxError>>,
    RequestIn: Send + 'static,
{
    type Error = BoxError;
    type Response = (Context, I11::RequestOut);

    async fn serve(&self, ctx: Context, req: RequestIn) -> Result<Self::Response, Self::Error> {
        let (ctx, req) = self.0.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.1.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.2.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.3.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.4.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.5.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.6.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.7.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.8.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.9.inspect_request(ctx, req).await.map_err(Into::into)?;
        self.10.inspect_request(ctx, req).await.map_err(Into::into)
    }
}

impl<I1, I2, I3, I4, I5, I6, I7, I8, I9, I10, I11, I12, RequestIn> Service<RequestIn>
    for (I1, I2, I3, I4, I5, I6, I7, I8, I9, I10, I11, I12)
where
    I1: RequestInspector<RequestIn, Error: Into<BoxError>>,
    I2: RequestInspector<I1::RequestOut, Error: Into<BoxError>>,
    I3: RequestInspector<I2::RequestOut, Error: Into<BoxError>>,
    I4: RequestInspector<I3::RequestOut, Error: Into<BoxError>>,
    I5: RequestInspector<I4::RequestOut, Error: Into<BoxError>>,
    I6: RequestInspector<I5::RequestOut, Error: Into<BoxError>>,
    I7: RequestInspector<I6::RequestOut, Error: Into<BoxError>>,
    I8: RequestInspector<I7::RequestOut, Error: Into<BoxError>>,
    I9: RequestInspector<I8::RequestOut, Error: Into<BoxError>>,
    I10: RequestInspector<I9::RequestOut, Error: Into<BoxError>>,
    I11: RequestInspector<I10::RequestOut, Error: Into<BoxError>>,
    I12: RequestInspector<I11::RequestOut, Error: Into<BoxError>>,
    RequestIn: Send + 'static,
{
    type Error = BoxError;
    type Response = (Context, I12::RequestOut);

    async fn serve(&self, ctx: Context, req: RequestIn) -> Result<Self::Response, Self::Error> {
        let (ctx, req) = self.0.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.1.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.2.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.3.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.4.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.5.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.6.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.7.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.8.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.9.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self
            .10
            .inspect_request(ctx, req)
            .await
            .map_err(Into::into)?;
        self.11.inspect_request(ctx, req).await.map_err(Into::into)
    }
}
