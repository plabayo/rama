use crate::error::BoxError;
use crate::{Context, Service};

use super::RequestInspector;

impl<I1, StateIn, RequestIn> Service<StateIn, RequestIn> for (I1,)
where
    I1: RequestInspector<StateIn, RequestIn, Error: Into<BoxError>>,
    StateIn: Clone + Send + Sync + 'static,
    RequestIn: Send + 'static,
{
    type Error = BoxError;
    type Response = (Context<I1::StateOut>, I1::RequestOut);

    async fn serve(
        &self,
        ctx: Context<StateIn>,
        req: RequestIn,
    ) -> Result<Self::Response, Self::Error> {
        self.0.inspect_request(ctx, req).await.map_err(Into::into)
    }
}

impl<I1, I2, StateIn, RequestIn> Service<StateIn, RequestIn> for (I1, I2)
where
    I1: RequestInspector<StateIn, RequestIn, Error: Into<BoxError>>,
    I2: RequestInspector<I1::StateOut, I1::RequestOut, Error: Into<BoxError>>,
    StateIn: Clone + Send + Sync + 'static,
    RequestIn: Send + 'static,
{
    type Error = BoxError;
    type Response = (Context<I2::StateOut>, I2::RequestOut);

    async fn serve(
        &self,
        ctx: Context<StateIn>,
        req: RequestIn,
    ) -> Result<Self::Response, Self::Error> {
        let (ctx, req) = self.0.inspect_request(ctx, req).await.map_err(Into::into)?;
        self.1.inspect_request(ctx, req).await.map_err(Into::into)
    }
}

impl<I1, I2, I3, StateIn, RequestIn> Service<StateIn, RequestIn> for (I1, I2, I3)
where
    I1: RequestInspector<StateIn, RequestIn, Error: Into<BoxError>>,
    I2: RequestInspector<I1::StateOut, I1::RequestOut, Error: Into<BoxError>>,
    I3: RequestInspector<I2::StateOut, I2::RequestOut, Error: Into<BoxError>>,
    StateIn: Clone + Send + Sync + 'static,
    RequestIn: Send + 'static,
{
    type Error = BoxError;
    type Response = (Context<I3::StateOut>, I3::RequestOut);

    async fn serve(
        &self,
        ctx: Context<StateIn>,
        req: RequestIn,
    ) -> Result<Self::Response, Self::Error> {
        let (ctx, req) = self.0.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.1.inspect_request(ctx, req).await.map_err(Into::into)?;
        self.2.inspect_request(ctx, req).await.map_err(Into::into)
    }
}

impl<I1, I2, I3, I4, StateIn, RequestIn> Service<StateIn, RequestIn> for (I1, I2, I3, I4)
where
    I1: RequestInspector<StateIn, RequestIn, Error: Into<BoxError>>,
    I2: RequestInspector<I1::StateOut, I1::RequestOut, Error: Into<BoxError>>,
    I3: RequestInspector<I2::StateOut, I2::RequestOut, Error: Into<BoxError>>,
    I4: RequestInspector<I3::StateOut, I3::RequestOut, Error: Into<BoxError>>,
    StateIn: Clone + Send + Sync + 'static,
    RequestIn: Send + 'static,
{
    type Error = BoxError;
    type Response = (Context<I4::StateOut>, I4::RequestOut);

    async fn serve(
        &self,
        ctx: Context<StateIn>,
        req: RequestIn,
    ) -> Result<Self::Response, Self::Error> {
        let (ctx, req) = self.0.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.1.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.2.inspect_request(ctx, req).await.map_err(Into::into)?;
        self.3.inspect_request(ctx, req).await.map_err(Into::into)
    }
}

impl<I1, I2, I3, I4, I5, StateIn, RequestIn> Service<StateIn, RequestIn> for (I1, I2, I3, I4, I5)
where
    I1: RequestInspector<StateIn, RequestIn, Error: Into<BoxError>>,
    I2: RequestInspector<I1::StateOut, I1::RequestOut, Error: Into<BoxError>>,
    I3: RequestInspector<I2::StateOut, I2::RequestOut, Error: Into<BoxError>>,
    I4: RequestInspector<I3::StateOut, I3::RequestOut, Error: Into<BoxError>>,
    I5: RequestInspector<I4::StateOut, I4::RequestOut, Error: Into<BoxError>>,
    StateIn: Clone + Send + Sync + 'static,
    RequestIn: Send + 'static,
{
    type Error = BoxError;
    type Response = (Context<I5::StateOut>, I5::RequestOut);

    async fn serve(
        &self,
        ctx: Context<StateIn>,
        req: RequestIn,
    ) -> Result<Self::Response, Self::Error> {
        let (ctx, req) = self.0.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.1.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.2.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.3.inspect_request(ctx, req).await.map_err(Into::into)?;
        self.4.inspect_request(ctx, req).await.map_err(Into::into)
    }
}

impl<I1, I2, I3, I4, I5, I6, StateIn, RequestIn> Service<StateIn, RequestIn>
    for (I1, I2, I3, I4, I5, I6)
where
    I1: RequestInspector<StateIn, RequestIn, Error: Into<BoxError>>,
    I2: RequestInspector<I1::StateOut, I1::RequestOut, Error: Into<BoxError>>,
    I3: RequestInspector<I2::StateOut, I2::RequestOut, Error: Into<BoxError>>,
    I4: RequestInspector<I3::StateOut, I3::RequestOut, Error: Into<BoxError>>,
    I5: RequestInspector<I4::StateOut, I4::RequestOut, Error: Into<BoxError>>,
    I6: RequestInspector<I5::StateOut, I5::RequestOut, Error: Into<BoxError>>,
    StateIn: Clone + Send + Sync + 'static,
    RequestIn: Send + 'static,
{
    type Error = BoxError;
    type Response = (Context<I6::StateOut>, I6::RequestOut);

    async fn serve(
        &self,
        ctx: Context<StateIn>,
        req: RequestIn,
    ) -> Result<Self::Response, Self::Error> {
        let (ctx, req) = self.0.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.1.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.2.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.3.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.4.inspect_request(ctx, req).await.map_err(Into::into)?;
        self.5.inspect_request(ctx, req).await.map_err(Into::into)
    }
}

impl<I1, I2, I3, I4, I5, I6, I7, StateIn, RequestIn> Service<StateIn, RequestIn>
    for (I1, I2, I3, I4, I5, I6, I7)
where
    I1: RequestInspector<StateIn, RequestIn, Error: Into<BoxError>>,
    I2: RequestInspector<I1::StateOut, I1::RequestOut, Error: Into<BoxError>>,
    I3: RequestInspector<I2::StateOut, I2::RequestOut, Error: Into<BoxError>>,
    I4: RequestInspector<I3::StateOut, I3::RequestOut, Error: Into<BoxError>>,
    I5: RequestInspector<I4::StateOut, I4::RequestOut, Error: Into<BoxError>>,
    I6: RequestInspector<I5::StateOut, I5::RequestOut, Error: Into<BoxError>>,
    I7: RequestInspector<I6::StateOut, I6::RequestOut, Error: Into<BoxError>>,
    StateIn: Clone + Send + Sync + 'static,
    RequestIn: Send + 'static,
{
    type Error = BoxError;
    type Response = (Context<I7::StateOut>, I7::RequestOut);

    async fn serve(
        &self,
        ctx: Context<StateIn>,
        req: RequestIn,
    ) -> Result<Self::Response, Self::Error> {
        let (ctx, req) = self.0.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.1.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.2.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.3.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.4.inspect_request(ctx, req).await.map_err(Into::into)?;
        let (ctx, req) = self.5.inspect_request(ctx, req).await.map_err(Into::into)?;
        self.6.inspect_request(ctx, req).await.map_err(Into::into)
    }
}

impl<I1, I2, I3, I4, I5, I6, I7, I8, StateIn, RequestIn> Service<StateIn, RequestIn>
    for (I1, I2, I3, I4, I5, I6, I7, I8)
where
    I1: RequestInspector<StateIn, RequestIn, Error: Into<BoxError>>,
    I2: RequestInspector<I1::StateOut, I1::RequestOut, Error: Into<BoxError>>,
    I3: RequestInspector<I2::StateOut, I2::RequestOut, Error: Into<BoxError>>,
    I4: RequestInspector<I3::StateOut, I3::RequestOut, Error: Into<BoxError>>,
    I5: RequestInspector<I4::StateOut, I4::RequestOut, Error: Into<BoxError>>,
    I6: RequestInspector<I5::StateOut, I5::RequestOut, Error: Into<BoxError>>,
    I7: RequestInspector<I6::StateOut, I6::RequestOut, Error: Into<BoxError>>,
    I8: RequestInspector<I7::StateOut, I7::RequestOut, Error: Into<BoxError>>,
    StateIn: Clone + Send + Sync + 'static,
    RequestIn: Send + 'static,
{
    type Error = BoxError;
    type Response = (Context<I8::StateOut>, I8::RequestOut);

    async fn serve(
        &self,
        ctx: Context<StateIn>,
        req: RequestIn,
    ) -> Result<Self::Response, Self::Error> {
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

impl<I1, I2, I3, I4, I5, I6, I7, I8, I9, StateIn, RequestIn> Service<StateIn, RequestIn>
    for (I1, I2, I3, I4, I5, I6, I7, I8, I9)
where
    I1: RequestInspector<StateIn, RequestIn, Error: Into<BoxError>>,
    I2: RequestInspector<I1::StateOut, I1::RequestOut, Error: Into<BoxError>>,
    I3: RequestInspector<I2::StateOut, I2::RequestOut, Error: Into<BoxError>>,
    I4: RequestInspector<I3::StateOut, I3::RequestOut, Error: Into<BoxError>>,
    I5: RequestInspector<I4::StateOut, I4::RequestOut, Error: Into<BoxError>>,
    I6: RequestInspector<I5::StateOut, I5::RequestOut, Error: Into<BoxError>>,
    I7: RequestInspector<I6::StateOut, I6::RequestOut, Error: Into<BoxError>>,
    I8: RequestInspector<I7::StateOut, I7::RequestOut, Error: Into<BoxError>>,
    I9: RequestInspector<I8::StateOut, I8::RequestOut, Error: Into<BoxError>>,
    StateIn: Clone + Send + Sync + 'static,
    RequestIn: Send + 'static,
{
    type Error = BoxError;
    type Response = (Context<I9::StateOut>, I9::RequestOut);

    async fn serve(
        &self,
        ctx: Context<StateIn>,
        req: RequestIn,
    ) -> Result<Self::Response, Self::Error> {
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

impl<I1, I2, I3, I4, I5, I6, I7, I8, I9, I10, StateIn, RequestIn> Service<StateIn, RequestIn>
    for (I1, I2, I3, I4, I5, I6, I7, I8, I9, I10)
where
    I1: RequestInspector<StateIn, RequestIn, Error: Into<BoxError>>,
    I2: RequestInspector<I1::StateOut, I1::RequestOut, Error: Into<BoxError>>,
    I3: RequestInspector<I2::StateOut, I2::RequestOut, Error: Into<BoxError>>,
    I4: RequestInspector<I3::StateOut, I3::RequestOut, Error: Into<BoxError>>,
    I5: RequestInspector<I4::StateOut, I4::RequestOut, Error: Into<BoxError>>,
    I6: RequestInspector<I5::StateOut, I5::RequestOut, Error: Into<BoxError>>,
    I7: RequestInspector<I6::StateOut, I6::RequestOut, Error: Into<BoxError>>,
    I8: RequestInspector<I7::StateOut, I7::RequestOut, Error: Into<BoxError>>,
    I9: RequestInspector<I8::StateOut, I8::RequestOut, Error: Into<BoxError>>,
    I10: RequestInspector<I9::StateOut, I9::RequestOut, Error: Into<BoxError>>,
    StateIn: Clone + Send + Sync + 'static,
    RequestIn: Send + 'static,
{
    type Error = BoxError;
    type Response = (Context<I10::StateOut>, I10::RequestOut);

    async fn serve(
        &self,
        ctx: Context<StateIn>,
        req: RequestIn,
    ) -> Result<Self::Response, Self::Error> {
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

impl<I1, I2, I3, I4, I5, I6, I7, I8, I9, I10, I11, StateIn, RequestIn> Service<StateIn, RequestIn>
    for (I1, I2, I3, I4, I5, I6, I7, I8, I9, I10, I11)
where
    I1: RequestInspector<StateIn, RequestIn, Error: Into<BoxError>>,
    I2: RequestInspector<I1::StateOut, I1::RequestOut, Error: Into<BoxError>>,
    I3: RequestInspector<I2::StateOut, I2::RequestOut, Error: Into<BoxError>>,
    I4: RequestInspector<I3::StateOut, I3::RequestOut, Error: Into<BoxError>>,
    I5: RequestInspector<I4::StateOut, I4::RequestOut, Error: Into<BoxError>>,
    I6: RequestInspector<I5::StateOut, I5::RequestOut, Error: Into<BoxError>>,
    I7: RequestInspector<I6::StateOut, I6::RequestOut, Error: Into<BoxError>>,
    I8: RequestInspector<I7::StateOut, I7::RequestOut, Error: Into<BoxError>>,
    I9: RequestInspector<I8::StateOut, I8::RequestOut, Error: Into<BoxError>>,
    I10: RequestInspector<I9::StateOut, I9::RequestOut, Error: Into<BoxError>>,
    I11: RequestInspector<I10::StateOut, I10::RequestOut, Error: Into<BoxError>>,
    StateIn: Clone + Send + Sync + 'static,
    RequestIn: Send + 'static,
{
    type Error = BoxError;
    type Response = (Context<I11::StateOut>, I11::RequestOut);

    async fn serve(
        &self,
        ctx: Context<StateIn>,
        req: RequestIn,
    ) -> Result<Self::Response, Self::Error> {
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

impl<I1, I2, I3, I4, I5, I6, I7, I8, I9, I10, I11, I12, StateIn, RequestIn>
    Service<StateIn, RequestIn> for (I1, I2, I3, I4, I5, I6, I7, I8, I9, I10, I11, I12)
where
    I1: RequestInspector<StateIn, RequestIn, Error: Into<BoxError>>,
    I2: RequestInspector<I1::StateOut, I1::RequestOut, Error: Into<BoxError>>,
    I3: RequestInspector<I2::StateOut, I2::RequestOut, Error: Into<BoxError>>,
    I4: RequestInspector<I3::StateOut, I3::RequestOut, Error: Into<BoxError>>,
    I5: RequestInspector<I4::StateOut, I4::RequestOut, Error: Into<BoxError>>,
    I6: RequestInspector<I5::StateOut, I5::RequestOut, Error: Into<BoxError>>,
    I7: RequestInspector<I6::StateOut, I6::RequestOut, Error: Into<BoxError>>,
    I8: RequestInspector<I7::StateOut, I7::RequestOut, Error: Into<BoxError>>,
    I9: RequestInspector<I8::StateOut, I8::RequestOut, Error: Into<BoxError>>,
    I10: RequestInspector<I9::StateOut, I9::RequestOut, Error: Into<BoxError>>,
    I11: RequestInspector<I10::StateOut, I10::RequestOut, Error: Into<BoxError>>,
    I12: RequestInspector<I11::StateOut, I11::RequestOut, Error: Into<BoxError>>,
    StateIn: Clone + Send + Sync + 'static,
    RequestIn: Send + 'static,
{
    type Error = BoxError;
    type Response = (Context<I12::StateOut>, I12::RequestOut);

    async fn serve(
        &self,
        ctx: Context<StateIn>,
        req: RequestIn,
    ) -> Result<Self::Response, Self::Error> {
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
