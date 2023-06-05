use std::{
    future::Future,
    pin::Pin,
    task::{ready, Context, Poll},
};

use tower::Service as TowerService;

pub trait Service<Input> {
    type Error;
    type Output;

    async fn call(self, input: Input) -> Result<Self::Output, Self::Error>;
}

mod error;
pub use error::BoxError;

mod factory;
pub use factory::ServiceFactory;

impl<T, I> Service<I> for T
where
    T: TowerService<I>,
{
    type Error = <T as TowerService<I>>::Error;
    type Output = <T as TowerService<I>>::Response;

    async fn call(self, input: I) -> Result<Self::Output, Self::Error> {
        TowerServiceFuture {
            state: TowerServiceState::NotReady { service: self },
            input: Some(input),
        }
        .await
    }
}

pin_project_lite::pin_project! {
    struct TowerServiceFuture<I, S>
where S: TowerService<I>,
{
        #[pin]
        state: TowerServiceState<S, <S as TowerService<I>>::Future>,
        input: Option<I>,
    }
}

pin_project_lite::pin_project! {
    #[project = TowerServiceStateProj]
    enum TowerServiceState<S, F> {
        NotReady { service: S },
        Ready { #[pin] future: F }
    }
}

impl<I, S> Future for TowerServiceFuture<I, S>
where
    S: TowerService<I>,
{
    type Output = Result<<S as TowerService<I>>::Response, <S as TowerService<I>>::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.as_mut().project();
        match this.state.as_mut().project() {
            TowerServiceStateProj::NotReady { service } => {
                ready!(service.poll_ready(cx))?;
                let input = this.input.take().expect("input should still be available");
                let future = TowerService::call(service, input);
                this.state.set(TowerServiceState::Ready { future });
                self.poll(cx)
            }
            TowerServiceStateProj::Ready { future } => future.poll(cx),
        }
    }
}

#[cfg(test)]
mod tower_service_tests {
    use super::*;

    struct TowerTestService {
        n: i32,
    }

    struct TowerTestServiceFuture {
        n: i32,
        target: i32,
    }

    impl Future for TowerTestServiceFuture {
        type Output = Result<i32, BoxError>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.n < self.target {
                self.n += 1;
                let _ = cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Ready(Ok(self.n))
        }
    }

    impl TowerService<i32> for TowerTestService {
        type Response = i32;
        type Error = BoxError;
        type Future = TowerTestServiceFuture;

        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if self.n == 0 {
                self.n += 1;
                let _ = cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, input: i32) -> Self::Future {
            TowerTestServiceFuture {
                n: self.n,
                target: input,
            }
        }
    }

    #[tokio::test]
    async fn test_tower_service() {
        let service = TowerTestService { n: 0 };
        let result = service.call(5).await.expect("tower service to succeed");
        assert_eq!(result, 5);
    }

    async fn handle(input: i32) -> Result<i32, BoxError> {
        Ok(input * 2)
    }

    #[tokio::test]
    async fn test_tower_service_fn() {
        let service = tower::service_fn(handle);
        let result = service.call(5).await.expect("tower service fn to succeed");
        assert_eq!(result, 10);
    }

    #[tokio::test]
    async fn test_tower_service_builder_fn() {
        let service = tower::ServiceBuilder::new()
            .concurrency_limit(1)
            .service_fn(handle);
        let result = service.call(5).await.expect("tower service fn to succeed");
        assert_eq!(result, 10);
    }
}
