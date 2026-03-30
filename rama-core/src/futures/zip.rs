use pin_project_lite::pin_project;
use std::{
    pin::Pin,
    task::{Context, Poll},
};

/// Joins two futures, waiting for both to complete.
///
/// # Examples
///
/// ```
/// use rama_core::futures;
///
/// # #[tokio::main]
/// # async fn main() {
/// let a = async { 1 };
/// let b = async { 2 };
///
/// assert_eq!(futures::zip(a, b).await, (1, 2));
/// # }
/// ```
pub fn zip<F1, F2>(future1: F1, future2: F2) -> Zip<F1, F2>
where
    F1: Future,
    F2: Future,
{
    Zip {
        future1: Some(future1),
        future2: Some(future2),
        output1: None,
        output2: None,
    }
}

pin_project! {
    /// Future for the [`zip()`] function.
    #[derive(Debug)]
    #[must_use = "futures do nothing unless you `.await` or poll them"]
    pub struct Zip<F1, F2>
    where
        F1: Future,
        F2: Future,
    {
        #[pin]
        future1: Option<F1>,
        output1: Option<F1::Output>,
        #[pin]
        future2: Option<F2>,
        output2: Option<F2::Output>,
    }

}

/// Extracts the contents of two options and zips them, handling `(Some(_), None)` cases
fn take_zip_from_parts<T1, T2>(o1: &mut Option<T1>, o2: &mut Option<T2>) -> Poll<(T1, T2)> {
    match (o1.take(), o2.take()) {
        (Some(t1), Some(t2)) => Poll::Ready((t1, t2)),
        (o1x, o2x) => {
            *o1 = o1x;
            *o2 = o2x;
            Poll::Pending
        }
    }
}

impl<F1, F2> Future for Zip<F1, F2>
where
    F1: Future,
    F2: Future,
{
    type Output = (F1::Output, F2::Output);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        if let Some(future) = this.future1.as_mut().as_pin_mut()
            && let Poll::Ready(out) = future.poll(cx)
        {
            *this.output1 = Some(out);

            this.future1.set(None);
        }

        if let Some(future) = this.future2.as_mut().as_pin_mut()
            && let Poll::Ready(out) = future.poll(cx)
        {
            *this.output2 = Some(out);

            this.future2.set(None);
        }

        take_zip_from_parts(this.output1, this.output2)
    }
}

/// Joins two fallible futures, waiting for both to complete or one of them to error.
///
/// # Examples
///
/// ```
/// use rama_core::futures;
///
/// # #[tokio::main]
/// # async fn main() {
/// let a = async { Ok::<i32, i32>(1) };
/// let b = async { Err::<i32, i32>(2) };
///
/// assert_eq!(futures::try_zip(a, b).await, Err(2));
/// # }
/// ```
pub fn try_zip<T1, T2, E, F1, F2>(future1: F1, future2: F2) -> TryZip<F1, T1, F2, T2>
where
    F1: Future<Output = Result<T1, E>>,
    F2: Future<Output = Result<T2, E>>,
{
    TryZip {
        future1: Some(future1),
        future2: Some(future2),
        output1: None,
        output2: None,
    }
}

pin_project! {
    /// Future for the [`try_zip()`] function.
    #[derive(Debug)]
    #[must_use = "futures do nothing unless you `.await` or poll them"]
    pub struct TryZip<F1, T1, F2, T2> {
        #[pin]
        future1: Option<F1>,
        output1: Option<T1>,
        #[pin]
        future2: Option<F2>,
        output2: Option<T2>,

    }

}

impl<T1, T2, E, F1, F2> Future for TryZip<F1, T1, F2, T2>
where
    F1: Future<Output = Result<T1, E>>,
    F2: Future<Output = Result<T2, E>>,
{
    type Output = Result<(T1, T2), E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        if let Some(future) = this.future1.as_mut().as_pin_mut()
            && let Poll::Ready(out) = future.poll(cx)
        {
            match out {
                Ok(t) => {
                    *this.output1 = Some(t);

                    this.future1.set(None);
                }

                Err(err) => return Poll::Ready(Err(err)),
            }
        }

        if let Some(future) = this.future2.as_mut().as_pin_mut()
            && let Poll::Ready(out) = future.poll(cx)
        {
            match out {
                Ok(t) => {
                    *this.output2 = Some(t);

                    this.future2.set(None);
                }

                Err(err) => return Poll::Ready(Err(err)),
            }
        }

        take_zip_from_parts(this.output1, this.output2).map(Ok)
    }
}
