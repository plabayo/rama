#[doc(hidden)]
#[macro_export]
macro_rules! __impl_inner_traits {
    (
        $(
            $trait:ident for $struct:ident <$($generic:ident),*>
            where
                {$($where_clause:tt)*}
                $(target: {$($target:tt)*})?
                $(target_mut: {$($target_mut:tt)*})?
        ); *$(;)?
    ) => {
        $(
            $crate::macros::traits::impl_inner_traits!{
                @$trait for $struct<$($generic),*>
                where
                    {$($where_clause)*}
                    $(target: {$($target)*})?
                    $(target_mut: {$($target_mut)*})?
            }
        )*

    };
    (
        @Socket for $struct:ident <$($generic:ident),*>
        where
            {$($where_clause:tt)*}
            target: {$($target:tt)*}

    ) => {
        #[warn(clippy::missing_trait_methods)]
        impl<$($generic),*> Socket for $struct<$($generic),*>
        where
            $($where_clause)*
        {
            fn local_addr(&self) -> std::io::Result<SocketAddr> {
                self.$($target)*.local_addr()
            }

            fn peer_addr(&self) -> std::io::Result<SocketAddr> {
                self.$($target)*.peer_addr()
            }
        }
    };

    (
        @AsyncRead for $struct:ident <$($generic:ident),*>
        where
            {$($where_clause:tt)*}
            target_mut: {$($target_mut:tt)*}
    ) => {
        #[warn(clippy::missing_trait_methods)]
        impl<$($generic),*> AsyncRead for $struct<$($generic),*>
        where
            $($where_clause)*
        {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                Pin::new(&mut self.$($target_mut)*).poll_read(cx, buf)
            }
        }
    };

    (
        @AsyncWrite for $struct:ident <$($generic:ident),*>
        where
            {$($where_clause:tt)*}
            target: {$($target:tt)*}
            target_mut: {$($target_mut:tt)*}
    ) => {
        #[warn(clippy::missing_trait_methods)]
        impl<$($generic),*> AsyncWrite for $struct<$($generic),*>
        where
            $($where_clause)*
        {
            fn poll_write(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> std::task::Poll<Result<usize, std::io::Error>> {
                Pin::new(&mut self.$($target_mut)*).poll_write(cx, buf)
            }

            fn poll_flush(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), std::io::Error>> {
                Pin::new(&mut self.$($target_mut)*).poll_flush(cx)
            }

            fn poll_shutdown(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), std::io::Error>> {
                Pin::new(&mut self.$($target_mut)*).poll_shutdown(cx)
            }

            fn is_write_vectored(&self) -> bool {
                self.$($target)*.is_write_vectored()
            }

            fn poll_write_vectored(
                mut self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                bufs: &[std::io::IoSlice<'_>],
            ) -> std::task::Poll<Result<usize, std::io::Error>> {
                Pin::new(&mut self.$($target_mut)*).poll_write_vectored(cx, bufs)
            }
        }
    }
}

pub use crate::__impl_inner_traits as impl_inner_traits;
