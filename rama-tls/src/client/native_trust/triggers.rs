use rama_core::futures::{
    Stream,
    stream::{Select, select},
};
use rama_utils::macros::{all_the_tuples_no_last_special_case, paste};
use std::{
    pin::Pin,
    task::{Context, Poll},
};

/// Turn a stream or a tuple of reload sources into native TLS trust refresh events.
///
/// Each item requests a refresh. Tuples of up to twelve sources can contain
/// streams, nested tuples, or custom implementations of this trait.
///
/// `Kind` distinguishes implementations so that a stream and a tuple can both
/// implement this trait. For streams it is `()`, and for tuples it is the tuple
/// of their members' markers. Callers normally let Rust infer the marker.
/// A custom source wrapper can use its own marker type.
pub trait IntoNativeTrustReloadTrigger<Kind> {
    /// The stream produced by this source.
    type Stream: Stream<Item = ()> + Send + 'static;

    /// Combine these sources into one stream of refresh requests.
    fn into_reload_stream(self) -> Self::Stream;
}

impl<S> IntoNativeTrustReloadTrigger<()> for S
where
    S: Stream<Item = ()> + Send + 'static,
{
    type Stream = S;

    fn into_reload_stream(self) -> Self::Stream {
        self
    }
}

macro_rules! impl_trigger_tuple {
    ($($source:ident),+) => {
        paste! {
            impl<$($source, [<Kind $source>]),+>
                IntoNativeTrustReloadTrigger<($([<Kind $source>],)+)> for ($($source,)+)
            where
                $($source: IntoNativeTrustReloadTrigger<[<Kind $source>]>),+
            {
                type Stream = impl_trigger_tuple!(@stream $($source),+);

                fn into_reload_stream(self) -> Self::Stream {
                    let ($([<$source:lower>],)+) = self;
                    impl_trigger_tuple!(@select $([<$source:lower>]),+)
                }
            }
        }
    };
    (@stream $last:ident) => { $last::Stream };
    (@stream $($source:ident),+) => {
        impl_trigger_tuple!(@split stream [] [$($source),+] [$($source),+])
    };
    (@select $last:ident) => { $last.into_reload_stream() };
    (@select $($source:ident),+) => {
        impl_trigger_tuple!(@split select [] [$($source),+] [$($source),+])
    };
    // Build a balanced Select tree so a ready source is polled about as often as its peers.
    // Move one source into the left half for every two entries in the last list.
    (@split $join:ident [$($left:ident),*] [$head:ident, $($right:ident),+]
        [$first:ident, $second:ident $(, $rest:ident)*]) => {
        impl_trigger_tuple!(@split $join [$($left,)* $head] [$($right),+] [$($rest),*])
    };
    (@split $join:ident [$($left:ident),+] [$($right:ident),+] [$($rest:ident)?]) => {
        impl_trigger_tuple!($join [$($left),+] [$($right),+])
    };
    (stream [$($left:ident),+] [$($right:ident),+]) => {
        Select<impl_trigger_tuple!(@stream $($left),+), impl_trigger_tuple!(@stream $($right),+)>
    };
    (select [$($left:ident),+] [$($right:ident),+]) => {
        select(impl_trigger_tuple!(@select $($left),+), impl_trigger_tuple!(@select $($right),+))
    };
}

all_the_tuples_no_last_special_case!(impl_trigger_tuple);

/// Receive manually requested native trust reloads.
pub struct ChannelReloadTrigger(flume::r#async::RecvStream<'static, ()>);

/// A cloneable sender for the channel reload trigger.
#[derive(Debug, Clone)]
pub struct ChannelReloadSender(flume::Sender<()>);

impl ChannelReloadTrigger {
    /// Create a sender and the trigger it feeds.
    #[must_use]
    pub fn new() -> (ChannelReloadSender, Self) {
        let (send, recv) = flume::bounded(1);
        (ChannelReloadSender(send), Self(recv.into_stream()))
    }
}

impl ChannelReloadSender {
    /// Queue a reload for the next handshake. Pending requests coalesce.
    pub fn request_reload(&self) -> Result<(), ChannelReloadClosed> {
        match self.0.try_send(()) {
            Ok(()) | Err(flume::TrySendError::Full(())) => Ok(()),
            Err(flume::TrySendError::Disconnected(())) => Err(ChannelReloadClosed::new()),
        }
    }
}

rama_utils::macros::error::static_str_error! {
    #[doc = "native trust reload channel is closed"]
    #[derive(Copy)]
    pub struct ChannelReloadClosed;
}

impl Stream for ChannelReloadTrigger {
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<()>> {
        Pin::new(&mut self.0).poll_next(cx)
    }
}

/// Request a native trust refresh when the process receives a Unix signal.
#[cfg(unix)]
pub struct UnixSignalTrigger(tokio::signal::unix::Signal);

#[cfg(unix)]
impl UnixSignalTrigger {
    /// Register for SIGHUP on the current Tokio runtime. As with other Tokio
    /// signal listeners, registering replaces the process's default behavior
    /// for this signal, even after the listener is dropped.
    ///
    /// ```
    /// # #[cfg(unix)]
    /// # async fn configure() -> std::io::Result<()> {
    /// use rama_tls::client::{TlsServerTrust, UnixSignalTrigger};
    ///
    /// let trust = TlsServerTrust::native_roots()
    ///     .with_reload_trigger(UnixSignalTrigger::sighup()?);
    /// # drop(trust);
    /// # Ok(())
    /// # }
    /// ```
    pub fn sighup() -> std::io::Result<Self> {
        Self::new(tokio::signal::unix::SignalKind::hangup())
    }

    /// Register for the specified Unix signal on the current Tokio runtime.
    ///
    /// The runtime must have I/O enabled.
    pub fn new(kind: tokio::signal::unix::SignalKind) -> std::io::Result<Self> {
        tokio::runtime::Handle::try_current().map_err(std::io::Error::other)?;
        tokio::signal::unix::signal(kind).map(Self)
    }
}

#[cfg(unix)]
impl Stream for UnixSignalTrigger {
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<()>> {
        self.0.poll_recv(cx)
    }
}

#[cfg(test)]
mod tests;
