pub use crate::net::forwarded::Forwarded;
use crate::net::forwarded::ForwardedElement;

mod via;
#[doc(inline)]
pub use via::Via;

mod x_forwarded_for;
#[doc(inline)]
pub use x_forwarded_for::XForwardedFor;

mod x_forwarded_host;
#[doc(inline)]
pub use x_forwarded_host::XForwardedHost;

mod x_forwarded_proto;
#[doc(inline)]
pub use x_forwarded_proto::XForwardedProto;

/// A trait for types headers that is used by middleware
/// which supports headers that can be converted into Forward data.
pub trait ForwardHeader:
    crate::http::headers::Header + IntoIterator<Item = ForwardedElement>
{
}

impl<T> ForwardHeader for T where
    T: crate::http::headers::Header + IntoIterator<Item = ForwardedElement>
{
}
