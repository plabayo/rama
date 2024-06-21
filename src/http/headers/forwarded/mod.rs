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

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_forward_header<T: ForwardHeader>() {}

    #[test]
    fn test_forward_header_impls() {
        assert_forward_header::<Forwarded>();
        assert_forward_header::<Via>();
        assert_forward_header::<XForwardedFor>();
        assert_forward_header::<XForwardedHost>();
        assert_forward_header::<XForwardedProto>();
    }
}
