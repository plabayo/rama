pub use crate::net::forwarded::Forwarded;

mod x_forwarded_for;
#[doc(inline)]
pub use x_forwarded_for::XForwardedFor;

mod x_forwarded_host;
#[doc(inline)]
pub use x_forwarded_host::XForwardedHost;

mod x_forwarded_proto;
#[doc(inline)]
pub use x_forwarded_proto::XForwardedProto;
