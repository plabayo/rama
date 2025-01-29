use headers::Header;
use http::{HeaderName, HeaderValue};
use crate::headers::Error;
use crate::headers::x_robots_tag_components::RobotsTag;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XRobotsTag {
    elements: Vec<RobotsTag>,
}

impl Header for XRobotsTag {
	fn name() -> &'static HeaderName {
		&crate::header::X_ROBOTS_TAG
	}

	fn decode<'i, I>(values: &mut I) -> Result<Self, Error>
	where
		Self: Sized,
		I: Iterator<Item=&'i HeaderValue>
	{
		todo!()
	}

	fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
		todo!()
	}
}
