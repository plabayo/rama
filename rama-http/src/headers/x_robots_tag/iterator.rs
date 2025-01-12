use crate::headers::x_robots_tag::Element;

#[derive(Debug, Clone)]
/// An iterator over the `XRobotsTag` header's elements.
pub struct Iterator(std::vec::IntoIter<Element>);

impl core::iter::Iterator for Iterator {
    type Item = Element;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

impl Iterator {
    pub fn new(elements: std::vec::IntoIter<Element>) -> Self {
        Self(elements)
    }
}
