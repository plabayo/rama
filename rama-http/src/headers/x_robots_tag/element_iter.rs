use crate::headers::x_robots_tag::Element;

#[derive(Debug, Clone)]
/// An iterator over the `XRobotsTag` header's elements.
pub struct ElementIter(std::vec::IntoIter<Element>);

impl Iterator for ElementIter {
    type Item = Element;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

impl ElementIter {
    pub fn new(elements: std::vec::IntoIter<Element>) -> Self {
        Self(elements)
    }
}
