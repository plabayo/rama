#[derive(Debug)]
pub(crate) struct Chain<'a> {
    next: Option<&'a (dyn std::error::Error + 'static)>,
}

impl<'a> Chain<'a> {
    pub(crate) fn new(head: &'a (dyn std::error::Error + 'static)) -> Self {
        Self { next: Some(head) }
    }
}

impl<'a> Iterator for Chain<'a> {
    type Item = &'a (dyn std::error::Error + 'static);

    fn next(&mut self) -> Option<Self::Item> {
        let error = self.next?;
        self.next = error.source();
        Some(error)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl ExactSizeIterator for Chain<'_> {
    fn len(&self) -> usize {
        let mut len = 0;
        let mut next = self.next;
        while let Some(cause) = next {
            next = cause.source();
            len += 1;
        }
        len
    }
}
