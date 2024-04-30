use std::fmt::{self, Debug, Display, Write};

pub(crate) struct ContextError<C, E> {
    pub(crate) context: C,
    pub(crate) error: E,
}

impl<C, E> Debug for ContextError<C, E>
where
    C: Display,
    E: Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Error")
            .field("context", &Quoted(&self.context))
            .field("source", &self.error)
            .finish()
    }
}

impl<C, E> Display for ContextError<C, E>
where
    C: Display,
    E: Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.context, self.error)
    }
}

impl<C, E> std::error::Error for ContextError<C, E>
where
    C: Display,
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.error.source()
    }
}

struct Quoted<C>(C);

impl<C> Debug for Quoted<C>
where
    C: Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_char('"')?;
        Quoted(&mut *formatter).write_fmt(format_args!("{}", self.0))?;
        formatter.write_char('"')?;
        Ok(())
    }
}

impl Write for Quoted<&mut fmt::Formatter<'_>> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        Display::fmt(&s.escape_debug(), self.0)
    }
}
