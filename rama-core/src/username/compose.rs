use rama_utils::macros::all_the_tuples_no_last_special_case;
use std::{
    fmt::{self, Write},
    sync::Arc,
};

use super::DEFAULT_USERNAME_LABEL_SEPARATOR;

#[derive(Debug, Clone)]
/// Composer struct used to compose a username into a [`String`],
/// with labels, all separated by the given `SEPARATOR`. Empty labels
/// aren't allowed.
pub struct Composer<const SEPARATOR: char = DEFAULT_USERNAME_LABEL_SEPARATOR> {
    buffer: String,
}

#[derive(Debug, Clone)]
/// [`std::error::Error`] returned in case composing of a username,
/// using [`Composer`] went wrong, somehow.
pub struct ComposeError(ComposeErrorKind);

#[derive(Debug, Clone)]
enum ComposeErrorKind {
    EmptyLabel,
    FmtError(fmt::Error),
}

impl fmt::Display for ComposeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            ComposeErrorKind::EmptyLabel => f.write_str("empty label"),
            ComposeErrorKind::FmtError(err) => write!(f, "fmt error: {err}"),
        }
    }
}

impl std::error::Error for ComposeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            ComposeErrorKind::EmptyLabel => None,
            ComposeErrorKind::FmtError(err) => err.source(),
        }
    }
}

impl<const SEPARATOR: char> Composer<SEPARATOR> {
    fn new(username: String) -> Self {
        Self { buffer: username }
    }

    /// write a label into the [`Composer`].
    pub fn write_label(&mut self, label: impl AsRef<str>) -> Result<(), ComposeError> {
        self.buffer
            .write_char(SEPARATOR)
            .map_err(|err| ComposeError(ComposeErrorKind::FmtError(err)))?;
        let label = label.as_ref();
        if label.is_empty() {
            return Err(ComposeError(ComposeErrorKind::EmptyLabel));
        }
        self.buffer
            .write_str(label.as_ref())
            .map_err(|err| ComposeError(ComposeErrorKind::FmtError(err)))?;
        Ok(())
    }

    fn compose(self) -> String {
        self.buffer
    }
}

#[inline]
/// Compose a username into a username together with its labels.
pub fn compose_username(
    username: String,
    labels: impl UsernameLabelWriter<DEFAULT_USERNAME_LABEL_SEPARATOR>,
) -> Result<String, ComposeError> {
    compose_username_with_separator::<DEFAULT_USERNAME_LABEL_SEPARATOR>(username, labels)
}

/// Compose a username into a username together with its labels,
/// using a custom separator instead of the default ([`DEFAULT_USERNAME_LABEL_SEPARATOR`])
pub fn compose_username_with_separator<const SEPARATOR: char>(
    username: String,
    labels: impl UsernameLabelWriter<SEPARATOR>,
) -> Result<String, ComposeError> {
    let mut composer = Composer::<SEPARATOR>::new(username);
    labels.write_labels(&mut composer)?;
    Ok(composer.compose())
}

/// A type that can write itself as label(s) to compose into a
/// username with labels. Often used by passing it to [`compose_username`].
pub trait UsernameLabelWriter<const SEPARATOR: char> {
    /// Write all labels into the given [`Composer`].
    fn write_labels(&self, composer: &mut Composer<SEPARATOR>) -> Result<(), ComposeError>;
}

impl<const SEPARATOR: char> UsernameLabelWriter<SEPARATOR> for String {
    fn write_labels(&self, composer: &mut Composer<SEPARATOR>) -> Result<(), ComposeError> {
        composer.write_label(self)
    }
}

impl<const SEPARATOR: char> UsernameLabelWriter<SEPARATOR> for &str {
    #[inline(always)]
    fn write_labels(&self, composer: &mut Composer<SEPARATOR>) -> Result<(), ComposeError> {
        composer.write_label(self)
    }
}

impl<const SEPARATOR: char, const N: usize, W> UsernameLabelWriter<SEPARATOR> for [W; N]
where
    W: UsernameLabelWriter<SEPARATOR>,
{
    fn write_labels(&self, composer: &mut Composer<SEPARATOR>) -> Result<(), ComposeError> {
        for writer in self {
            writer.write_labels(composer)?;
        }
        Ok(())
    }
}

impl<const SEPARATOR: char, W> UsernameLabelWriter<SEPARATOR> for Option<W>
where
    W: UsernameLabelWriter<SEPARATOR>,
{
    fn write_labels(&self, composer: &mut Composer<SEPARATOR>) -> Result<(), ComposeError> {
        match self {
            Some(writer) => writer.write_labels(composer),
            None => Ok(()),
        }
    }
}

impl<const SEPARATOR: char, W> UsernameLabelWriter<SEPARATOR> for &W
where
    W: UsernameLabelWriter<SEPARATOR>,
{
    #[inline(always)]
    fn write_labels(&self, composer: &mut Composer<SEPARATOR>) -> Result<(), ComposeError> {
        (*self).write_labels(composer)
    }
}

impl<const SEPARATOR: char, W> UsernameLabelWriter<SEPARATOR> for Arc<W>
where
    W: UsernameLabelWriter<SEPARATOR>,
{
    fn write_labels(&self, composer: &mut Composer<SEPARATOR>) -> Result<(), ComposeError> {
        (**self).write_labels(composer)
    }
}

impl<const SEPARATOR: char, W> UsernameLabelWriter<SEPARATOR> for Vec<W>
where
    W: UsernameLabelWriter<SEPARATOR>,
{
    fn write_labels(&self, composer: &mut Composer<SEPARATOR>) -> Result<(), ComposeError> {
        for writer in self {
            writer.write_labels(composer)?;
        }
        Ok(())
    }
}

macro_rules! impl_username_label_writer_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<const SEPARATOR: char, $($param),+> UsernameLabelWriter<SEPARATOR> for crate::combinators::$id<$($param),+>
        where
            $(
                $param: UsernameLabelWriter<SEPARATOR>,
            )+
        {
            fn write_labels(&self, composer: &mut Composer<SEPARATOR>) -> Result<(), ComposeError> {
                match self {
                    $(
                        crate::combinators::$id::$param(writer) => {
                            writer.write_labels(composer)
                        }
                    )+
                }
            }
        }
    };
}

crate::combinators::impl_either!(impl_username_label_writer_either);

macro_rules! impl_username_label_writer_for_tuple {
    ( $($ty:ident),* $(,)? ) => {
        #[allow(non_snake_case)]
        impl<const SEPARATOR: char, $($ty),*> UsernameLabelWriter<SEPARATOR> for ($($ty,)*)
        where
            $( $ty: UsernameLabelWriter<SEPARATOR>, )*
        {
            fn write_labels(&self, composer: &mut Composer<SEPARATOR>) -> Result<(), ComposeError> {
                let ($($ty),*,) = self;
                $(
                    $ty.write_labels(composer)?;
                )*
                Ok(())
            }
        }
    };
}
all_the_tuples_no_last_special_case!(impl_username_label_writer_for_tuple);
