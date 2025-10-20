use crate::http::uri::{UriMatchError, UriMatchReplace};
use rama_http_types::Uri;
use rama_utils::macros::all_the_tuples_no_last_special_case;
use std::borrow::Cow;

/// Apply fallthrough to slices, arrays, tuples or vectors.
pub struct UriMatchReplaceFallthrough<R>(pub R);

macro_rules! impl_uri_match_replace_on_fallthrough_slice {
    () => {
        fn match_replace_uri<'a>(
            &self,
            mut uri: Cow<'a, Uri>,
        ) -> Result<Cow<'a, Uri>, UriMatchError<'a>> {
            let mut found = false;
            for rule in self.0.iter() {
                match rule.match_replace_uri(uri) {
                    Ok(new_uri) => {
                        uri = new_uri;
                        found = true;
                    }
                    Err(UriMatchError::NoMatch(original_uri)) => uri = original_uri,
                    Err(UriMatchError::Unexpected(err)) => {
                        return Err(UriMatchError::Unexpected(err));
                    }
                }
            }
            if found {
                Ok(uri)
            } else {
                Err(UriMatchError::NoMatch(uri))
            }
        }
    };
}

impl<R: UriMatchReplace, const N: usize> UriMatchReplace for UriMatchReplaceFallthrough<[R; N]> {
    impl_uri_match_replace_on_fallthrough_slice!();
}

impl<R: UriMatchReplace> UriMatchReplace for UriMatchReplaceFallthrough<&[R]> {
    impl_uri_match_replace_on_fallthrough_slice!();
}

impl<R: UriMatchReplace> UriMatchReplace for UriMatchReplaceFallthrough<Vec<R>> {
    impl_uri_match_replace_on_fallthrough_slice!();
}

macro_rules! impl_uri_match_replace_on_fallthrough_tuple {
    ( $($ty:ident),* $(,)? ) => {
        #[allow(non_snake_case)]
        impl<$($ty),+> UriMatchReplace for UriMatchReplaceFallthrough<($($ty),+,)>
        where
            $(
                $ty: UriMatchReplace,
            )+
        {
            fn match_replace_uri<'a>(&self, mut uri: Cow<'a, Uri>) -> Result<Cow<'a, Uri>, UriMatchError<'a>> {
                let Self((
                    $($ty),+
                    ,
                )) = self;
                let mut found = false;
                $(
                    match $ty.match_replace_uri(uri) {
                        Ok(new_uri) => {
                            uri = new_uri;
                            found = true;
                        }
                        Err(UriMatchError::NoMatch(original_uri)) => uri = original_uri,
                        Err(UriMatchError::Unexpected(err)) => {
                            return Err(UriMatchError::Unexpected(err));
                        }
                    }
                )+
                if found {
                    Ok(uri)
                } else {
                    Err(UriMatchError::NoMatch(uri))
                }
            }
        }
    };
}

all_the_tuples_no_last_special_case!(impl_uri_match_replace_on_fallthrough_tuple);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::uri::{UriMatchReplaceScheme, match_replace::UriMatchReplaceNever};

    #[test]
    fn fallthrough_slices_simple() {
        let input = [
            UriMatchReplaceScheme::replace("fpt".parse().unwrap(), "fpts".parse().unwrap()),
            UriMatchReplaceScheme::http_to_https(),
            UriMatchReplaceScheme::replace("foo".parse().unwrap(), "bar".parse().unwrap()),
            UriMatchReplaceScheme::replace("https".parse().unwrap(), "baz".parse().unwrap()),
            UriMatchReplaceScheme::replace("fpt".parse().unwrap(), "fpts".parse().unwrap()),
        ];

        //slice
        let uri = UriMatchReplaceFallthrough(input.as_slice())
            .match_replace_uri(Cow::Owned(Uri::from_static("http://example.com")))
            .unwrap();
        assert_eq!("baz://example.com/", uri.to_string());

        // vec
        let uri = UriMatchReplaceFallthrough(input.to_vec())
            .match_replace_uri(Cow::Owned(Uri::from_static("http://example.com")))
            .unwrap();
        assert_eq!("baz://example.com/", uri.to_string());

        // arr
        let uri = UriMatchReplaceFallthrough(input.clone())
            .match_replace_uri(Cow::Owned(Uri::from_static("http://example.com")))
            .unwrap();
        assert_eq!("baz://example.com/", uri.to_string());

        // 1 no-error test w/ arr
        match input.match_replace_uri(Cow::Owned(Uri::from_static("gopher://example.com"))) {
            Ok(found) => panic!("unexpected match found: {found}"),
            Err(UriMatchError::NoMatch(_)) => (), // good,
            Err(UriMatchError::Unexpected(err)) => panic!("unexpected error: {err}"),
        }
    }

    #[test]
    fn fallthrough_tuple_simple() {
        let input = (
            UriMatchReplaceNever::new(),
            UriMatchReplaceScheme::http_to_https(),
            UriMatchReplaceNever::new(),
            UriMatchReplaceScheme::replace("https".parse().unwrap(), "baz".parse().unwrap()),
            UriMatchReplaceNever::new(),
        );

        let uri = UriMatchReplaceFallthrough(input.clone())
            .match_replace_uri(Cow::Owned(Uri::from_static("http://example.com")))
            .unwrap();
        assert_eq!("baz://example.com/", uri.to_string());

        // 1 no-error test w/ arr
        match input.match_replace_uri(Cow::Owned(Uri::from_static("gopher://example.com"))) {
            Ok(found) => panic!("unexpected match found: {found}"),
            Err(UriMatchError::NoMatch(_)) => (), // good,
            Err(UriMatchError::Unexpected(err)) => panic!("unexpected error: {err}"),
        }
    }
}
