use super::{UriMatchError, UriMatchReplace};
use rama_http_types::Uri;
use rama_utils::macros::all_the_tuples_no_last_special_case;
use std::borrow::Cow;

macro_rules! impl_uri_match_replace_on_tuple {
    ( $($ty:ident),* $(,)? ) => {
        #[allow(non_snake_case)]
        impl<$($ty),+> UriMatchReplace for ($($ty),+,)
        where
            $(
                $ty: UriMatchReplace,
            )+
        {
            fn match_replace_uri<'a>(&self, mut uri: Cow<'a, Uri>) -> Result<Cow<'a, Uri>, UriMatchError<'a>> {
                let (
                    $($ty),+
                    ,
                ) = self;
                $(
                    match $ty.match_replace_uri(uri) {
                        Ok(new_uri) => {
                            return Ok(new_uri);
                        }
                        Err(UriMatchError::NoMatch(original_uri)) => uri = original_uri,
                        Err(UriMatchError::Unexpected(err)) => {
                            return Err(UriMatchError::Unexpected(err));
                        }
                    }
                )+
                Err(UriMatchError::NoMatch(uri))
            }
        }
    };
}

all_the_tuples_no_last_special_case!(impl_uri_match_replace_on_tuple);

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use rama_http_types::Uri;

    use crate::http::uri::{
        UriMatchError, UriMatchReplace as _, UriMatchReplaceScheme,
        match_replace::UriMatchReplaceNever,
    };

    #[test]
    fn tuple_simple() {
        let input = (
            UriMatchReplaceNever::new(),
            UriMatchReplaceScheme::http_to_https(),
            UriMatchReplaceNever::new(),
            UriMatchReplaceScheme::replace("https".parse().unwrap(), "baz".parse().unwrap()),
            UriMatchReplaceNever::new(),
        );

        let uri = input
            .match_replace_uri(Cow::Owned(Uri::from_static("http://example.com")))
            .unwrap();
        assert_eq!("https://example.com/", uri.to_string());

        match input.match_replace_uri(Cow::Owned(Uri::from_static("ftp://example.com"))) {
            Ok(found) => panic!("unexpected match found: {found}"),
            Err(UriMatchError::NoMatch(_)) => (), // good,
            Err(UriMatchError::Unexpected(err)) => panic!("unexpected error: {err}"),
        }
    }
}
