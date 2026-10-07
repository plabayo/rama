//! Table entry builders: each yields a named exercise closure.

macro_rules! decode {
    ($ty:ty) => {
        (stringify!($ty), |values: &[::rama_http_types::HeaderValue]| {
            $crate::fuzz::support::sink($crate::fuzz::support::decoded::<$ty>(values));
        })
    };
    ($ty:ty, |$h:ident| $body:block) => {
        (stringify!($ty), |values: &[::rama_http_types::HeaderValue]| {
            if let Some($h) = $crate::fuzz::support::decoded::<$ty>(values) $body
        })
    };
    ($ty:ty, |$h:ident, $values:ident| $body:block) => {
        (stringify!($ty), |$values: &[::rama_http_types::HeaderValue]| {
            if let Some($h) = $crate::fuzz::support::decoded::<$ty>($values) $body
        })
    };
    ($ty:ty, $exercise:path) => {
        decode!($ty, |h| {
            $exercise(&h);
        })
    };
}

macro_rules! forward_conversion {
    ($ty:ty) => {
        (stringify!($ty), $crate::fuzz::parts::converted::<$ty>)
    };
}

macro_rules! parse_str {
    ($ty:ty) => {
        (concat!(stringify!($ty), "::from_str"), |s: &str| {
            if let Ok(parsed) = s.parse::<$ty>() {
                $crate::fuzz::support::roundtrip(&parsed);
                $crate::fuzz::support::display(&parsed);
            }
        })
    };
}

macro_rules! enum_str {
    ($ty:ty $(, |$v:ident| $header:expr)?) => {
        (concat!(stringify!($ty), "::from"), |s: &str| {
            let parsed = <$ty>::from(s);
            $crate::fuzz::support::token(&parsed);
            $crate::fuzz::support::sink(parsed.as_str());
            $crate::fuzz::support::sink(parsed.as_static_str());
            $crate::fuzz::support::sink(<$ty>::strict_parse(s));
            $crate::fuzz::support::sink(s.parse::<$ty>());
            $(
                let $v = parsed;
                $crate::fuzz::support::roundtrip(&$header);
            )?
        })
    };
}
