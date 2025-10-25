use quote::ToTokens;
use syn::parse::Parse;

pub(crate) trait Combine: Sized {
    fn combine(self, other: Self) -> syn::Result<Self>;
}

pub(crate) fn parse_attrs<T>(ident: &str, attrs: &[syn::Attribute]) -> syn::Result<T>
where
    T: Combine + Default + Parse,
{
    attrs
        .iter()
        .filter(|attr| attr.meta.path().is_ident(ident))
        .map(|attr| attr.parse_args::<T>())
        .try_fold(T::default(), |out, next| out.combine(next?))
}

pub(crate) fn combine_unary_attribute<K>(a: &mut Option<K>, b: Option<K>) -> syn::Result<()>
where
    K: ToTokens,
{
    if let Some(kw) = b {
        if a.is_some() {
            let kw_name = std::any::type_name::<K>().split("::").last().unwrap();
            let msg = format!("`{kw_name}` specified more than once");
            return Err(syn::Error::new_spanned(kw, msg));
        }
        *a = Some(kw);
    }
    Ok(())
}
