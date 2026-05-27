use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::Ident;

/// Resolve the root path under which `rama-http`'s `html` module lives.
///
/// We try, in order:
///   1. the `rama-http` crate — produces `::rama_http` or `crate` when
///      we're inside `rama-http` itself (doctests / tests).
///   2. the `rama` umbrella crate — produces `::rama::http`.
///   3. a `compile_error!` fallback.
///
/// **Order matters.** `proc-macro-crate` returns
/// [`FoundCrate::Itself`] for *any* compilation unit that lives under
/// the `rama` package's manifest — including `rama`'s own lib, its
/// examples, and its integration tests. In all those cases the emitted
/// path must resolve via `rama-http` (a real direct dependency of
/// `rama`), because `::rama` itself is not in scope from inside the
/// crate being compiled. Checking `rama-http` first sidesteps this
/// asymmetry without needing an `extern crate self as rama;` hack in
/// `rama`'s lib.rs.
pub(crate) fn resolve_root() -> TokenStream {
    if let Ok(found) = crate_name("rama-http") {
        return match found {
            FoundCrate::Itself => quote!(crate),
            FoundCrate::Name(name) => {
                let ident = Ident::new(&name, Span::call_site());
                quote!(::#ident)
            }
        };
    }

    if let Ok(found) = crate_name("rama") {
        // We only land here for downstream crates that depend on the
        // umbrella `rama` (and not directly on `rama-http`). In that
        // case `crate_name("rama")` returns the dependency's local
        // name — `Itself` is impossible because that's already been
        // claimed by the `rama-http` branch above.
        let ident = match found {
            FoundCrate::Itself => Ident::new("rama", Span::call_site()),
            FoundCrate::Name(name) => Ident::new(&name, Span::call_site()),
        };
        return quote!(::#ident::http);
    }

    quote! {
        { compile_error!(
            "rama-http-macros could not find rama-http or rama. \
             Add a dependency on `rama` (with the `html` feature) \
             or `rama-http` (with the `html` feature)."
        ); }
    }
}
