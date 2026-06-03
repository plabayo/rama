use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;

/// Get the path prefix that should be used to reference items provided by
/// `individual_crate_name`.
///
/// This prefers the umbrella `rama` crate (and supports renames of it). The
/// umbrella flattens some crates (e.g. rama-core's modules appear directly as
/// `rama::extensions`) but nests others under a module (e.g. rama-utils lives at
/// `rama::utils`). Pass `umbrella_module` to account for the latter: `None` for
/// a flattened crate, `Some("utils")` for one nested at `rama::<module>`.
///
/// If the umbrella is not found `individual_crate_name` is used directly (its
/// items live at the crate root, so `umbrella_module` does not apply there).
pub(crate) fn support_root_ts(
    individual_crate_name: &'static str,
    umbrella_module: Option<&'static str>,
) -> TokenStream {
    // Prefer the umbrella crate
    if let Ok(found) = crate_name("rama") {
        let ident = match found {
            FoundCrate::Itself => Ident::new("rama", Span::call_site()),
            FoundCrate::Name(name) => Ident::new(&name, Span::call_site()),
        };
        return if let Some(module) = umbrella_module {
            let module = Ident::new(module, Span::call_site());
            quote!(::#ident::#module)
        } else {
            quote!(::#ident)
        };
    }

    // Fall back to the individual_crate_name crate directly (eg rama-core)
    if let Ok(found) = crate_name(individual_crate_name) {
        return match found {
            FoundCrate::Itself => quote!(crate),
            FoundCrate::Name(name) => {
                let ident = Ident::new(&name, Span::call_site());
                quote!(::#ident)
            }
        };
    }

    quote! {
        { compile_error!(
            "Add a dependency on `rama` or `{}` to use this macro",
             individual_crate_name
        ); }
    }
}
