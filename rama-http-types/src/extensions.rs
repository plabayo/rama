#[derive(Default, Clone)]
pub struct RamaExtensions(pub rama_core::context::Extensions);

#[derive(Default, Clone)]
pub struct HyperiumExtensions(pub crate::dep::hyperium::http::Extensions);

impl From<HyperiumExtensions> for rama_core::context::Extensions {
    fn from(HyperiumExtensions(mut extensions): HyperiumExtensions) -> Self {
        let mut rama_extensions = extensions
            .remove::<RamaExtensions>()
            .map_or_else(rama_core::context::Extensions::new, |ext| ext.0);

        rama_extensions.insert(HyperiumExtensions(extensions));

        rama_extensions
    }
}

impl From<RamaExtensions> for crate::dep::hyperium::http::Extensions {
    fn from(RamaExtensions(mut extensions): RamaExtensions) -> Self {
        let mut hyper_extensions = extensions
            .remove::<HyperiumExtensions>()
            .map_or_else(crate::dep::hyperium::http::Extensions::new, |ext| ext.0);

        hyper_extensions.insert(RamaExtensions(extensions));

        hyper_extensions
    }
}
