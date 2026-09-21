use rama_core::extensions::{Extensions, ExtensionsRef, TypeErasedExtension};
use rama_net::client::ConnectRequest;

// Identity here tracks who wrote an extension, never TLS compatibility. A
// caller's later replacement remains authoritative even if its value is equal.
#[derive(Clone, Debug)]
struct GeneratedExtension {
    previous: Option<TypeErasedExtension>,
    generated: TypeErasedExtension,
}

#[derive(Clone, Debug, rama_core::extensions::Extension)]
pub(super) struct GeneratedServiceInput(Vec<GeneratedExtension>);

fn latest_extension(
    extensions: &Extensions,
    kind: std::any::TypeId,
) -> Option<&TypeErasedExtension> {
    let mut result = [None];
    extensions.get_many_erased(&[kind], &mut result);
    result[0].map(|(value, _)| value)
}

fn copy_extensions(
    extensions: &Extensions,
    output: &mut Vec<TypeErasedExtension>,
    removed: &[std::any::TypeId],
) {
    if let Some(parent) = extensions.parent() {
        copy_extensions(parent, output, removed);
    }
    output.extend(
        extensions
            .self_iter_all()
            .filter(|value| !removed.contains(&value.type_id()))
            .cloned(),
    );
}

impl GeneratedServiceInput {
    pub(super) fn capture(before: &Extensions, after: &Extensions) {
        fn changes(before: &Extensions, after: &Extensions, delta: &mut Vec<GeneratedExtension>) {
            if let Some(parent) = after.parent() {
                changes(before, parent, delta);
            }
            for value in after.self_iter_all() {
                let previous = latest_extension(before, value.type_id());
                delta.retain(|entry| entry.generated.type_id() != value.type_id());
                if !previous.is_some_and(|previous| previous.ptr_eq(value)) {
                    delta.push(GeneratedExtension {
                        previous: previous.cloned(),
                        generated: value.clone(),
                    });
                }
            }
        }
        let mut delta = Vec::new();
        changes(before, after, &mut delta);
        if !delta.is_empty() {
            after.insert(Self(delta));
        }
    }

    pub(super) fn restore(input: &mut ConnectRequest) {
        let Some(generated) = input.extensions().get_ref::<Self>() else {
            return;
        };
        let mut removed = vec![std::any::TypeId::of::<Self>()];
        let mut restored = Vec::new();
        for entry in &generated.0 {
            let kind = entry.generated.type_id();
            if latest_extension(input.extensions(), kind)
                .is_some_and(|current| current.ptr_eq(&entry.generated))
            {
                removed.push(kind);
                restored.extend(entry.previous.iter().cloned());
            }
        }
        // Rebuild only on reentry, sharing all retained values. New caller TLS
        // policies and route overrides survive; computed transport state does not.
        let mut retained = Vec::new();
        copy_extensions(input.extensions(), &mut retained, &removed);
        input.extensions = retained.into_iter().chain(restored).collect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::{
        Fork as _,
        extensions::{Egress, Ingress},
    };
    use rama_http_types::Version;
    use rama_net::{client::ProxyRoute, http::TargetHttpVersion};

    #[test]
    fn caller_nested_overrides_survive_returned_input_restore() {
        for egress in [false, true] {
            let original = ConnectRequest::new("example.com:443".parse().unwrap());
            original
                .extensions()
                .insert(TargetHttpVersion(Version::HTTP_2));
            original.extensions().insert(ProxyRoute::Direct);
            let mut returned = original.fork();
            returned
                .extensions()
                .insert(TargetHttpVersion(Version::HTTP_2));
            returned.extensions().insert(ProxyRoute::Direct);
            GeneratedServiceInput::capture(original.extensions(), returned.extensions());
            let override_policy = Extensions::new();
            override_policy.insert(TargetHttpVersion(Version::HTTP_11));
            override_policy.insert(ProxyRoute::Proxy(
                "http://proxy.example:3128".parse().unwrap(),
            ));
            if egress {
                returned.extensions().insert(Egress(override_policy));
            } else {
                returned.extensions().insert(Ingress(override_policy));
            }
            GeneratedServiceInput::restore(&mut returned);
            assert_eq!(
                returned
                    .extensions()
                    .get_ref::<TargetHttpVersion>()
                    .unwrap()
                    .0,
                Version::HTTP_11
            );
            assert!(matches!(
                returned.extensions().get_ref::<ProxyRoute>().unwrap(),
                ProxyRoute::Proxy(_)
            ));
        }
    }
}
