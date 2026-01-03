use core::panic;
use itertools::Itertools;
use parking_lot::RwLock;
use std::time::Instant;
use std::{
    any::{Any, TypeId},
    sync::Arc,
};
// Which stores do we have
// connection
// stream
// request
// egress
// ingress

// Request: NoRetry DoThis        Use Connection                              BlaRequest
// Connection:             Create                Negotiated tls IsHealth=True

// Request 2: Dothis         Use connection                                    Bla Request

#[derive(Debug, Clone)]
/// combined view on all extensions that apply at a specific place
struct Extensions {
    stores: Vec<ExtensionStore>,
}

impl Extensions {
    fn new(store: ExtensionStore) -> Self {
        Self {
            stores: vec![store.clone()],
        }
    }

    fn add_new_store(&mut self, store: ExtensionStore) {
        self.stores.push(store.clone());
    }

    fn main_store(&self) -> &ExtensionStore {
        &self.stores[0]
    }

    /// Insert a type into this [`Extensions]` store.
    fn insert<T>(&self, val: T)
    where
        T: Clone + Send + Sync + std::fmt::Debug + 'static,
    {
        self.main_store().insert(val);
    }

    // TODO implement this efficienlty for our use case (this is possible with our structure)
    fn unified_view(&self) -> Vec<(Instant, String, StoredExtensions)> {
        let mut all_extensions = Vec::new();

        for store in &self.stores {
            all_extensions.extend(
                store
                    .storage
                    .read()
                    .iter()
                    .map(|item| (item.0, store.name.clone(), item.1.clone())),
            );
        }

        // Sort by Instant (the first element of the tuple)
        all_extensions.sort_by_key(|(instant, _, _)| *instant);

        all_extensions
    }

    fn get<T: Send + Clone + Sync + 'static>(&self) -> Option<T> {
        let type_id = TypeId::of::<T>();
        self.unified_view()
            .iter()
            .rev()
            .find(|item| item.2.0 == type_id)
            .and_then(|ext| (*ext.2.1).as_any().downcast_ref())
            .cloned()
    }

    fn get_smart<T: Send + Clone + Sync + 'static>(&self) -> Option<T> {
        let type_id = TypeId::of::<T>();

        // 1. Acquire all read locks simultaneously
        let guards: Vec<_> = self
            .stores
            .iter()
            .map(|s| (s.storage.read(), &s.name))
            .collect();

        // 2. Search backwards across all stores
        // Since each store is append-only (sorted by time),
        // the latest T must be near the end of one of these vecs.

        let mut latest: Option<(Instant, &StoredExtensions)> = None;

        for (storage, _) in &guards {
            // Look from the back of this specific store
            if let Some(found) = storage.iter().rev().find(|item| item.1.0 == type_id) {
                match latest {
                    None => latest = Some((found.0, &found.1)),
                    Some((current_instant, _)) if found.0 > current_instant => {
                        latest = Some((found.0, &found.1));
                    }
                    _ => {}
                }
            }
        }

        // 3. Downcast the winner
        println!("latest {latest:?}");
        latest.and_then(|(_, ext)| (*ext.1).as_any().downcast_ref().cloned())
    }

    fn iter_type<'a, T: Clone + 'static>(&'a self) -> impl Iterator<Item = (Instant, T)> + 'a {
        let type_id = TypeId::of::<T>();

        let mut guards: Vec<_> = self.stores.iter().map(|s| s.storage.read()).collect();

        let mut cursors = vec![0; guards.len()];

        std::iter::from_fn(move || {
            let mut best_store = None;
            let mut earliest_time = None;

            for (i, guard) in guards.iter().enumerate() {
                while cursors[i] < guard.len() && guard[cursors[i]].1.0 != type_id {
                    cursors[i] += 1;
                }

                if let Some(item) = guard.get(cursors[i]) {
                    if earliest_time.is_none() || item.0 < earliest_time.unwrap() {
                        earliest_time = Some(item.0);
                        best_store = Some(i);
                    }
                }
            }

            if let Some(i) = best_store {
                let item = &guards[i][cursors[i]];
                let val = (*item.1.1).as_any().downcast_ref::<T>().cloned();
                cursors[i] += 1;

                return Some((item.0, val?));
            }

            None
        })
    }
}

#[derive(Debug, Clone)]
/// Single extensions store, this is readonly and appendonly, we use &self for everything
struct ExtensionStore {
    // again no string later, but for proto type this works
    name: String,
    // we have external crate options here, or we can implement some of these algorithms
    // for now we just do it as simple as possible. But with our setup we can do this much
    // more efficient
    storage: Arc<RwLock<Vec<(Instant, StoredExtensions)>>>,
}

impl ExtensionStore {
    fn new(name: String) -> Self {
        Self {
            name,
            storage: Default::default(),
        }
    }

    /// Insert a type into this [`Extensions]` store.
    fn insert<T>(&self, val: T)
    where
        T: Clone + Send + Sync + std::fmt::Debug + 'static,
    {
        let extension = StoredExtensions(TypeId::of::<T>(), Box::new(val));
        self.storage.write().push((Instant::now(), extension));
    }

    fn deep_copy(&self) -> Self {
        Self {
            name: "self.name".to_owned(),
            storage: Arc::new(RwLock::new(self.storage.read().clone())),
        }
    }
}

#[derive(Clone, Debug)]
/// TODO we should be able to store this more efficiently, so so much room for nice stuff
struct StoredExtensions(TypeId, Box<dyn ExtensionType>);

trait ExtensionType: Any + Send + Sync + std::fmt::Debug {
    fn clone_box(&self) -> Box<dyn ExtensionType>;
    fn as_any(&self) -> &dyn Any;
}

impl<T: Clone + Send + Sync + std::fmt::Debug + 'static> ExtensionType for T {
    fn clone_box(&self) -> Box<dyn ExtensionType> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Clone for Box<dyn ExtensionType> {
    fn clone(&self) -> Self {
        (**self).clone_box()
    }
}

mod tests {
    use super::*;

    #[derive(Clone, Debug)]
    struct NoRetry;

    #[derive(Clone, Debug)]
    struct TargetHttpVersion;

    #[derive(Clone, Debug)]
    struct ConnectionInfo;

    #[derive(Clone, Debug)]
    struct RequestInfoInner;

    #[derive(Clone, Debug)]
    struct BrokenConnection;

    #[derive(Clone, Debug)]
    struct IsHealth(bool);

    #[test]
    fn setup() {
        let req_store = ExtensionStore::new("request".to_owned());
        let mut request = Extensions::new(req_store);

        request.insert(NoRetry);
        request.insert(TargetHttpVersion);

        println!("request extensions {request:?}");

        // 1. now we go to connector setup
        // 2. we create the extensions for our connector
        // 3. we add request extensions to this, and vice versa
        let conn_store = ExtensionStore::new("connection".to_owned());
        let connection = Extensions::new(conn_store);

        // We add connector extensions also to our request
        request.add_new_store(connection.main_store().clone());

        // In connector setup now we only edit connection extension
        connection.insert(ConnectionInfo);
        connection.insert(IsHealth(true));

        // We also have access to request to read thing, but all connection specific things
        // should add this point be copied over the connection which should survive a single request
        // flow. Here this would be TargetHttpVersion since this is used by connector.

        // if Some(version) = request.get::<TargetHttpVersion>() {
        //     connection.insert(version)
        // }

        request.insert(RequestInfoInner);

        // This should have the complete view, unified view is basically a combined time sorted view
        // all events/extensions added in correct order
        println!("request extensions: {:#?}", request.unified_view());

        // This should only see intial request extensions and the connection extensions
        println!("connection extensions: {:#?}", connection.unified_view());

        println!("is healthy {:?}", request.get_smart::<IsHealth>());

        // Now our connection's internal state machine detect it is broken
        // and inserts this in extensions, our request should also be able to see this
        connection.insert(BrokenConnection);
        connection.insert(IsHealth(false));

        // println!("request extensions: {:#?}", request.unified_view());

        println!("is healthy {:?}", request.get_smart::<IsHealth>());

        let history: Vec<_> = request.iter_type::<IsHealth>().collect();
        println!("health history {history:#?}");
    }
}

mod bla {
    use std::{any::TypeId, sync::Arc};

    use parking_lot::RwLock;

    use crate::new::StoredExtensions;

    struct SingleStore(Arc<RwLock<Vec<StoredExtensions>>>);

    struct Storage {
        this: SingleStore,
        others: Vec<SingleStore>,
    }

    #[derive(Clone, Debug)]
    struct Merger;

    impl Storage {
        /// Insert a type into this [`Extensions]` store.
        fn insert<T>(&self, val: T)
        where
            T: Clone + Send + Sync + std::fmt::Debug + 'static,
        {
            // TODO instead of boxing do we arc???

            let extension = StoredExtensions(TypeId::of::<T>(), Box::new(val));
            self.this.0.write().push(extension.clone());
            for other in &self.others {
                other.0.write().push(extension.clone());
            }
        }

        fn register_other(&mut self, other: SingleStore) {
            {
                let mut writer = other.0.write();
                writer.push(StoredExtensions(TypeId::of::<Merger>(), Box::new(Merger)));
                let reader = self.this.0.read();
                writer.extend(reader.iter().cloned());
            }
            self.others.push(other);
        }
    }
}
