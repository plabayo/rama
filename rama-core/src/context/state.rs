#[cfg(test)]
mod test {
    use std::ops::Deref;
    use std::sync::atomic::AtomicU64;
    use std::sync::Arc;

    use crate::context::AsRef;

    struct Database;

    #[derive(AsRef)]
    struct State {
        db: Database,
    }

    #[derive(AsRef)]
    struct ConnectionState {
        inner: Arc<State>,
        counter: Arc<AtomicU64>,
    }

    impl<T> AsRef<T> for ConnectionState
    where
        State: AsRef<T>,
    {
        fn as_ref(&self) -> &T {
            self.inner.deref().as_ref()
        }
    }

    impl From<Arc<State>> for ConnectionState {
        fn from(inner: Arc<State>) -> Self {
            Self {
                inner,
                counter: Arc::new(AtomicU64::new(0)),
            }
        }
    }

    fn assert_database<T: AsRef<Database>>(_t: &T) {}
    fn assert_counter<T: AsRef<Arc<AtomicU64>>>(_t: &T) {}

    #[test]
    fn test_state_wrapper() {
        let state = Arc::new(State { db: Database });
        let connection_state = ConnectionState::from(state.clone());

        assert_database(state.deref());
        assert_database(&connection_state);
        assert_counter(&connection_state);
    }
}
