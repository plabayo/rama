//! Typed ids for the units crates share: a key one crate assigns and another
//! reads back.

use rama_core::define_id;

define_id! {
    /// Identifies one connection: whoever creates the connection inserts it in
    /// its extensions, everyone else reads it from there.
    pub struct ConnectionId;
}

define_id! {
    /// Identifies one request and response exchange carried by a connection,
    /// whatever the protocol.
    pub struct RequestId;
}

#[cfg(test)]
mod tests {
    use super::ConnectionId;
    use rama_core::extensions::Extensions;

    #[test]
    fn a_fork_inherits_the_id_until_it_inserts_its_own() {
        let connection = Extensions::new();
        let parent = ConnectionId::next();
        connection.insert(parent);

        let fork = connection.fork();
        assert_eq!(fork.get_ref::<ConnectionId>(), Some(&parent));

        let own = ConnectionId::next();
        fork.insert(own);
        assert_ne!(own, parent);
        assert_eq!(fork.get_ref::<ConnectionId>(), Some(&own));
        assert_eq!(
            connection.get_ref::<ConnectionId>(),
            Some(&parent),
            "the parent keeps its own id"
        );
    }
}
