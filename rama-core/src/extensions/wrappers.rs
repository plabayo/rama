use rama_utils::macros::impl_deref;

use super::Extension;

#[derive(Debug, Clone, Extension)]
/// Ingress connection wrapper use by servers
pub struct Ingress<T>(pub T);

impl_deref!(Ingress);

#[derive(Debug, Clone, Extension)]
/// Egress connection wrapper use by client
pub struct Egress<T>(pub T);

impl_deref!(Egress);

#[cfg(test)]
mod tests {
    use crate::extensions::tests::*;
    use crate::extensions::{Egress, Extensions, Ingress};

    #[test]
    fn ingress_view_walks_parent() {
        let conn_ext = Extensions::new();
        conn_ext.insert(ConnSocketInfo("client-in"));

        let req = Extensions::new();
        req.insert(Ingress(conn_ext));

        assert_eq!(
            req.ingress().and_then(|i| i.get_ref::<ConnSocketInfo>()),
            Some(&ConnSocketInfo("client-in"))
        );
    }

    #[test]
    fn egress_view_walks_parent() {
        let conn_ext = Extensions::new();
        conn_ext.insert(ConnSocketInfo("egress-side"));

        let req = Extensions::new();
        req.insert(Egress(conn_ext));

        assert_eq!(
            req.egress().and_then(|e| e.get_ref::<ConnSocketInfo>()),
            Some(&ConnSocketInfo("egress-side"))
        );
    }

    #[test]
    fn ingress_egress_disambiguate_in_mitm() {
        let in_conn = Extensions::new();
        in_conn.insert(ConnSocketInfo("in"));
        let out_conn = Extensions::new();
        out_conn.insert(ConnSocketInfo("out"));

        let req = Extensions::new();
        req.insert(Ingress(in_conn));
        req.insert(Egress(out_conn));

        assert_eq!(
            req.ingress().and_then(|i| i.get_ref::<ConnSocketInfo>()),
            Some(&ConnSocketInfo("in"))
        );
        assert_eq!(
            req.egress().and_then(|e| e.get_ref::<ConnSocketInfo>()),
            Some(&ConnSocketInfo("out"))
        );
    }

    #[test]
    fn egress_view_walks_through_parent_to_find_wrapper() {
        let conn_ext = Extensions::new();
        conn_ext.insert(ConnSocketInfo("inside-parent"));
        let req = Extensions::new();
        req.insert(Egress(conn_ext));

        let resp = req.fork();
        assert_eq!(
            resp.egress().and_then(|e| e.get_ref::<ConnSocketInfo>()),
            Some(&ConnSocketInfo("inside-parent"))
        );
    }

    #[test]
    fn ingress_egress_return_none_when_absent() {
        let req = Extensions::new();
        assert!(req.ingress().is_none());
        assert!(req.egress().is_none());
    }

    #[test]
    fn iter_ref_yields_local_then_parent_newest_to_oldest() {
        let parent = Extensions::new();
        parent.insert(RequestId(1));
        parent.insert(RequestId(2));

        let child = parent.fork();
        child.insert(RequestId(3));
        child.insert(RequestId(4));

        let ids: Vec<_> = child.iter_ref::<RequestId>().map(|r| r.0).collect();
        assert_eq!(ids, vec![4, 3, 2, 1]);
    }

    #[test]
    fn iter_ref_walks_egress_and_ingress_wrappers_inline() {
        let conn_in = Extensions::new();
        conn_in.insert(RequestId(10));
        conn_in.insert(RequestId(11));
        let conn_out = Extensions::new();
        conn_out.insert(RequestId(20));

        let req = Extensions::new();
        req.insert(RequestId(1));
        req.insert(Ingress(conn_in));
        req.insert(Egress(conn_out));

        let ids: Vec<_> = req.iter_ref::<RequestId>().map(|r| r.0).collect();
        assert_eq!(ids, vec![20, 11, 10, 1]);
    }

    #[test]
    fn local_direct_after_wrapper_shadows_wrapper() {
        let conn = Extensions::new();
        conn.insert(RequestId(99));
        let req = Extensions::new();
        req.insert(Ingress(conn));
        req.insert(RequestId(1));

        assert_eq!(req.get_ref::<RequestId>(), Some(&RequestId(1)));
    }

    #[test]
    fn wrapper_after_local_direct_shadows_direct() {
        let conn = Extensions::new();
        conn.insert(RequestId(99));
        let req = Extensions::new();
        req.insert(RequestId(1));
        req.insert(Ingress(conn));

        assert_eq!(req.get_ref::<RequestId>(), Some(&RequestId(99)));
    }
}
