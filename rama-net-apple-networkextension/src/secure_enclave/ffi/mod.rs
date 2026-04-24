pub(super) mod core_foundation;

pub(crate) use core_foundation::{
    CfData, CfNumber, CfOwned, CfString, QueryDictionary, cf_error, cf_release,
};
