//! Derive bounded distributions and ordering rules from retained evidence.
//!
//! Analysis is reproducible from evidence; it does not create new observations
//! or establish that a provider can replay every observed component.

pub mod order;

pub mod capture;

pub mod numeric;

pub mod profile;
