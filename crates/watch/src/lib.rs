//! LatticeAGI Watch — zone core.
//!
//! Deterministic blocking/trailing monitors, drift detection, audit arithmetic,
//! the human remainder queue, signed evidence, and the offline bundle verifier.
//!
//! Status: UNWRITTEN — GATED BEHIND COVENANT v1. This crate is the open-source
//! core of the Watch zone (`watch/1`); it is not a release or certification.

pub mod adapters;
pub mod aggregate;
pub mod auditmath;
pub mod backup;
pub mod bundle;
pub mod clock;
pub mod config;
pub mod conform;
pub mod crypto;
pub mod daemon;
pub mod detect;
pub mod doctor;
pub mod drift;
pub mod events;
pub mod fault;
pub mod fixture;
pub mod guard;
pub mod ids;
pub mod json;
pub mod methods;
pub mod metrics;
pub mod monitor;
pub mod objects;
pub mod schema;
pub mod server;
pub mod store;
pub mod verify;

/// Wire/product constants.
pub const PROTOCOL: &str = "watch/1";
pub const PRODUCT_STATUS: &str = "UNWRITTEN_GATED";
pub const PROFILE: &str = "lab/1";
/// Request frame bound (bytes).
pub const REQ_MAX: usize = 1_048_576;
/// Reply frame bound (bytes).
pub const REPLY_MAX: usize = 8_388_608;
/// Offline bundle parse bound (bytes).
pub const BUNDLE_PARSE_MAX: usize = 67_108_864;
/// Generic JSON object depth bound.
pub const DEPTH_MAX: usize = 24;
/// Generic members-per-object bound.
pub const MEMBERS_MAX: usize = 128;
/// Generic array length bound.
pub const ARRAY_MAX: usize = 4096;
/// Generic sorted-set bound.
pub const SET_MAX: usize = 64;
/// Text bound in UTF-8 bytes.
pub const TEXT_MAX: usize = 512;
/// Maximum safe integer token on the wire.
pub const SAFE_INT_MAX: u64 = 9_007_199_254_740_991;
/// Maximum U counter value (signed 64).
pub const U_MAX: u64 = 9_223_372_036_854_775_807;
/// Trailing window width in ms (fixed).
pub const WINDOW_MS: u64 = 10_000;
/// Trailing window settle delay after window end (ms).
pub const WINDOW_DUE_MS: u64 = 500;
/// Per-principal request rate: sustained / burst.
pub const RATE_PER_SEC: u64 = 100;
pub const RATE_BURST: u64 = 100;
/// Connection caps.
pub const CONN_PER_PRINCIPAL: usize = 8;
pub const CONN_TOTAL: usize = 64;
/// In-flight check caps.
pub const CHECK_TOTAL: usize = 128;
pub const CHECK_PER_RUN: usize = 16;
/// Active run cap.
pub const RUN_TOTAL: usize = 64;
/// Listing page bound.
pub const PAGE_MAX: usize = 100;
/// Retry delay (ms) attached to retryable faults.
pub const RETRY_AFTER_MS: u64 = 1000;
/// Internal monitor reply bound (bytes).
pub const MONITOR_REPLY_MAX: usize = 65_536;
