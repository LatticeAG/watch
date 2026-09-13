//! Adapter profiles (§1.2/§5). OSS-core ships only the inert fixture
//! profile `fixture/1` handling record.read/record.write. The certified
//! `runtime-guard/1` profile is a documented interface that requires an
//! independently certified runtime implementation — it is NOT implemented
//! here and must never be faked.

use crate::fault::{Code, Fault};

/// Is `profile` a certified adapter profile this build can serve?
pub fn profile_available(profile: &str, certified: &[String]) -> bool {
    certified.iter().any(|p| p == profile) && profile == "fixture/1"
}

/// A runtime-guard/1 adapter requires external certification; the OSS core
/// exposes the interface surface as a NotImplemented error.
pub fn runtime_guard_unavailable() -> Fault {
    Fault::new(
        Code::AdapterUnavailable,
        "runtime-guard/1 requires a separately certified adapter (not implemented in OSS core)",
    )
}
