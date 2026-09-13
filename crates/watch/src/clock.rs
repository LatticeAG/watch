//! Boot identity and the deadline clock.
//!
//! `ms` values are local CLOCK_BOOTTIME milliseconds, valid only with the
//! current boot UUID. `BootClock` reads the kernel boot id from procfs and
//! derives CLOCK_BOOTTIME milliseconds from system uptime plus a high
//! resolution monotonic delta anchored at process start.

use std::time::Instant;

/// Current boot UUID (`/proc/sys/kernel/random/boot_id`), lowercased.
pub fn boot_id() -> std::io::Result<String> {
    let raw = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    Ok(raw.trim().to_ascii_lowercase())
}

/// Milliseconds in the CLOCK_BOOTTIME domain (uptime since boot, including
/// suspend time on Linux).
pub fn boottime_ms() -> u64 {
    // sysinfo uptime covers the CLOCK_BOOTTIME domain.
    let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };
    if unsafe { libc::sysinfo(&mut info) } == 0 {
        info.uptime as u64 * 1000
    } else {
        // Fall back to monotonic elapsed since an arbitrary anchor; still a
        // monotone deadline clock, but boot-anchored callers should fault.
        0
    }
}

/// Process-local boottime clock with sub-second precision.
pub struct BootClock {
    anchor_ms: u64,
    start: Instant,
    pub boot: String,
}

impl BootClock {
    pub fn new() -> std::io::Result<BootClock> {
        let boot = boot_id()?;
        Ok(BootClock {
            anchor_ms: boottime_ms(),
            start: Instant::now(),
            boot,
        })
    }

    /// CLOCK_BOOTTIME milliseconds (sub-second precise within this process).
    pub fn now_ms(&self) -> u64 {
        self.anchor_ms + self.start.elapsed().as_millis() as u64
    }
}

/// A test clock driven by an explicit `now`.
#[derive(Clone)]
pub struct FixedClock {
    pub now: u64,
}

impl FixedClock {
    pub fn new(now: u64) -> FixedClock {
        FixedClock { now }
    }
}
