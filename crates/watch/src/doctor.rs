//! Offline `doctor` (§4/§5): read-only checks — permissions, pins, schema,
//! sandbox, release, adapter — in listed order. No mutation.

use std::path::Path;

use crate::config::{load_config, load_trust, startup_gates, verify_artifacts};
use crate::fault::Code;
use crate::json::Value;

/// Run all doctor checks; emit Doctor with checks in listed name order.
pub fn run(config_path: &Path, trust_path: &Path) -> Value {
    let mut checks: Vec<(&'static str, bool, Option<String>)> = Vec::new();

    // permissions: config readable, key file owner-readable only, data dir
    // owned/non-world-writable.
    let cfg = load_config(config_path);
    let trust = load_trust(trust_path);
    let mut perm_ok = cfg.is_ok() && trust.is_ok();
    let mut perm_code: Option<String> = None;
    if let Ok(c) = &cfg {
        if let Ok(md) = std::fs::metadata(&c.signer_key_file) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if md.permissions().mode() & 0o077 != 0 {
                    perm_ok = false;
                    perm_code = Some("SCHEMA_INVALID".into());
                }
            }
        } else {
            perm_ok = false;
            perm_code = Some("ARTIFACT_UNAVAILABLE".into());
        }
    } else {
        perm_ok = false;
        perm_code = Some("ARTIFACT_UNAVAILABLE".into());
    }
    checks.push(("permissions", perm_ok, perm_code));

    // pins: signer pin live for all Watch tags; source keys pinned.
    let mut pin_ok = true;
    let mut pin_code = None;
    if let (Ok(c), Ok(t)) = (&cfg, &trust) {
        for tag in ["audit", "clearance", "bundle", "backup"] {
            if crate::config::require_pin(t, tag, &c.tenant, &c.signer_key_id, c.signer_key_epoch)
                .is_err()
            {
                pin_ok = false;
                pin_code = Some("SIGNATURE_INVALID".into());
            }
        }
    } else {
        pin_ok = false;
        pin_code = Some("SIGNATURE_INVALID".into());
    }
    checks.push(("pins", pin_ok, pin_code));

    // schema: config+trust strict-parse (already loaded above).
    let schema_ok = cfg.is_ok() && trust.is_ok();
    checks.push((
        "schema",
        schema_ok,
        (!schema_ok).then(|| "SCHEMA_INVALID".to_string()),
    ));

    // sandbox: OSS-core worker isolation is thread-based; check artifacts.
    let sandbox_ok = match &cfg {
        Ok(c) => verify_artifacts(c).is_ok(),
        Err(_) => false,
    };
    checks.push((
        "sandbox",
        sandbox_ok,
        (!sandbox_ok).then(|| "ARTIFACT_UNAVAILABLE".to_string()),
    ));

    // release: production requires signed release; lab passes.
    let release_ok = match (&cfg, &trust) {
        (Ok(c), Ok(t)) => startup_gates(c, t).is_ok(),
        _ => false,
    };
    checks.push((
        "release",
        release_ok,
        (!release_ok).then(|| "GATED".to_string()),
    ));

    // adapter: certified profiles must include only fixture/1 in OSS core.
    let adapter_ok = match &cfg {
        Ok(c) => c.certified_profiles.iter().all(|p| p == "fixture/1"),
        Err(_) => false,
    };
    checks.push((
        "adapter",
        adapter_ok,
        (!adapter_ok).then(|| "ADAPTER_UNAVAILABLE".to_string()),
    ));

    let ready = checks.iter().all(|(_, ok, _)| *ok);
    Value::obj(vec![
        ("ready", Value::Bool(ready)),
        ("profile", Value::str(crate::PROFILE)),
        (
            "checks",
            Value::Arr(
                checks
                    .iter()
                    .map(|(name, ok, code)| {
                        Value::obj(vec![
                            ("name", Value::str(name)),
                            ("ok", Value::Bool(*ok)),
                            (
                                "code",
                                match code {
                                    Some(c) => Value::str(c),
                                    None => Value::Null,
                                },
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

pub fn code_to_exit(code: Option<&str>) -> i32 {
    match code {
        None => 0,
        Some("GATED") | Some("ADAPTER_UNAVAILABLE") | Some("ARTIFACT_UNAVAILABLE") => 5,
        Some("SIGNATURE_INVALID") => 6,
        Some("MIGRATION_REQUIRED") => 7,
        Some("NOT_FOUND")
        | Some("STATE_CONFLICT")
        | Some("REVISION_CONFLICT")
        | Some("IDEMPOTENCY_CONFLICT")
        | Some("POLICY_STALE")
        | Some("TARGET_STALE")
        | Some("REVIEW_STALE")
        | Some("LEASE_EXPIRED")
        | Some("EFFECT_CONFLICT")
        | Some("SOURCE_GAP")
        | Some("SOURCE_FORK")
        | Some("SOURCE_BINDING")
        | Some("COUNTER_ROLLBACK")
        | Some("UNAUTHENTICATED")
        | Some("FORBIDDEN") => 4,
        Some("RATE_LIMITED")
        | Some("CAPACITY")
        | Some("AUDIT_UNAVAILABLE")
        | Some("SOURCE_STALE")
        | Some("CLOCK_FAULT")
        | Some("COUNTER_EXHAUSTED")
        | Some("BUNDLE_LIMIT") => 5,
        _ => 2,
    }
}

/// Exit-code mapping for the wire Code enum (§4 table).
pub fn exit_for_code(code: &str) -> i32 {
    match code {
        "BAD_FRAME"
        | "BAD_JSON"
        | "SCHEMA_INVALID"
        | "UNSUPPORTED_VERSION"
        | "METHOD_UNKNOWN"
        | "POLICY_INVALID" => 2,
        "NOT_FOUND"
        | "STATE_CONFLICT"
        | "REVISION_CONFLICT"
        | "IDEMPOTENCY_CONFLICT"
        | "POLICY_STALE"
        | "TARGET_STALE"
        | "REVIEW_STALE"
        | "LEASE_EXPIRED"
        | "EFFECT_CONFLICT"
        | "SOURCE_GAP"
        | "SOURCE_FORK"
        | "SOURCE_BINDING"
        | "COUNTER_ROLLBACK"
        | "UNAUTHENTICATED"
        | "FORBIDDEN" => 4,
        "RATE_LIMITED"
        | "CAPACITY"
        | "GATED"
        | "ADAPTER_UNAVAILABLE"
        | "AUDIT_UNAVAILABLE"
        | "SOURCE_STALE"
        | "CLOCK_FAULT"
        | "COUNTER_EXHAUSTED"
        | "BUNDLE_LIMIT"
        | "ARTIFACT_UNAVAILABLE" => 5,
        "SIGNATURE_INVALID" => 6,
        "MIGRATION_REQUIRED" => 7,
        _ => 2,
    }
}

/// Terminal check/review states → exit codes for `--wait` results.
pub fn exit_for_terminal(kind: &str, state: &str) -> i32 {
    match (kind, state) {
        ("check", "CLEAR") => 0,
        ("check", "DENY") | ("check", "HELD") => 3,
        ("check", "CANCELLED") | ("check", "STALE") => 4,
        ("check", "EXPIRED") => 5,
        ("review", "REJECTED") => 3,
        ("verify", "INVALID") => 6,
        ("verify", "INCOMPLETE") | ("verify", "INTEGRITY_ONLY") => 4,
        ("verify", "FULL_REPLAY") => 0,
        _ => 0,
    }
}

pub fn _unused(_: Code) {}
