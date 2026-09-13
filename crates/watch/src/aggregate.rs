//! Blocking aggregation (§1.4/§2.2), deadline rule, and findings digests.

use crate::crypto::d;
use crate::json::Value;
use crate::schema::*;

/// One settled-or-missing required monitor slot, in monitor-ID order.
pub type Slot = Option<Result_>;

/// The finalized blocking outcome class.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Clear,
    Deny(String),
    /// HELD on the check's own remainder; `new_review` false means an
    /// identical active basis already exists and no queue slot was consumed.
    Held {
        reason: String,
        new_review: bool,
    },
    Expired(String),
}

/// Queue-admission context for the uncertain path.
pub struct QueueCtx {
    pub depth: u64,
    pub per_run_open: u64,
    pub queue_capacity: u64,
    pub per_run_cap: u64,
    /// An active review with the identical basis already exists.
    pub existing_basis: bool,
}

/// §1.4 aggregation over the complete required result vector:
/// hard flag → DENY (first flagged reason in monitor-ID order);
/// any unavailable/deadline-missing required result → EXPIRED;
/// uncertain → HELD unless a queue position is needed and full → DENY.
/// Otherwise CLEAR. A `None` slot is a deadline-missing result.
pub fn aggregate(slots: &[Slot], q: &QueueCtx) -> Outcome {
    for r in slots.iter().flatten() {
        if r.verdict == Verdict::Flag {
            return Outcome::Deny(r.reason.clone());
        }
    }
    for s in slots {
        match s {
            None => return Outcome::Expired("MONITOR_TIMEOUT".to_string()),
            Some(r) if r.verdict == Verdict::Unavailable => {
                return Outcome::Expired("MONITOR_UNAVAILABLE".to_string())
            }
            _ => {}
        }
    }
    let uncertain: Vec<&Result_> = slots
        .iter()
        .filter_map(|s| s.as_ref())
        .filter(|r| r.verdict == Verdict::Uncertain)
        .collect();
    if !uncertain.is_empty() {
        let reason = uncertain[0].reason.clone();
        if q.existing_basis {
            return Outcome::Held {
                reason,
                new_review: false,
            };
        }
        if q.depth >= q.queue_capacity || q.per_run_open >= q.per_run_cap {
            return Outcome::Deny("QUEUE_FULL".to_string());
        }
        return Outcome::Held {
            reason,
            new_review: true,
        };
    }
    Outcome::Clear
}

/// `D("findings", uncertain results sorted by monitor with evidence=[])`.
pub fn findings_digest(results: &[Result_]) -> String {
    let mut uncertain: Vec<&Result_> = results
        .iter()
        .filter(|r| r.verdict == Verdict::Uncertain)
        .collect();
    uncertain.sort_by(|a, b| a.monitor.cmp(&b.monitor));
    let vals: Vec<Value> = uncertain
        .into_iter()
        .map(|r| {
            let mut r2 = r.clone();
            r2.evidence = Vec::new();
            result_value(&r2)
        })
        .collect();
    d("findings", &Value::Arr(vals))
}

/// `D("basis", Basis)` — the review dedup key stored in reviews.basis.
pub fn basis_digest(b: &Basis) -> String {
    d("basis", &basis_value(b))
}

/// `D("intent", Intent)` — the internal non-signature commitment.
pub fn intent_digest(i: &Intent) -> String {
    d("intent", &intent_value(i))
}

/// Episode key `J({run,monitor,baseline})` used by the alert index.
pub fn episode_key(run: &str, monitor: &str, baseline: &str) -> String {
    crate::json::jcs(&Value::obj(vec![
        ("run", Value::str(run)),
        ("monitor", Value::str(monitor)),
        ("baseline", Value::str(baseline)),
    ]))
}

/// `wta_` + first 32 hex chars of D("alert-id",{run,monitor,baseline,first}).
pub fn alert_id(run: &str, monitor: &str, baseline: &str, first: &Ref) -> String {
    let body = Value::obj(vec![
        ("run", Value::str(run)),
        ("monitor", Value::str(monitor)),
        ("baseline", Value::str(baseline)),
        ("first", ref_value(first)),
    ]);
    format!("wta_{}", &d("alert-id", &body)[..32])
}

/// `wth_` + first 32 hex chars of D("review-id",{run,basis,alert,origin_check}).
/// `basis` is the Basis *digest*; `origin_check` is the creating check or null.
pub fn review_id(
    run: &str,
    basis: Option<&str>,
    alert: Option<&str>,
    origin: Option<&str>,
) -> String {
    let body = Value::obj(vec![
        ("run", Value::str(run)),
        ("basis", basis.map(Value::str).unwrap_or(Value::Null)),
        ("alert", alert.map(Value::str).unwrap_or(Value::Null)),
        (
            "origin_check",
            origin.map(Value::str).unwrap_or(Value::Null),
        ),
    ]);
    format!("wth_{}", &d("review-id", &body)[..32])
}

/// A worker response received at or after its deadline is late evidence only.
pub fn worker_late(worker_deadline_ms: u64, received_ms: u64) -> bool {
    received_ms >= worker_deadline_ms
}
