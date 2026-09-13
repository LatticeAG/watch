//! The five pinned deterministic detectors (§1.4) and exact-integer TVD.

use crate::drift;
use crate::schema::*;

/// `TVD_bp = floor(10000 * sum_i(abs(current_i*B - baseline_i*C)) / (2*C*B))`
/// with B, C the exact count totals. Arbitrary precision via u128; floors once.
/// Returns None when a total is zero (unreachable for admitted windows).
pub fn tvd_bp(baseline: &[u64; 4], current: &[u64; 4]) -> Option<u64> {
    let b: u128 = baseline.iter().map(|x| *x as u128).sum();
    let c: u128 = current.iter().map(|x| *x as u128).sum();
    if b == 0 || c == 0 {
        return None;
    }
    let mut num: u128 = 0;
    for i in 0..4 {
        let cur = current[i] as u128 * b;
        let base = baseline[i] as u128 * c;
        num += cur.abs_diff(base);
    }
    let score = (10_000u128 * num) / (2 * c * b);
    Some(score.min(10_000) as u64)
}

fn res(
    monitor: &Monitor,
    verdict: Verdict,
    reason: &str,
    score_bp: Option<u64>,
    ev: Vec<Ref>,
) -> Result_ {
    Result_ {
        monitor: monitor.id.clone(),
        detector: monitor.detector,
        verdict,
        reason: reason.to_string(),
        score_bp,
        evidence: ev,
    }
}

/// Evaluate one pinned detector against one observation (+ intent for
/// blocking). Pure: same inputs always yield the same Result.
pub fn evaluate(
    monitor: &Monitor,
    policy: &Policy,
    body: &ObservationBody,
    obs_ref: Option<Ref>,
    intent: Option<&Intent>,
    drift_state: Option<&Drift>,
) -> Result_ {
    let ev: Vec<Ref> = obs_ref.into_iter().collect();
    match monitor.detector {
        Detector::Scope => {
            let bad_snap = !body
                .snapshot
                .scopes
                .iter()
                .all(|s| policy.allowed_scopes.contains(s));
            let bad_intent = intent
                .map(|i| !i.scopes.iter().all(|s| policy.allowed_scopes.contains(s)))
                .unwrap_or(false);
            if bad_snap || bad_intent {
                res(monitor, Verdict::Flag, "SCOPE_DRIFT", None, ev)
            } else {
                res(monitor, Verdict::Clear, "SCOPE_OK", None, ev)
            }
        }
        Detector::Spend => {
            let cost = intent.map(|i| i.cost_minor).unwrap_or(0);
            let total = body
                .snapshot
                .committed_minor
                .saturating_add(body.snapshot.reserved_minor)
                .saturating_add(cost);
            if total > policy.cap_minor {
                res(monitor, Verdict::Flag, "SPEND_CAP", None, ev)
            } else if cost >= policy.review_at_minor {
                res(monitor, Verdict::Uncertain, "LARGE_ACTION", None, ev)
            } else {
                res(monitor, Verdict::Clear, "SPEND_OK", None, ev)
            }
        }
        Detector::Replicas => match body.snapshot.replicas {
            None => res(monitor, Verdict::Unavailable, "REPLICA_UNKNOWN", None, ev),
            Some(c) if c > policy.max_replicas => {
                res(monitor, Verdict::Flag, "REPLICATION_DRIFT", None, ev)
            }
            Some(_) => res(monitor, Verdict::Clear, "REPLICAS_OK", None, ev),
        },
        Detector::Rate => match &body.snapshot.window {
            None => res(monitor, Verdict::Unavailable, "WINDOW_MISSING", None, ev),
            Some(w) => {
                let total: u64 = w.counts.iter().sum();
                if total > policy.rate_per_window {
                    res(monitor, Verdict::Flag, "RATE_SPIKE", None, ev)
                } else {
                    res(monitor, Verdict::Clear, "RATE_OK", None, ev)
                }
            }
        },
        Detector::Distribution => match &body.snapshot.window {
            None => res(monitor, Verdict::Unavailable, "WINDOW_MISSING", None, ev),
            Some(w) => {
                let samples: u64 = w.counts.iter().sum();
                if samples < policy.min_window_samples {
                    return res(monitor, Verdict::Unavailable, "BASELINE_WARMUP", None, ev);
                }
                let score = tvd_bp(&policy.baseline.counts, &w.counts).unwrap_or(0);
                let prior = drift_state.cloned().unwrap_or(Drift {
                    state: DriftState::Warmup,
                    high_streak: 0,
                    low_streak: 0,
                    last_window_ms: None,
                    score_bp: None,
                    data: "insufficient".to_string(),
                });
                let next = drift::step(
                    &prior,
                    w.start_ms,
                    drift::WindowInput::Complete { samples, score },
                    policy,
                );
                let (verdict, reason) = match next.state {
                    DriftState::Drift => (Verdict::Flag, "DISTRIBUTION_DRIFT"),
                    DriftState::Suspect => (Verdict::Uncertain, "DISTRIBUTION_SUSPECT"),
                    DriftState::Stable => (Verdict::Clear, "DISTRIBUTION_OK"),
                    DriftState::Warmup => (Verdict::Clear, "DISTRIBUTION_OK"),
                };
                res(monitor, verdict, reason, Some(score), ev)
            }
        },
    }
}
