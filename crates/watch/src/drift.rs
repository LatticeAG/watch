//! The drift reducer (§2.3) — exact state machine over closed windows.

use crate::schema::{Drift, DriftState, Policy};

/// One window's contribution to the drift reducer.
#[derive(Debug, Clone, Copy)]
pub enum WindowInput {
    /// A supplied complete window (samples = total count, score = TVD bp).
    Complete { samples: u64, score: u64 },
    /// An expected window that was never supplied, or a nonconsecutive
    /// (gapped) supplied window: records `data=missing`, establishes
    /// `last_window_ms`, and does not advance a streak.
    Missing,
}

enum Class {
    High,
    Low,
    Middle,
}

fn classify(score: u64, p: &Policy) -> Class {
    if score >= p.drift_high_bp {
        Class::High
    } else if score < p.drift_low_bp {
        Class::Low
    } else {
        Class::Middle
    }
}

/// Advance the drift reducer by one expected window slot at `start_ms`.
/// A repeated `start_ms` (≤ last_window_ms) produces no transition.
pub fn step(prior: &Drift, start_ms: u64, input: WindowInput, p: &Policy) -> Drift {
    let mut next = prior.clone();
    if let Some(last) = prior.last_window_ms {
        if start_ms <= last {
            return next; // repeated window: no transition
        }
    }

    let gapped = prior
        .last_window_ms
        .map(|last| start_ms > last + crate::WINDOW_MS)
        .unwrap_or(false);

    let (class, data) = match input {
        WindowInput::Missing => (None, "missing"),
        WindowInput::Complete { samples, score } => {
            if gapped {
                (None, "missing")
            } else if samples < p.min_window_samples {
                (None, "insufficient")
            } else {
                (Some(classify(score, p)), "complete")
            }
        }
    };

    next.last_window_ms = Some(start_ms);
    next.data = data.to_string();

    let class = match class {
        None => {
            // Missing / insufficient / skipped: reset streaks; DRIFT stays
            // latched, any other state returns to WARMUP.
            next.high_streak = 0;
            next.low_streak = 0;
            next.score_bp = None;
            if next.state != DriftState::Drift {
                next.state = DriftState::Warmup;
            }
            return next;
        }
        Some(c) => c,
    };

    if let WindowInput::Complete { score, .. } = input {
        next.score_bp = Some(score);
    }

    match (prior.state, class) {
        (DriftState::Warmup | DriftState::Stable, Class::High) => {
            next.state = DriftState::Suspect;
            next.high_streak = 1;
            next.low_streak = 0;
        }
        (DriftState::Suspect, Class::High) => {
            let h = prior.high_streak + 1;
            if h >= p.high_windows {
                next.state = DriftState::Drift;
                next.high_streak = p.high_windows;
                next.low_streak = 0;
            } else {
                next.state = DriftState::Suspect;
                next.high_streak = h;
                next.low_streak = 0;
            }
        }
        (DriftState::Warmup | DriftState::Stable | DriftState::Suspect, Class::Low)
        | (DriftState::Warmup | DriftState::Stable | DriftState::Suspect, Class::Middle) => {
            next.state = DriftState::Stable;
            next.high_streak = 0;
            next.low_streak = 0;
        }
        (DriftState::Drift, Class::High) | (DriftState::Drift, Class::Middle) => {
            next.state = DriftState::Drift;
            next.high_streak = 0;
            next.low_streak = 0;
        }
        (DriftState::Drift, Class::Low) => {
            let l = prior.low_streak + 1;
            if l >= p.low_windows {
                next.state = DriftState::Stable;
                next.high_streak = 0;
                next.low_streak = 0;
            } else {
                next.state = DriftState::Drift;
                next.high_streak = 0;
                next.low_streak = l;
            }
        }
    }
    next
}

/// Harness form: fold an ordered window list over an explicit prior.
/// Each entry is `{start, samples, score}`; an entry with `samples: 0` and a
/// synthetic marker is not used — gaps arise from nonconsecutive starts.
pub fn fold(prior: &Drift, windows: &[(u64, u64, u64)], p: &Policy) -> Drift {
    let mut d = prior.clone();
    for (start, samples, score) in windows {
        d = step(
            &d,
            *start,
            WindowInput::Complete {
                samples: *samples,
                score: *score,
            },
            p,
        );
    }
    d
}
