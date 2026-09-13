//! Fault codes, replies, and the CLI exit mapping.

use crate::json::Value;

/// Wire fault codes (§3.1). Every code has exactly one trigger class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    BadFrame,
    BadJson,
    SchemaInvalid,
    UnsupportedVersion,
    MethodUnknown,
    Unauthenticated,
    Forbidden,
    NotFound,
    StateConflict,
    RevisionConflict,
    IdempotencyConflict,
    RateLimited,
    Capacity,
    Gated,
    AdapterUnavailable,
    PolicyInvalid,
    PolicyStale,
    SignatureInvalid,
    SourceGap,
    SourceFork,
    SourceStale,
    SourceBinding,
    CounterRollback,
    TargetStale,
    ReviewStale,
    LeaseExpired,
    EffectConflict,
    AuditUnavailable,
    CounterExhausted,
    BundleLimit,
    ArtifactUnavailable,
    ClockFault,
    MigrationRequired,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        use Code::*;
        match self {
            BadFrame => "BAD_FRAME",
            BadJson => "BAD_JSON",
            SchemaInvalid => "SCHEMA_INVALID",
            UnsupportedVersion => "UNSUPPORTED_VERSION",
            MethodUnknown => "METHOD_UNKNOWN",
            Unauthenticated => "UNAUTHENTICATED",
            Forbidden => "FORBIDDEN",
            NotFound => "NOT_FOUND",
            StateConflict => "STATE_CONFLICT",
            RevisionConflict => "REVISION_CONFLICT",
            IdempotencyConflict => "IDEMPOTENCY_CONFLICT",
            RateLimited => "RATE_LIMITED",
            Capacity => "CAPACITY",
            Gated => "GATED",
            AdapterUnavailable => "ADAPTER_UNAVAILABLE",
            PolicyInvalid => "POLICY_INVALID",
            PolicyStale => "POLICY_STALE",
            SignatureInvalid => "SIGNATURE_INVALID",
            SourceGap => "SOURCE_GAP",
            SourceFork => "SOURCE_FORK",
            SourceStale => "SOURCE_STALE",
            SourceBinding => "SOURCE_BINDING",
            CounterRollback => "COUNTER_ROLLBACK",
            TargetStale => "TARGET_STALE",
            ReviewStale => "REVIEW_STALE",
            LeaseExpired => "LEASE_EXPIRED",
            EffectConflict => "EFFECT_CONFLICT",
            AuditUnavailable => "AUDIT_UNAVAILABLE",
            CounterExhausted => "COUNTER_EXHAUSTED",
            BundleLimit => "BUNDLE_LIMIT",
            ArtifactUnavailable => "ARTIFACT_UNAVAILABLE",
            ClockFault => "CLOCK_FAULT",
            MigrationRequired => "MIGRATION_REQUIRED",
        }
    }

    /// Only these faults are retryable, with a fixed 1000 ms delay.
    pub fn retryable(self) -> bool {
        matches!(
            self,
            Code::RateLimited | Code::Capacity | Code::AuditUnavailable | Code::SourceStale
        )
    }

    /// CLI exit code mapping (§4).
    pub fn exit_code(self) -> i32 {
        use Code::*;
        match self {
            BadFrame | BadJson | SchemaInvalid | UnsupportedVersion | MethodUnknown
            | PolicyInvalid => 2,
            NotFound | StateConflict | RevisionConflict | IdempotencyConflict | PolicyStale
            | TargetStale | ReviewStale | LeaseExpired | EffectConflict | SourceGap
            | SourceFork | SourceBinding | CounterRollback => 4,
            RateLimited | Capacity | Gated | AdapterUnavailable | AuditUnavailable
            | SourceStale | ClockFault | CounterExhausted | BundleLimit | ArtifactUnavailable => 5,
            SignatureInvalid => 6,
            MigrationRequired => 7,
            // Auth failures are not in the printed table; map to the least
            // surprising stable bucket (4 = access/existence class).
            Unauthenticated | Forbidden => 4,
        }
    }
}

/// A wire fault value.
#[derive(Debug, Clone)]
pub struct Fault {
    pub code: Code,
    pub message: String,
}

impl Fault {
    pub fn new(code: Code, message: &str) -> Fault {
        Fault {
            code,
            message: message.to_string(),
        }
    }
    pub fn to_value(&self) -> Value {
        let mut o = Vec::new();
        o.push(("code".to_string(), Value::str(self.code.as_str())));
        o.push(("message".to_string(), Value::str(&self.message)));
        o.push(("retryable".to_string(), Value::Bool(self.code.retryable())));
        o.push((
            "retry_after_ms".to_string(),
            if self.code.retryable() {
                Value::num(crate::RETRY_AFTER_MS)
            } else {
                Value::Null
            },
        ));
        Value::Obj(o)
    }
}

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for Fault {}

/// Terminal check/verifier states also map into the exit table (§4).
pub fn exit_for_check_state(state: &str) -> i32 {
    match state {
        "CLEAR" => 0,
        "DENY" | "HELD" => 3,
        "CANCELLED" | "STALE" => 4,
        "EXPIRED" => 5,
        "EVALUATING" => 0,
        _ => 0,
    }
}

/// Verifier status exit mapping: FULL_REPLAY=0, INCOMPLETE/INTEGRITY_ONLY=4,
/// INVALID=6.
pub fn exit_for_verify_status(status: &str) -> i32 {
    match status {
        "FULL_REPLAY" => 0,
        "INCOMPLETE" | "INTEGRITY_ONLY" => 4,
        "INVALID" => 6,
        _ => 4,
    }
}
