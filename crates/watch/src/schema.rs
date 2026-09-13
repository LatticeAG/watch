//! Closed-schema validators for every wire object (§1.1–§1.3, §3.4, §5.1, §6.1).
//!
//! Every listed member is required, including nullable members; unknown
//! members are `SCHEMA_INVALID`. Scalar and cross-field rules are runtime
//! validation, not type hints.

use crate::crypto::{is_pub, is_sig};
use crate::fault::{Code, Fault};
use crate::ids::*;
use crate::json::{u_str, Value};

pub type R<T> = Result<T, Fault>;

fn err(code: Code, msg: &str) -> Fault {
    Fault::new(code, msg)
}

pub fn schem(msg: &str) -> Fault {
    err(Code::SchemaInvalid, msg)
}

pub fn missing(_name: &str) -> Fault {
    schem("required member missing")
}

pub fn field<'a>(m: &'a [(String, Value)], name: &str) -> R<&'a Value> {
    m.iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v)
        .ok_or_else(|| missing(name))
}

pub fn closed(m: &[(String, Value)], allowed: &[&str]) -> R<()> {
    for (k, _) in m {
        if !allowed.contains(&k.as_str()) {
            return Err(schem("unknown member"));
        }
    }
    Ok(())
}

pub fn obj(v: &Value) -> R<&[(String, Value)]> {
    v.as_obj().ok_or_else(|| schem("expected object"))
}

pub fn arr(v: &Value) -> R<&[Value]> {
    v.as_arr().ok_or_else(|| schem("expected array"))
}

pub fn s(v: &Value) -> R<&str> {
    v.as_str().ok_or_else(|| schem("expected string"))
}

pub fn boolean(v: &Value) -> R<bool> {
    v.as_bool().ok_or_else(|| schem("expected boolean"))
}

/// Number token (nonnegative safe integer).
pub fn n(v: &Value) -> R<u64> {
    v.as_int()
        .ok_or_else(|| schem("expected integer number token"))
}

/// U counter (canonical decimal string ≤ 2^63-1).
pub fn u(v: &Value) -> R<u64> {
    let st = s(v)?;
    u_str(st).ok_or_else(|| schem("invalid U counter"))
}

pub fn opt_u(v: &Value) -> R<Option<u64>> {
    if *v == Value::Null {
        Ok(None)
    } else {
        Ok(Some(u(v)?))
    }
}

pub fn opt_n(v: &Value) -> R<Option<u64>> {
    if *v == Value::Null {
        Ok(None)
    } else {
        Ok(Some(n(v)?))
    }
}

pub fn opt_id(v: &Value) -> R<Option<String>> {
    if *v == Value::Null {
        Ok(None)
    } else {
        Ok(Some(id(v)?))
    }
}

pub fn opt_hash(v: &Value) -> R<Option<String>> {
    if *v == Value::Null {
        Ok(None)
    } else {
        Ok(Some(hash(v)?))
    }
}

pub fn opt_text(v: &Value) -> R<Option<String>> {
    if *v == Value::Null {
        Ok(None)
    } else {
        Ok(Some(text(v)?))
    }
}

pub fn id(v: &Value) -> R<String> {
    let st = s(v)?;
    if valid_id(st) {
        Ok(st.to_string())
    } else {
        Err(schem("invalid Id"))
    }
}

pub fn hash(v: &Value) -> R<String> {
    let st = s(v)?;
    if valid_hash(st) {
        Ok(st.to_string())
    } else {
        Err(schem("invalid Hash"))
    }
}

pub fn text(v: &Value) -> R<String> {
    let st = s(v)?;
    if valid_text(st) {
        Ok(st.to_string())
    } else {
        Err(schem("invalid Text"))
    }
}

pub fn boot(v: &Value) -> R<String> {
    let st = s(v)?;
    if valid_boot(st) {
        Ok(st.to_string())
    } else {
        Err(schem("invalid Boot"))
    }
}

pub fn sig(v: &Value) -> R<String> {
    let st = s(v)?;
    if is_sig(st) {
        Ok(st.to_string())
    } else {
        Err(schem("invalid Sig"))
    }
}

pub fn pubkey(v: &Value) -> R<String> {
    let st = s(v)?;
    if is_pub(st) {
        Ok(st.to_string())
    } else {
        Err(schem("invalid Pub"))
    }
}

pub fn id_list(v: &Value) -> R<Vec<String>> {
    let items: R<Vec<String>> = arr(v)?.iter().map(id).collect();
    let items = items?;
    if !valid_id_set(&items) {
        return Err(schem("id set not sorted/unique"));
    }
    Ok(items)
}

/// causes — a bounded set of hash commitments (SET_MAX).
pub fn hash_list(v: &Value) -> R<Vec<String>> {
    let items: R<Vec<String>> = arr(v)?.iter().map(hash).collect();
    let items = items?;
    if items.len() > crate::SET_MAX {
        return Err(schem("hash set too large"));
    }
    Ok(items)
}

/// event_hashes — an array bound by ARRAY_MAX, not a set.
pub fn hash_array(v: &Value) -> R<Vec<String>> {
    let items: R<Vec<String>> = arr(v)?.iter().map(hash).collect();
    let items = items?;
    if items.len() > crate::ARRAY_MAX {
        return Err(schem("hash array too large"));
    }
    Ok(items)
}

pub fn lit_str(v: &Value, want: &str) -> R<()> {
    if s(v)? == want {
        Ok(())
    } else {
        Err(schem("unexpected literal"))
    }
}

pub fn lit_num(v: &Value, want: u64) -> R<()> {
    if n(v)? == want {
        Ok(())
    } else {
        Err(schem("unexpected literal number"))
    }
}

pub fn bins(v: &Value) -> R<[u64; 4]> {
    let a = arr(v)?;
    if a.len() != 4 {
        return Err(schem("Bins needs 4 entries"));
    }
    Ok([u(&a[0])?, u(&a[1])?, u(&a[2])?, u(&a[3])?])
}

pub fn bins_to_value(b: &[u64; 4]) -> Value {
    Value::Arr(b.iter().map(|c| Value::ustr(&c.to_string())).collect())
}

// ---------------------------------------------------------------------------
// Primitive compound types

#[derive(Debug, Clone, PartialEq)]
pub struct Head {
    pub seq: u64,
    pub hash: String,
}

pub fn head(v: &Value) -> R<Head> {
    let m = obj(v)?;
    closed(m, &["seq", "hash"])?;
    Ok(Head {
        seq: u(field(m, "seq")?)?,
        hash: hash(field(m, "hash")?)?,
    })
}

pub fn head_value(h: &Head) -> Value {
    Value::obj(vec![
        ("seq", Value::ustr(&h.seq.to_string())),
        ("hash", Value::str(&h.hash)),
    ])
}

/// The genesis head: seq 0, hash = 64 zero hex chars.
pub fn empty_head() -> Head {
    Head {
        seq: 0,
        hash: "0".repeat(64),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Ref {
    pub source: String,
    pub epoch: u64,
    pub seq: u64,
    pub hash: String,
}

pub fn ref_(v: &Value) -> R<Ref> {
    let m = obj(v)?;
    closed(m, &["source", "epoch", "seq", "hash"])?;
    Ok(Ref {
        source: id(field(m, "source")?)?,
        epoch: u(field(m, "epoch")?)?,
        seq: u(field(m, "seq")?)?,
        hash: hash(field(m, "hash")?)?,
    })
}

pub fn ref_value(r: &Ref) -> Value {
    Value::obj(vec![
        ("source", Value::str(&r.source)),
        ("epoch", Value::ustr(&r.epoch.to_string())),
        ("seq", Value::ustr(&r.seq.to_string())),
        ("hash", Value::str(&r.hash)),
    ])
}

#[derive(Debug, Clone, PartialEq)]
pub struct ForeignRef {
    pub namespace: String,
    pub subject: String,
    pub digest: String,
}

pub fn foreign_ref(v: &Value) -> R<ForeignRef> {
    let m = obj(v)?;
    closed(m, &["namespace", "subject", "digest"])?;
    Ok(ForeignRef {
        namespace: text(field(m, "namespace")?)?,
        subject: text(field(m, "subject")?)?,
        digest: hash(field(m, "digest")?)?,
    })
}

pub fn foreign_ref_value(r: &ForeignRef) -> Value {
    Value::obj(vec![
        ("namespace", Value::str(&r.namespace)),
        ("subject", Value::str(&r.subject)),
        ("digest", Value::str(&r.digest)),
    ])
}

#[derive(Debug, Clone, PartialEq)]
pub struct Window {
    pub start_ms: u64,
    pub counts: [u64; 4],
}

pub fn window(v: &Value) -> R<Window> {
    let m = obj(v)?;
    closed(m, &["start_ms", "width_ms", "counts"])?;
    let w = Window {
        start_ms: u(field(m, "start_ms")?)?,
        counts: bins(field(m, "counts")?)?,
    };
    lit_num(field(m, "width_ms")?, crate::WINDOW_MS)?;
    if !w.start_ms.is_multiple_of(crate::WINDOW_MS) {
        return Err(schem("window start not a multiple of width"));
    }
    Ok(w)
}

pub fn window_value(w: &Window) -> Value {
    Value::obj(vec![
        ("start_ms", Value::ustr(&w.start_ms.to_string())),
        ("width_ms", Value::num(crate::WINDOW_MS)),
        ("counts", bins_to_value(&w.counts)),
    ])
}

#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub committed_minor: u64,
    pub reserved_minor: u64,
    pub scopes: Vec<String>,
    pub replicas: Option<u64>,
    pub target_revision: u64,
    pub window: Option<Window>,
}

pub fn snapshot(v: &Value) -> R<Snapshot> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "committed_minor",
            "reserved_minor",
            "currency",
            "scopes",
            "replicas",
            "target_revision",
            "window",
        ],
    )?;
    lit_str(field(m, "currency")?, "USD")?;
    let replicas = opt_n(field(m, "replicas")?)?;
    let window = {
        let w = field(m, "window")?;
        if *w == Value::Null {
            None
        } else {
            Some(window(w)?)
        }
    };
    Ok(Snapshot {
        committed_minor: u(field(m, "committed_minor")?)?,
        reserved_minor: u(field(m, "reserved_minor")?)?,
        scopes: id_list(field(m, "scopes")?)?,
        replicas,
        target_revision: u(field(m, "target_revision")?)?,
        window,
    })
}

pub fn snapshot_value(s: &Snapshot) -> Value {
    Value::obj(vec![
        (
            "committed_minor",
            Value::ustr(&s.committed_minor.to_string()),
        ),
        ("reserved_minor", Value::ustr(&s.reserved_minor.to_string())),
        ("currency", Value::str("USD")),
        (
            "scopes",
            Value::Arr(s.scopes.iter().map(|x| Value::str(x)).collect()),
        ),
        (
            "replicas",
            match s.replicas {
                Some(r) => Value::num(r),
                None => Value::Null,
            },
        ),
        (
            "target_revision",
            Value::ustr(&s.target_revision.to_string()),
        ),
        (
            "window",
            match &s.window {
                Some(w) => window_value(w),
                None => Value::Null,
            },
        ),
    ])
}

#[derive(Debug, Clone, PartialEq)]
pub struct Signal {
    pub score_bp: u64,
    pub model: String,
    pub prompt: String,
    pub content_commitment: String,
}

pub fn signal(v: &Value) -> R<Signal> {
    let m = obj(v)?;
    closed(
        m,
        &["kind", "score_bp", "model", "prompt", "content_commitment"],
    )?;
    lit_str(field(m, "kind")?, "rationale-score")?;
    let score = n(field(m, "score_bp")?)?;
    if score > 10_000 {
        return Err(schem("score_bp out of range"));
    }
    Ok(Signal {
        score_bp: score,
        model: hash(field(m, "model")?)?,
        prompt: hash(field(m, "prompt")?)?,
        content_commitment: hash(field(m, "content_commitment")?)?,
    })
}

pub fn signal_value(sg: &Signal) -> Value {
    Value::obj(vec![
        ("kind", Value::str("rationale-score")),
        ("score_bp", Value::num(sg.score_bp)),
        ("model", Value::str(&sg.model)),
        ("prompt", Value::str(&sg.prompt)),
        ("content_commitment", Value::str(&sg.content_commitment)),
    ])
}

// ---------------------------------------------------------------------------
// Signed envelope

#[derive(Debug, Clone, PartialEq)]
pub struct Signed {
    pub body: Value,
    pub digest: String,
    pub key_id: String,
    pub key_epoch: u64,
    pub signature: String,
}

pub fn signed(v: &Value) -> R<Signed> {
    let m = obj(v)?;
    closed(m, &["body", "digest", "key_id", "key_epoch", "signature"])?;
    Ok(Signed {
        body: field(m, "body")?.clone(),
        digest: hash(field(m, "digest")?)?,
        key_id: id(field(m, "key_id")?)?,
        key_epoch: u(field(m, "key_epoch")?)?,
        signature: sig(field(m, "signature")?)?,
    })
}

pub fn signed_value(sv: &Signed) -> Value {
    Value::obj(vec![
        ("body", sv.body.clone()),
        ("digest", Value::str(&sv.digest)),
        ("key_id", Value::str(&sv.key_id)),
        ("key_epoch", Value::ustr(&sv.key_epoch.to_string())),
        ("signature", Value::str(&sv.signature)),
    ])
}

// ---------------------------------------------------------------------------
// Observation / intent / tools

#[derive(Debug, Clone, PartialEq)]
pub struct ObservationBody {
    pub tenant: String,
    pub source: String,
    pub epoch: u64,
    pub boot: String,
    pub seq: u64,
    pub prev: String,
    pub run: String,
    pub cut_ms: u64,
    pub snapshot: Snapshot,
    pub signal: Option<Signal>,
    pub lineage: Vec<ForeignRef>,
}

pub fn observation_body(v: &Value) -> R<ObservationBody> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "v", "tenant", "source", "epoch", "boot", "seq", "prev", "run", "cut_ms", "snapshot",
            "signal", "lineage",
        ],
    )?;
    lit_num(field(m, "v")?, 1)?;
    let signal = {
        let sv = field(m, "signal")?;
        if *sv == Value::Null {
            None
        } else {
            Some(signal(sv)?)
        }
    };
    let lineage: R<Vec<ForeignRef>> = arr(field(m, "lineage")?)?.iter().map(foreign_ref).collect();
    Ok(ObservationBody {
        tenant: id(field(m, "tenant")?)?,
        source: id(field(m, "source")?)?,
        epoch: u(field(m, "epoch")?)?,
        boot: boot(field(m, "boot")?)?,
        seq: u(field(m, "seq")?)?,
        prev: hash(field(m, "prev")?)?,
        run: id(field(m, "run")?)?,
        cut_ms: u(field(m, "cut_ms")?)?,
        snapshot: snapshot(field(m, "snapshot")?)?,
        signal,
        lineage: lineage?,
    })
}

pub fn observation_body_value(b: &ObservationBody) -> Value {
    Value::obj(vec![
        ("v", Value::num(1)),
        ("tenant", Value::str(&b.tenant)),
        ("source", Value::str(&b.source)),
        ("epoch", Value::ustr(&b.epoch.to_string())),
        ("boot", Value::str(&b.boot)),
        ("seq", Value::ustr(&b.seq.to_string())),
        ("prev", Value::str(&b.prev)),
        ("run", Value::str(&b.run)),
        ("cut_ms", Value::ustr(&b.cut_ms.to_string())),
        ("snapshot", snapshot_value(&b.snapshot)),
        (
            "signal",
            match &b.signal {
                Some(sg) => signal_value(sg),
                None => Value::Null,
            },
        ),
        (
            "lineage",
            Value::Arr(b.lineage.iter().map(foreign_ref_value).collect()),
        ),
    ])
}

/// The two inert fixture tools.
pub fn tool_request(v: &Value) -> R<Value> {
    let m = obj(v)?;
    let opv = field(m, "op")?;
    match s(opv)? {
        "read" => {
            closed(m, &["op", "record"])?;
            id(field(m, "record")?)?;
        }
        "write" => {
            closed(m, &["op", "record", "value", "cost_minor"])?;
            id(field(m, "record")?)?;
            text(field(m, "value")?)?;
            u(field(m, "cost_minor")?)?;
        }
        _ => return Err(schem("unknown tool op")),
    }
    Ok(v.clone())
}

#[derive(Debug, Clone, PartialEq)]
pub struct Intent {
    pub action: String,
    pub request_hash: String,
    pub tool: String,
    pub target_revision: u64,
    pub authority_hash: String,
    pub scopes: Vec<String>,
    pub cost_minor: u64,
}

pub fn intent(v: &Value) -> R<Intent> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "action",
            "request_hash",
            "tool",
            "target_revision",
            "authority_hash",
            "scopes",
            "cost_minor",
            "currency",
        ],
    )?;
    lit_str(field(m, "currency")?, "USD")?;
    let tool = s(field(m, "tool")?)?;
    if tool != "record.read" && tool != "record.write" {
        return Err(schem("unknown tool"));
    }
    Ok(Intent {
        action: id(field(m, "action")?)?,
        request_hash: hash(field(m, "request_hash")?)?,
        tool: tool.to_string(),
        target_revision: u(field(m, "target_revision")?)?,
        authority_hash: hash(field(m, "authority_hash")?)?,
        scopes: id_list(field(m, "scopes")?)?,
        cost_minor: u(field(m, "cost_minor")?)?,
    })
}

pub fn intent_value(i: &Intent) -> Value {
    Value::obj(vec![
        ("action", Value::str(&i.action)),
        ("request_hash", Value::str(&i.request_hash)),
        ("tool", Value::str(&i.tool)),
        (
            "target_revision",
            Value::ustr(&i.target_revision.to_string()),
        ),
        ("authority_hash", Value::str(&i.authority_hash)),
        (
            "scopes",
            Value::Arr(i.scopes.iter().map(|x| Value::str(x)).collect()),
        ),
        ("cost_minor", Value::ustr(&i.cost_minor.to_string())),
        ("currency", Value::str("USD")),
    ])
}

// ---------------------------------------------------------------------------
// Policy

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Detector {
    Scope,
    Spend,
    Replicas,
    Rate,
    Distribution,
}

impl Detector {
    pub fn as_str(self) -> &'static str {
        match self {
            Detector::Scope => "scope",
            Detector::Spend => "spend",
            Detector::Replicas => "replicas",
            Detector::Rate => "rate",
            Detector::Distribution => "distribution",
        }
    }
    pub fn parse(s: &str) -> Option<Detector> {
        match s {
            "scope" => Some(Detector::Scope),
            "spend" => Some(Detector::Spend),
            "replicas" => Some(Detector::Replicas),
            "rate" => Some(Detector::Rate),
            "distribution" => Some(Detector::Distribution),
            _ => None,
        }
    }
    /// Fixed tool-bin order index: read, write, spawn, external.
    pub fn all() -> [Detector; 5] {
        [
            Detector::Scope,
            Detector::Spend,
            Detector::Replicas,
            Detector::Rate,
            Detector::Distribution,
        ]
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Monitor {
    pub id: String,
    pub detector: Detector,
    pub mode: String,
    pub required: bool,
    pub artifact: String,
    pub deadline_ms: u64,
}

pub fn monitor(v: &Value) -> R<Monitor> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "id",
            "detector",
            "mode",
            "required",
            "artifact",
            "deadline_ms",
        ],
    )?;
    let det_s = s(field(m, "detector")?)?;
    let detector = Detector::parse(det_s).ok_or_else(|| schem("unknown detector"))?;
    let mode = s(field(m, "mode")?)?;
    if mode != "blocking" && mode != "trailing" {
        return Err(schem("bad monitor mode"));
    }
    Ok(Monitor {
        id: id(field(m, "id")?)?,
        detector,
        mode: mode.to_string(),
        required: boolean(field(m, "required")?)?,
        artifact: hash(field(m, "artifact")?)?,
        deadline_ms: n(field(m, "deadline_ms")?)?,
    })
}

pub fn monitor_value(mo: &Monitor) -> Value {
    Value::obj(vec![
        ("id", Value::str(&mo.id)),
        ("detector", Value::str(mo.detector.as_str())),
        ("mode", Value::str(&mo.mode)),
        ("required", Value::Bool(mo.required)),
        ("artifact", Value::str(&mo.artifact)),
        ("deadline_ms", Value::num(mo.deadline_ms)),
    ])
}

#[derive(Debug, Clone, PartialEq)]
pub struct Baseline {
    pub id: String,
    pub counts: [u64; 4],
    pub evidence: String,
    pub approved_by: String,
    pub approved_at_utc: String,
}

pub fn baseline(v: &Value) -> R<Baseline> {
    let m = obj(v)?;
    closed(
        m,
        &["id", "counts", "evidence", "approved_by", "approved_at_utc"],
    )?;
    Ok(Baseline {
        id: id(field(m, "id")?)?,
        counts: bins(field(m, "counts")?)?,
        evidence: hash(field(m, "evidence")?)?,
        approved_by: id(field(m, "approved_by")?)?,
        approved_at_utc: text(field(m, "approved_at_utc")?)?,
    })
}

pub fn baseline_value(b: &Baseline) -> Value {
    Value::obj(vec![
        ("id", Value::str(&b.id)),
        ("counts", bins_to_value(&b.counts)),
        ("evidence", Value::str(&b.evidence)),
        ("approved_by", Value::str(&b.approved_by)),
        ("approved_at_utc", Value::str(&b.approved_at_utc)),
    ])
}

#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    pub id: String,
    pub generation: u64,
    pub predecessor: Option<String>,
    pub tenant: String,
    pub allowed_scopes: Vec<String>,
    pub cap_minor: u64,
    pub review_at_minor: u64,
    pub max_replicas: u64,
    pub rate_per_window: u64,
    pub baseline: Baseline,
    pub drift_high_bp: u64,
    pub drift_low_bp: u64,
    pub min_window_samples: u64,
    pub high_windows: u64,
    pub low_windows: u64,
    pub freshness_ms: u64,
    pub evaluation_ms: u64,
    pub clearance_ms: u64,
    pub review_ttl_ms: u64,
    pub review_accept_ms: u64,
    pub claim_lease_ms: u64,
    pub queue_capacity: u64,
    pub per_run_open_reviews: u64,
    pub monitors: Vec<Monitor>,
}

pub fn policy(v: &Value) -> R<Policy> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "v",
            "id",
            "generation",
            "predecessor",
            "tenant",
            "allowed_scopes",
            "cap_minor",
            "review_at_minor",
            "max_replicas",
            "rate_per_window",
            "baseline",
            "drift_high_bp",
            "drift_low_bp",
            "min_window_samples",
            "high_windows",
            "low_windows",
            "freshness_ms",
            "evaluation_ms",
            "clearance_ms",
            "review_ttl_ms",
            "review_accept_ms",
            "claim_lease_ms",
            "queue_capacity",
            "per_run_open_reviews",
            "monitors",
        ],
    )?;
    lit_num(field(m, "v")?, 1)?;
    let monitors: R<Vec<Monitor>> = arr(field(m, "monitors")?)?.iter().map(monitor).collect();
    Ok(Policy {
        id: id(field(m, "id")?)?,
        generation: u(field(m, "generation")?)?,
        predecessor: opt_hash(field(m, "predecessor")?)?,
        tenant: id(field(m, "tenant")?)?,
        allowed_scopes: id_list(field(m, "allowed_scopes")?)?,
        cap_minor: u(field(m, "cap_minor")?)?,
        review_at_minor: u(field(m, "review_at_minor")?)?,
        max_replicas: n(field(m, "max_replicas")?)?,
        rate_per_window: u(field(m, "rate_per_window")?)?,
        baseline: baseline(field(m, "baseline")?)?,
        drift_high_bp: n(field(m, "drift_high_bp")?)?,
        drift_low_bp: n(field(m, "drift_low_bp")?)?,
        min_window_samples: n(field(m, "min_window_samples")?)?,
        high_windows: n(field(m, "high_windows")?)?,
        low_windows: n(field(m, "low_windows")?)?,
        freshness_ms: n(field(m, "freshness_ms")?)?,
        evaluation_ms: n(field(m, "evaluation_ms")?)?,
        clearance_ms: n(field(m, "clearance_ms")?)?,
        review_ttl_ms: n(field(m, "review_ttl_ms")?)?,
        review_accept_ms: n(field(m, "review_accept_ms")?)?,
        claim_lease_ms: n(field(m, "claim_lease_ms")?)?,
        queue_capacity: n(field(m, "queue_capacity")?)?,
        per_run_open_reviews: n(field(m, "per_run_open_reviews")?)?,
        monitors: monitors?,
    })
}

/// §1.2 policy constraints. Enforced at validation, never clamped.
pub fn policy_constraints(p: &Policy) -> R<()> {
    let pe = |m: &str| err(Code::PolicyInvalid, m);
    if !(p.drift_low_bp < p.drift_high_bp && p.drift_high_bp <= 10_000) {
        return Err(pe("drift bounds"));
    }
    if p.baseline.counts.iter().sum::<u64>() == 0 {
        return Err(pe("baseline total zero"));
    }
    if p.min_window_samples < 100 {
        return Err(pe("min_window_samples < 100"));
    }
    if p.high_windows != 2 {
        return Err(pe("high_windows != 2"));
    }
    if p.low_windows != 3 {
        return Err(pe("low_windows != 3"));
    }
    if !(1..=64).contains(&p.max_replicas) {
        return Err(pe("max_replicas out of range"));
    }
    if !(p.review_at_minor >= 1 && p.review_at_minor <= p.cap_minor) {
        return Err(pe("review_at_minor out of range"));
    }
    // Monitors unique by id and detector; exactly scope/spend/replicas
    // required-blocking; rate/distribution optional trailing.
    let mut ids = std::collections::HashSet::new();
    let mut dets = std::collections::HashSet::new();
    for m in &p.monitors {
        if !ids.insert(m.id.clone()) || !dets.insert(m.detector) {
            return Err(pe("duplicate monitor id or detector"));
        }
    }
    for (det, want_required) in [
        (Detector::Scope, true),
        (Detector::Spend, true),
        (Detector::Replicas, true),
        (Detector::Rate, false),
        (Detector::Distribution, false),
    ] {
        match p.monitors.iter().find(|m| m.detector == det) {
            Some(m) => {
                let want_mode = if det == Detector::Rate || det == Detector::Distribution {
                    "trailing"
                } else {
                    "blocking"
                };
                if m.mode != want_mode || m.required != want_required {
                    return Err(pe("monitor mode/required wrong for detector"));
                }
            }
            None => {
                if want_required {
                    return Err(pe("required blocking monitor missing"));
                }
            }
        }
    }
    Ok(())
}

pub fn policy_value(p: &Policy) -> Value {
    Value::obj(vec![
        ("v", Value::num(1)),
        ("id", Value::str(&p.id)),
        ("generation", Value::ustr(&p.generation.to_string())),
        (
            "predecessor",
            match &p.predecessor {
                Some(h) => Value::str(h),
                None => Value::Null,
            },
        ),
        ("tenant", Value::str(&p.tenant)),
        (
            "allowed_scopes",
            Value::Arr(p.allowed_scopes.iter().map(|x| Value::str(x)).collect()),
        ),
        ("cap_minor", Value::ustr(&p.cap_minor.to_string())),
        (
            "review_at_minor",
            Value::ustr(&p.review_at_minor.to_string()),
        ),
        ("max_replicas", Value::num(p.max_replicas)),
        (
            "rate_per_window",
            Value::ustr(&p.rate_per_window.to_string()),
        ),
        ("baseline", baseline_value(&p.baseline)),
        ("drift_high_bp", Value::num(p.drift_high_bp)),
        ("drift_low_bp", Value::num(p.drift_low_bp)),
        ("min_window_samples", Value::num(p.min_window_samples)),
        ("high_windows", Value::num(p.high_windows)),
        ("low_windows", Value::num(p.low_windows)),
        ("freshness_ms", Value::num(p.freshness_ms)),
        ("evaluation_ms", Value::num(p.evaluation_ms)),
        ("clearance_ms", Value::num(p.clearance_ms)),
        ("review_ttl_ms", Value::num(p.review_ttl_ms)),
        ("review_accept_ms", Value::num(p.review_accept_ms)),
        ("claim_lease_ms", Value::num(p.claim_lease_ms)),
        ("queue_capacity", Value::num(p.queue_capacity)),
        ("per_run_open_reviews", Value::num(p.per_run_open_reviews)),
        (
            "monitors",
            Value::Arr(p.monitors.iter().map(monitor_value).collect()),
        ),
    ])
}

// ---------------------------------------------------------------------------
// Run / drift / result / check

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    Open,
    Paused,
    Quarantined,
    Closed,
}

impl RunState {
    pub fn as_str(self) -> &'static str {
        match self {
            RunState::Open => "OPEN",
            RunState::Paused => "PAUSED",
            RunState::Quarantined => "QUARANTINED",
            RunState::Closed => "CLOSED",
        }
    }
    pub fn parse(s: &str) -> Option<RunState> {
        match s {
            "OPEN" => Some(RunState::Open),
            "PAUSED" => Some(RunState::Paused),
            "QUARANTINED" => Some(RunState::Quarantined),
            "CLOSED" => Some(RunState::Closed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftState {
    Warmup,
    Stable,
    Suspect,
    Drift,
}

impl DriftState {
    pub fn as_str(self) -> &'static str {
        match self {
            DriftState::Warmup => "WARMUP",
            DriftState::Stable => "STABLE",
            DriftState::Suspect => "SUSPECT",
            DriftState::Drift => "DRIFT",
        }
    }
    pub fn parse(s: &str) -> Option<DriftState> {
        match s {
            "WARMUP" => Some(DriftState::Warmup),
            "STABLE" => Some(DriftState::Stable),
            "SUSPECT" => Some(DriftState::Suspect),
            "DRIFT" => Some(DriftState::Drift),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Drift {
    pub state: DriftState,
    pub high_streak: u64,
    pub low_streak: u64,
    pub last_window_ms: Option<u64>,
    pub score_bp: Option<u64>,
    pub data: String,
}

pub fn drift(v: &Value) -> R<Drift> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "state",
            "high_streak",
            "low_streak",
            "last_window_ms",
            "score_bp",
            "data",
        ],
    )?;
    let st = s(field(m, "state")?)?;
    let state = DriftState::parse(st).ok_or_else(|| schem("bad drift state"))?;
    let data = s(field(m, "data")?)?;
    if data != "complete" && data != "insufficient" && data != "missing" {
        return Err(schem("bad drift data"));
    }
    let score = opt_n(field(m, "score_bp")?)?;
    if let Some(x) = score {
        if x > 10_000 {
            return Err(schem("score_bp out of range"));
        }
    }
    Ok(Drift {
        state,
        high_streak: n(field(m, "high_streak")?)?,
        low_streak: n(field(m, "low_streak")?)?,
        last_window_ms: opt_u(field(m, "last_window_ms")?)?,
        score_bp: score,
        data: data.to_string(),
    })
}

pub fn drift_value(d: &Drift) -> Value {
    Value::obj(vec![
        ("state", Value::str(d.state.as_str())),
        ("high_streak", Value::num(d.high_streak)),
        ("low_streak", Value::num(d.low_streak)),
        (
            "last_window_ms",
            match d.last_window_ms {
                Some(x) => Value::ustr(&x.to_string()),
                None => Value::Null,
            },
        ),
        (
            "score_bp",
            match d.score_bp {
                Some(x) => Value::num(x),
                None => Value::Null,
            },
        ),
        ("data", Value::str(&d.data)),
    ])
}

#[derive(Debug, Clone, PartialEq)]
pub struct Run {
    pub id: String,
    pub revision: u64,
    pub tenant: String,
    pub source: String,
    pub source_epoch: u64,
    pub runtime: String,
    pub guard_epoch: u64,
    pub boot: String,
    pub mode: String,
    pub profile: String,
    pub state: RunState,
    pub policy: String,
    pub cursor: Head,
    pub last_cut_ms: Option<u64>,
    pub last_received_ms: Option<u64>,
    pub drift: Drift,
    pub pause_reason: Option<String>,
}

pub fn run(v: &Value) -> R<Run> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "id",
            "revision",
            "tenant",
            "source",
            "source_epoch",
            "runtime",
            "guard_epoch",
            "boot",
            "mode",
            "profile",
            "state",
            "policy",
            "cursor",
            "last_cut_ms",
            "last_received_ms",
            "drift",
            "pause_reason",
        ],
    )?;
    let mode = s(field(m, "mode")?)?;
    if mode != "GUARDED" && mode != "SHADOW" {
        return Err(schem("bad mode"));
    }
    let profile = s(field(m, "profile")?)?;
    if profile != "fixture/1" && profile != "runtime-guard/1" {
        return Err(schem("bad profile"));
    }
    let st = s(field(m, "state")?)?;
    let state = RunState::parse(st).ok_or_else(|| schem("bad run state"))?;
    Ok(Run {
        id: id(field(m, "id")?)?,
        revision: u(field(m, "revision")?)?,
        tenant: id(field(m, "tenant")?)?,
        source: id(field(m, "source")?)?,
        source_epoch: u(field(m, "source_epoch")?)?,
        runtime: id(field(m, "runtime")?)?,
        guard_epoch: u(field(m, "guard_epoch")?)?,
        boot: boot(field(m, "boot")?)?,
        mode: mode.to_string(),
        profile: profile.to_string(),
        state,
        policy: hash(field(m, "policy")?)?,
        cursor: head(field(m, "cursor")?)?,
        last_cut_ms: opt_u(field(m, "last_cut_ms")?)?,
        last_received_ms: opt_u(field(m, "last_received_ms")?)?,
        drift: drift(field(m, "drift")?)?,
        pause_reason: opt_text(field(m, "pause_reason")?)?,
    })
}

pub fn run_value(r: &Run) -> Value {
    Value::obj(vec![
        ("id", Value::str(&r.id)),
        ("revision", Value::ustr(&r.revision.to_string())),
        ("tenant", Value::str(&r.tenant)),
        ("source", Value::str(&r.source)),
        ("source_epoch", Value::ustr(&r.source_epoch.to_string())),
        ("runtime", Value::str(&r.runtime)),
        ("guard_epoch", Value::ustr(&r.guard_epoch.to_string())),
        ("boot", Value::str(&r.boot)),
        ("mode", Value::str(&r.mode)),
        ("profile", Value::str(&r.profile)),
        ("state", Value::str(r.state.as_str())),
        ("policy", Value::str(&r.policy)),
        ("cursor", head_value(&r.cursor)),
        (
            "last_cut_ms",
            match r.last_cut_ms {
                Some(x) => Value::ustr(&x.to_string()),
                None => Value::Null,
            },
        ),
        (
            "last_received_ms",
            match r.last_received_ms {
                Some(x) => Value::ustr(&x.to_string()),
                None => Value::Null,
            },
        ),
        ("drift", drift_value(&r.drift)),
        (
            "pause_reason",
            match &r.pause_reason {
                Some(t) => Value::str(t),
                None => Value::Null,
            },
        ),
    ])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Clear,
    Flag,
    Uncertain,
    Unavailable,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Clear => "clear",
            Verdict::Flag => "flag",
            Verdict::Uncertain => "uncertain",
            Verdict::Unavailable => "unavailable",
        }
    }
    pub fn parse(s: &str) -> Option<Verdict> {
        match s {
            "clear" => Some(Verdict::Clear),
            "flag" => Some(Verdict::Flag),
            "uncertain" => Some(Verdict::Uncertain),
            "unavailable" => Some(Verdict::Unavailable),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Result_ {
    pub monitor: String,
    pub detector: Detector,
    pub verdict: Verdict,
    pub reason: String,
    pub score_bp: Option<u64>,
    pub evidence: Vec<Ref>,
}

pub fn result(v: &Value) -> R<Result_> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "monitor", "detector", "verdict", "reason", "score_bp", "evidence",
        ],
    )?;
    let det = s(field(m, "detector")?)?;
    let detector = Detector::parse(det).ok_or_else(|| schem("bad detector"))?;
    let vd = s(field(m, "verdict")?)?;
    let verdict = Verdict::parse(vd).ok_or_else(|| schem("bad verdict"))?;
    let score = opt_n(field(m, "score_bp")?)?;
    if let Some(x) = score {
        if x > 10_000 {
            return Err(schem("score_bp out of range"));
        }
    }
    let ev: R<Vec<Ref>> = arr(field(m, "evidence")?)?.iter().map(ref_).collect();
    let ev = ev?;
    if ev.len() > crate::SET_MAX {
        return Err(schem("evidence too large"));
    }
    Ok(Result_ {
        monitor: id(field(m, "monitor")?)?,
        detector,
        verdict,
        reason: text(field(m, "reason")?)?,
        score_bp: score,
        evidence: ev,
    })
}

pub fn result_value(r: &Result_) -> Value {
    Value::obj(vec![
        ("monitor", Value::str(&r.monitor)),
        ("detector", Value::str(r.detector.as_str())),
        ("verdict", Value::str(r.verdict.as_str())),
        ("reason", Value::str(&r.reason)),
        (
            "score_bp",
            match r.score_bp {
                Some(x) => Value::num(x),
                None => Value::Null,
            },
        ),
        (
            "evidence",
            Value::Arr(r.evidence.iter().map(ref_value).collect()),
        ),
    ])
}

#[derive(Debug, Clone, PartialEq)]
pub struct Basis {
    pub run: String,
    pub intent: String,
    pub policy: String,
    pub guard_epoch: u64,
    pub target_revision: u64,
    pub max_total_minor: u64,
    pub findings: String,
}

pub fn basis(v: &Value) -> R<Basis> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "run",
            "intent",
            "policy",
            "guard_epoch",
            "target_revision",
            "max_total_minor",
            "findings",
        ],
    )?;
    Ok(Basis {
        run: id(field(m, "run")?)?,
        intent: hash(field(m, "intent")?)?,
        policy: hash(field(m, "policy")?)?,
        guard_epoch: u(field(m, "guard_epoch")?)?,
        target_revision: u(field(m, "target_revision")?)?,
        max_total_minor: u(field(m, "max_total_minor")?)?,
        findings: hash(field(m, "findings")?)?,
    })
}

pub fn basis_value(b: &Basis) -> Value {
    Value::obj(vec![
        ("run", Value::str(&b.run)),
        ("intent", Value::str(&b.intent)),
        ("policy", Value::str(&b.policy)),
        ("guard_epoch", Value::ustr(&b.guard_epoch.to_string())),
        (
            "target_revision",
            Value::ustr(&b.target_revision.to_string()),
        ),
        (
            "max_total_minor",
            Value::ustr(&b.max_total_minor.to_string()),
        ),
        ("findings", Value::str(&b.findings)),
    ])
}

#[derive(Debug, Clone, PartialEq)]
pub struct Clearance {
    pub tenant: String,
    pub run: String,
    pub runtime: String,
    pub guard_epoch: u64,
    pub boot: String,
    pub check: String,
    pub intent: String,
    pub policy: String,
    pub observation: Ref,
    pub basis: String,
    pub issued_ms: u64,
    pub expires_ms: u64,
    pub mode: String,
}

pub fn clearance_body(v: &Value) -> R<Clearance> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "v",
            "tenant",
            "run",
            "runtime",
            "guard_epoch",
            "boot",
            "check",
            "intent",
            "policy",
            "observation",
            "basis",
            "issued_ms",
            "expires_ms",
            "mode",
            "semantics",
        ],
    )?;
    lit_num(field(m, "v")?, 1)?;
    lit_str(field(m, "semantics")?, "NO_WATCH_VETO_NOT_AUTHORIZATION")?;
    let mode = s(field(m, "mode")?)?;
    if mode != "GUARDED" && mode != "SHADOW" {
        return Err(schem("bad mode"));
    }
    Ok(Clearance {
        tenant: id(field(m, "tenant")?)?,
        run: id(field(m, "run")?)?,
        runtime: id(field(m, "runtime")?)?,
        guard_epoch: u(field(m, "guard_epoch")?)?,
        boot: boot(field(m, "boot")?)?,
        check: id(field(m, "check")?)?,
        intent: hash(field(m, "intent")?)?,
        policy: hash(field(m, "policy")?)?,
        observation: ref_(field(m, "observation")?)?,
        basis: hash(field(m, "basis")?)?,
        issued_ms: u(field(m, "issued_ms")?)?,
        expires_ms: u(field(m, "expires_ms")?)?,
        mode: mode.to_string(),
    })
}

pub fn clearance_body_value(c: &Clearance) -> Value {
    Value::obj(vec![
        ("v", Value::num(1)),
        ("tenant", Value::str(&c.tenant)),
        ("run", Value::str(&c.run)),
        ("runtime", Value::str(&c.runtime)),
        ("guard_epoch", Value::ustr(&c.guard_epoch.to_string())),
        ("boot", Value::str(&c.boot)),
        ("check", Value::str(&c.check)),
        ("intent", Value::str(&c.intent)),
        ("policy", Value::str(&c.policy)),
        ("observation", ref_value(&c.observation)),
        ("basis", Value::str(&c.basis)),
        ("issued_ms", Value::ustr(&c.issued_ms.to_string())),
        ("expires_ms", Value::ustr(&c.expires_ms.to_string())),
        ("mode", Value::str(&c.mode)),
        ("semantics", Value::str("NO_WATCH_VETO_NOT_AUTHORIZATION")),
    ])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckState {
    Evaluating,
    Clear,
    Deny,
    Held,
    Expired,
    Cancelled,
    Stale,
}

impl CheckState {
    pub fn as_str(self) -> &'static str {
        match self {
            CheckState::Evaluating => "EVALUATING",
            CheckState::Clear => "CLEAR",
            CheckState::Deny => "DENY",
            CheckState::Held => "HELD",
            CheckState::Expired => "EXPIRED",
            CheckState::Cancelled => "CANCELLED",
            CheckState::Stale => "STALE",
        }
    }
    pub fn parse(s: &str) -> Option<CheckState> {
        match s {
            "EVALUATING" => Some(CheckState::Evaluating),
            "CLEAR" => Some(CheckState::Clear),
            "DENY" => Some(CheckState::Deny),
            "HELD" => Some(CheckState::Held),
            "EXPIRED" => Some(CheckState::Expired),
            "CANCELLED" => Some(CheckState::Cancelled),
            "STALE" => Some(CheckState::Stale),
            _ => None,
        }
    }
    pub fn terminal(self) -> bool {
        self != CheckState::Evaluating
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Check {
    pub id: String,
    pub revision: u64,
    pub run: String,
    pub intent: Intent,
    pub observation: Ref,
    pub policy: String,
    pub state: CheckState,
    pub created_ms: u64,
    pub deadline_ms: u64,
    pub results: Vec<Result_>,
    pub review: Option<String>,
    pub clearance: Option<Signed>,
    pub reason: String,
}

pub fn check(v: &Value) -> R<Check> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "id",
            "revision",
            "run",
            "intent",
            "observation",
            "policy",
            "state",
            "created_ms",
            "deadline_ms",
            "results",
            "review",
            "clearance",
            "reason",
        ],
    )?;
    let st = s(field(m, "state")?)?;
    let state = CheckState::parse(st).ok_or_else(|| schem("bad check state"))?;
    let results: R<Vec<Result_>> = arr(field(m, "results")?)?.iter().map(result).collect();
    let clv = field(m, "clearance")?;
    let clearance = if *clv == Value::Null {
        None
    } else {
        let sv = signed(clv)?;
        clearance_body(&sv.body)?;
        Some(sv)
    };
    Ok(Check {
        id: id(field(m, "id")?)?,
        revision: u(field(m, "revision")?)?,
        run: id(field(m, "run")?)?,
        intent: intent(field(m, "intent")?)?,
        observation: ref_(field(m, "observation")?)?,
        policy: hash(field(m, "policy")?)?,
        state,
        created_ms: u(field(m, "created_ms")?)?,
        deadline_ms: u(field(m, "deadline_ms")?)?,
        results: results?,
        review: opt_id(field(m, "review")?)?,
        clearance,
        reason: text(field(m, "reason")?)?,
    })
}

pub fn check_value(c: &Check) -> Value {
    Value::obj(vec![
        ("id", Value::str(&c.id)),
        ("revision", Value::ustr(&c.revision.to_string())),
        ("run", Value::str(&c.run)),
        ("intent", intent_value(&c.intent)),
        ("observation", ref_value(&c.observation)),
        ("policy", Value::str(&c.policy)),
        ("state", Value::str(c.state.as_str())),
        ("created_ms", Value::ustr(&c.created_ms.to_string())),
        ("deadline_ms", Value::ustr(&c.deadline_ms.to_string())),
        (
            "results",
            Value::Arr(c.results.iter().map(result_value).collect()),
        ),
        (
            "review",
            match &c.review {
                Some(r) => Value::str(r),
                None => Value::Null,
            },
        ),
        (
            "clearance",
            match &c.clearance {
                Some(cl) => signed_value(cl),
                None => Value::Null,
            },
        ),
        ("reason", Value::str(&c.reason)),
    ])
}

// ---------------------------------------------------------------------------
// Review / alert

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewState {
    Open,
    Claimed,
    Deferred,
    Accepted,
    Rejected,
    Expired,
    Consumed,
    Closed,
}

impl ReviewState {
    pub fn as_str(self) -> &'static str {
        match self {
            ReviewState::Open => "OPEN",
            ReviewState::Claimed => "CLAIMED",
            ReviewState::Deferred => "DEFERRED",
            ReviewState::Accepted => "ACCEPTED",
            ReviewState::Rejected => "REJECTED",
            ReviewState::Expired => "EXPIRED",
            ReviewState::Consumed => "CONSUMED",
            ReviewState::Closed => "CLOSED",
        }
    }
    pub fn parse(s: &str) -> Option<ReviewState> {
        match s {
            "OPEN" => Some(ReviewState::Open),
            "CLAIMED" => Some(ReviewState::Claimed),
            "DEFERRED" => Some(ReviewState::Deferred),
            "ACCEPTED" => Some(ReviewState::Accepted),
            "REJECTED" => Some(ReviewState::Rejected),
            "EXPIRED" => Some(ReviewState::Expired),
            "CONSUMED" => Some(ReviewState::Consumed),
            "CLOSED" => Some(ReviewState::Closed),
            _ => None,
        }
    }
    /// Active states occupy a remainder slot.
    pub fn active(self) -> bool {
        matches!(
            self,
            ReviewState::Open
                | ReviewState::Claimed
                | ReviewState::Deferred
                | ReviewState::Accepted
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warning,
    Critical,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Info => "info",
            Level::Warning => "warning",
            Level::Critical => "critical",
        }
    }
    pub fn parse(s: &str) -> Option<Level> {
        match s {
            "info" => Some(Level::Info),
            "warning" => Some(Level::Warning),
            "critical" => Some(Level::Critical),
            _ => None,
        }
    }
    pub fn rank(self) -> u8 {
        match self {
            Level::Critical => 0,
            Level::Warning => 1,
            Level::Info => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Review {
    pub id: String,
    pub revision: u64,
    pub run: String,
    pub check: Option<String>,
    pub alert: Option<String>,
    pub basis: Option<Basis>,
    pub kind: String,
    pub state: ReviewState,
    pub level: Level,
    pub created_seq: u64,
    pub due_ms: u64,
    pub owner: Option<String>,
    pub lease_until_ms: Option<u64>,
    pub wake_ms: Option<u64>,
    pub accepted_until_ms: Option<u64>,
    pub reason: String,
    pub resolution: Option<String>,
    pub resolved_by: Option<String>,
}

pub fn review(v: &Value) -> R<Review> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "id",
            "revision",
            "run",
            "check",
            "alert",
            "basis",
            "kind",
            "state",
            "level",
            "created_seq",
            "due_ms",
            "owner",
            "lease_until_ms",
            "wake_ms",
            "accepted_until_ms",
            "reason",
            "resolution",
            "resolved_by",
        ],
    )?;
    let st = s(field(m, "state")?)?;
    let state = ReviewState::parse(st).ok_or_else(|| schem("bad review state"))?;
    let kind = s(field(m, "kind")?)?;
    if kind != "blocking" && kind != "trailing" {
        return Err(schem("bad kind"));
    }
    let lv = s(field(m, "level")?)?;
    let level = Level::parse(lv).ok_or_else(|| schem("bad level"))?;
    let bv = field(m, "basis")?;
    let basis = if *bv == Value::Null {
        None
    } else {
        Some(basis(bv)?)
    };
    Ok(Review {
        id: id(field(m, "id")?)?,
        revision: u(field(m, "revision")?)?,
        run: id(field(m, "run")?)?,
        check: opt_id(field(m, "check")?)?,
        alert: opt_id(field(m, "alert")?)?,
        basis,
        kind: kind.to_string(),
        state,
        level,
        created_seq: u(field(m, "created_seq")?)?,
        due_ms: u(field(m, "due_ms")?)?,
        owner: opt_id(field(m, "owner")?)?,
        lease_until_ms: opt_u(field(m, "lease_until_ms")?)?,
        wake_ms: opt_u(field(m, "wake_ms")?)?,
        accepted_until_ms: opt_u(field(m, "accepted_until_ms")?)?,
        reason: text(field(m, "reason")?)?,
        resolution: opt_text(field(m, "resolution")?)?,
        resolved_by: opt_id(field(m, "resolved_by")?)?,
    })
}

pub fn review_value(r: &Review) -> Value {
    Value::obj(vec![
        ("id", Value::str(&r.id)),
        ("revision", Value::ustr(&r.revision.to_string())),
        ("run", Value::str(&r.run)),
        (
            "check",
            r.check
                .as_ref()
                .map(|x| Value::str(x))
                .unwrap_or(Value::Null),
        ),
        (
            "alert",
            r.alert
                .as_ref()
                .map(|x| Value::str(x))
                .unwrap_or(Value::Null),
        ),
        (
            "basis",
            r.basis.as_ref().map(basis_value).unwrap_or(Value::Null),
        ),
        ("kind", Value::str(&r.kind)),
        ("state", Value::str(r.state.as_str())),
        ("level", Value::str(r.level.as_str())),
        ("created_seq", Value::ustr(&r.created_seq.to_string())),
        ("due_ms", Value::ustr(&r.due_ms.to_string())),
        (
            "owner",
            r.owner
                .as_ref()
                .map(|x| Value::str(x))
                .unwrap_or(Value::Null),
        ),
        (
            "lease_until_ms",
            r.lease_until_ms
                .map(|x| Value::ustr(&x.to_string()))
                .unwrap_or(Value::Null),
        ),
        (
            "wake_ms",
            r.wake_ms
                .map(|x| Value::ustr(&x.to_string()))
                .unwrap_or(Value::Null),
        ),
        (
            "accepted_until_ms",
            r.accepted_until_ms
                .map(|x| Value::ustr(&x.to_string()))
                .unwrap_or(Value::Null),
        ),
        ("reason", Value::str(&r.reason)),
        (
            "resolution",
            r.resolution
                .as_ref()
                .map(|x| Value::str(x))
                .unwrap_or(Value::Null),
        ),
        (
            "resolved_by",
            r.resolved_by
                .as_ref()
                .map(|x| Value::str(x))
                .unwrap_or(Value::Null),
        ),
    ])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertState {
    Open,
    Acknowledged,
    Resolved,
}

impl AlertState {
    pub fn as_str(self) -> &'static str {
        match self {
            AlertState::Open => "OPEN",
            AlertState::Acknowledged => "ACKNOWLEDGED",
            AlertState::Resolved => "RESOLVED",
        }
    }
    pub fn parse(s: &str) -> Option<AlertState> {
        match s {
            "OPEN" => Some(AlertState::Open),
            "ACKNOWLEDGED" => Some(AlertState::Acknowledged),
            "RESOLVED" => Some(AlertState::Resolved),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Alert {
    pub id: String,
    pub revision: u64,
    pub run: String,
    pub monitor: String,
    pub baseline: String,
    pub state: AlertState,
    pub level: Level,
    pub first: Ref,
    pub last: Ref,
    pub occurrences: u64,
    pub review: Option<String>,
    pub reason: String,
    pub resolved_by: Option<String>,
}

pub fn alert(v: &Value) -> R<Alert> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "id",
            "revision",
            "run",
            "monitor",
            "baseline",
            "state",
            "level",
            "first",
            "last",
            "occurrences",
            "review",
            "reason",
            "resolved_by",
        ],
    )?;
    let st = s(field(m, "state")?)?;
    let state = AlertState::parse(st).ok_or_else(|| schem("bad alert state"))?;
    let lv = s(field(m, "level")?)?;
    let level = Level::parse(lv).ok_or_else(|| schem("bad level"))?;
    Ok(Alert {
        id: id(field(m, "id")?)?,
        revision: u(field(m, "revision")?)?,
        run: id(field(m, "run")?)?,
        monitor: id(field(m, "monitor")?)?,
        baseline: id(field(m, "baseline")?)?,
        state,
        level,
        first: ref_(field(m, "first")?)?,
        last: ref_(field(m, "last")?)?,
        occurrences: u(field(m, "occurrences")?)?,
        review: opt_id(field(m, "review")?)?,
        reason: text(field(m, "reason")?)?,
        resolved_by: opt_id(field(m, "resolved_by")?)?,
    })
}

pub fn alert_value(a: &Alert) -> Value {
    Value::obj(vec![
        ("id", Value::str(&a.id)),
        ("revision", Value::ustr(&a.revision.to_string())),
        ("run", Value::str(&a.run)),
        ("monitor", Value::str(&a.monitor)),
        ("baseline", Value::str(&a.baseline)),
        ("state", Value::str(a.state.as_str())),
        ("level", Value::str(a.level.as_str())),
        ("first", ref_value(&a.first)),
        ("last", ref_value(&a.last)),
        ("occurrences", Value::ustr(&a.occurrences.to_string())),
        (
            "review",
            a.review
                .as_ref()
                .map(|x| Value::str(x))
                .unwrap_or(Value::Null),
        ),
        ("reason", Value::str(&a.reason)),
        (
            "resolved_by",
            a.resolved_by
                .as_ref()
                .map(|x| Value::str(x))
                .unwrap_or(Value::Null),
        ),
    ])
}

// ---------------------------------------------------------------------------
// Effects

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectState {
    Declared,
    Confirmed,
    NotDispatched,
    Unknown,
}

impl EffectState {
    pub fn as_str(self) -> &'static str {
        match self {
            EffectState::Declared => "DECLARED",
            EffectState::Confirmed => "CONFIRMED",
            EffectState::NotDispatched => "NOT_DISPATCHED",
            EffectState::Unknown => "UNKNOWN",
        }
    }
    pub fn parse(s: &str) -> Option<EffectState> {
        match s {
            "DECLARED" => Some(EffectState::Declared),
            "CONFIRMED" => Some(EffectState::Confirmed),
            "NOT_DISPATCHED" => Some(EffectState::NotDispatched),
            "UNKNOWN" => Some(EffectState::Unknown),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct EffectBody {
    pub tenant: String,
    pub run: String,
    pub check: String,
    pub action: String,
    pub intent: String,
    pub clearance: String,
    pub runtime: String,
    pub guard_epoch: u64,
    pub boot: String,
    pub state: EffectState,
    pub at_ms: u64,
    pub provider_receipt: Option<String>,
    pub predecessor: Option<String>,
}

pub fn effect_body(v: &Value) -> R<EffectBody> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "v",
            "tenant",
            "run",
            "check",
            "action",
            "intent",
            "clearance",
            "runtime",
            "guard_epoch",
            "boot",
            "state",
            "at_ms",
            "provider_receipt",
            "predecessor",
        ],
    )?;
    lit_num(field(m, "v")?, 1)?;
    let st = s(field(m, "state")?)?;
    let state = EffectState::parse(st).ok_or_else(|| schem("bad effect state"))?;
    Ok(EffectBody {
        tenant: id(field(m, "tenant")?)?,
        run: id(field(m, "run")?)?,
        check: id(field(m, "check")?)?,
        action: id(field(m, "action")?)?,
        intent: hash(field(m, "intent")?)?,
        clearance: hash(field(m, "clearance")?)?,
        runtime: id(field(m, "runtime")?)?,
        guard_epoch: u(field(m, "guard_epoch")?)?,
        boot: boot(field(m, "boot")?)?,
        state,
        at_ms: u(field(m, "at_ms")?)?,
        provider_receipt: opt_hash(field(m, "provider_receipt")?)?,
        predecessor: opt_hash(field(m, "predecessor")?)?,
    })
}

pub fn effect_body_value(e: &EffectBody) -> Value {
    Value::obj(vec![
        ("v", Value::num(1)),
        ("tenant", Value::str(&e.tenant)),
        ("run", Value::str(&e.run)),
        ("check", Value::str(&e.check)),
        ("action", Value::str(&e.action)),
        ("intent", Value::str(&e.intent)),
        ("clearance", Value::str(&e.clearance)),
        ("runtime", Value::str(&e.runtime)),
        ("guard_epoch", Value::ustr(&e.guard_epoch.to_string())),
        ("boot", Value::str(&e.boot)),
        ("state", Value::str(e.state.as_str())),
        ("at_ms", Value::ustr(&e.at_ms.to_string())),
        (
            "provider_receipt",
            e.provider_receipt
                .as_ref()
                .map(|x| Value::str(x))
                .unwrap_or(Value::Null),
        ),
        (
            "predecessor",
            e.predecessor
                .as_ref()
                .map(|x| Value::str(x))
                .unwrap_or(Value::Null),
        ),
    ])
}

// ---------------------------------------------------------------------------
// Evaluation schemas

#[derive(Debug, Clone, PartialEq)]
pub struct EvalRow {
    pub unit: String,
    pub cluster: String,
    pub truth: String,
    pub watcher: String,
    pub human: String,
    pub prevention: String,
    pub late: bool,
    pub review: bool,
}

pub fn eval_row(v: &Value) -> R<EvalRow> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "unit",
            "cluster",
            "truth",
            "watcher",
            "human",
            "prevention",
            "late",
            "review",
        ],
    )?;
    let truth = s(field(m, "truth")?)?;
    if !["dangerous", "benign", "unknown"].contains(&truth) {
        return Err(schem("bad truth"));
    }
    for (nm, f) in [
        ("watcher", field(m, "watcher")?),
        ("human", field(m, "human")?),
    ] {
        let p = s(f)?;
        if !["flag", "clear", "abstain"].contains(&p) {
            return Err(schem("bad prediction"));
        }
        let _ = nm;
    }
    let prevention = s(field(m, "prevention")?)?;
    if !["blocked", "dispatched", "not_attempted"].contains(&prevention) {
        return Err(schem("bad prevention"));
    }
    Ok(EvalRow {
        unit: id(field(m, "unit")?)?,
        cluster: id(field(m, "cluster")?)?,
        truth: truth.to_string(),
        watcher: s(field(m, "watcher")?)?.to_string(),
        human: s(field(m, "human")?)?.to_string(),
        prevention: prevention.to_string(),
        late: boolean(field(m, "late")?)?,
        review: boolean(field(m, "review")?)?,
    })
}

pub fn eval_row_value(r: &EvalRow) -> Value {
    Value::obj(vec![
        ("unit", Value::str(&r.unit)),
        ("cluster", Value::str(&r.cluster)),
        ("truth", Value::str(&r.truth)),
        ("watcher", Value::str(&r.watcher)),
        ("human", Value::str(&r.human)),
        ("prevention", Value::str(&r.prevention)),
        ("late", Value::Bool(r.late)),
        ("review", Value::Bool(r.review)),
    ])
}

#[derive(Debug, Clone, PartialEq)]
pub struct EvalInput {
    pub id: String,
    pub dataset: String,
    pub policy: String,
    pub split: String,
    pub sampling: String,
    pub independent_units: bool,
    pub population_count: u64,
    pub rows: Vec<EvalRow>,
}

pub fn eval_input(v: &Value) -> R<EvalInput> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "id",
            "dataset",
            "policy",
            "split",
            "sampling",
            "independent_units",
            "population_count",
            "rows",
        ],
    )?;
    let split = s(field(m, "split")?)?;
    if !["heldout", "calibration"].contains(&split) {
        return Err(schem("bad split"));
    }
    let sampling = s(field(m, "sampling")?)?;
    if !["census", "simple_random", "alerts_only"].contains(&sampling) {
        return Err(schem("bad sampling"));
    }
    let rows: R<Vec<EvalRow>> = arr(field(m, "rows")?)?.iter().map(eval_row).collect();
    let rows = rows?;
    Ok(EvalInput {
        id: id(field(m, "id")?)?,
        dataset: hash(field(m, "dataset")?)?,
        policy: hash(field(m, "policy")?)?,
        split: split.to_string(),
        sampling: sampling.to_string(),
        independent_units: boolean(field(m, "independent_units")?)?,
        population_count: u(field(m, "population_count")?)?,
        rows,
    })
}

pub fn eval_input_value(e: &EvalInput) -> Value {
    Value::obj(vec![
        ("id", Value::str(&e.id)),
        ("dataset", Value::str(&e.dataset)),
        ("policy", Value::str(&e.policy)),
        ("split", Value::str(&e.split)),
        ("sampling", Value::str(&e.sampling)),
        ("independent_units", Value::Bool(e.independent_units)),
        (
            "population_count",
            Value::ustr(&e.population_count.to_string()),
        ),
        (
            "rows",
            Value::Arr(e.rows.iter().map(eval_row_value).collect()),
        ),
    ])
}

// ---------------------------------------------------------------------------
// Host / events

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostState {
    Starting,
    Ready,
    Draining,
    Faulted,
    Stopped,
}

impl HostState {
    pub fn as_str(self) -> &'static str {
        match self {
            HostState::Starting => "STARTING",
            HostState::Ready => "READY",
            HostState::Draining => "DRAINING",
            HostState::Faulted => "FAULTED",
            HostState::Stopped => "STOPPED",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Host {
    pub state: HostState,
    pub epoch: u64,
    pub boot: String,
    pub reason: Option<String>,
}

pub fn host_value(h: &Host) -> Value {
    Value::obj(vec![
        ("state", Value::str(h.state.as_str())),
        ("epoch", Value::ustr(&h.epoch.to_string())),
        ("boot", Value::str(&h.boot)),
        (
            "reason",
            h.reason
                .as_ref()
                .map(|x| Value::str(x))
                .unwrap_or(Value::Null),
        ),
    ])
}

/// The 31 event kinds of EventValues, in schema order.
pub const EVENT_KINDS: &[&str] = &[
    "HostStarted",
    "HostReady",
    "HostDraining",
    "HostFaulted",
    "HostStopped",
    "PolicyActivated",
    "RunOpened",
    "ObservationAccepted",
    "RunPaused",
    "RunResumed",
    "RunQuarantined",
    "RunClosed",
    "DriftUpdated",
    "TrailingEvaluated",
    "CheckStarted",
    "CheckFinalized",
    "ReviewOpened",
    "ReviewClaimed",
    "ReviewReleased",
    "ReviewDeferred",
    "ReviewWoken",
    "ReviewAccepted",
    "ReviewRejected",
    "ReviewExpired",
    "ReviewConsumed",
    "ReviewClosed",
    "AlertOpened",
    "AlertUpdated",
    "AlertAcknowledged",
    "AlertResolved",
    "EffectRecorded",
    "EvaluationRecorded",
    "ExportRecorded",
];

#[derive(Debug, Clone, PartialEq)]
pub struct EventBody {
    pub tenant: String,
    pub seq: u64,
    pub prev: String,
    pub epoch: u64,
    pub boot: String,
    pub at_ms: u64,
    pub actor: String,
    pub request: String,
    pub kind: String,
    pub value: Value,
    pub causes: Vec<String>,
}

/// Validate an EventBody; `value` shape is checked against the event kind.
pub fn event_body(v: &Value) -> R<EventBody> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "v", "tenant", "seq", "prev", "epoch", "boot", "at_ms", "actor", "request", "kind",
            "value", "causes",
        ],
    )?;
    lit_num(field(m, "v")?, 1)?;
    let kind = s(field(m, "kind")?)?.to_string();
    if !EVENT_KINDS.contains(&kind.as_str()) {
        return Err(schem("unknown event kind"));
    }
    let value = field(m, "value")?.clone();
    validate_event_value(&kind, &value)?;
    Ok(EventBody {
        tenant: id(field(m, "tenant")?)?,
        seq: u(field(m, "seq")?)?,
        prev: hash(field(m, "prev")?)?,
        epoch: u(field(m, "epoch")?)?,
        boot: boot(field(m, "boot")?)?,
        at_ms: u(field(m, "at_ms")?)?,
        actor: id(field(m, "actor")?)?,
        request: id(field(m, "request")?)?,
        kind,
        value,
        causes: hash_list(field(m, "causes")?)?,
    })
}

pub fn event_body_value(e: &EventBody) -> Value {
    Value::obj(vec![
        ("v", Value::num(1)),
        ("tenant", Value::str(&e.tenant)),
        ("seq", Value::ustr(&e.seq.to_string())),
        ("prev", Value::str(&e.prev)),
        ("epoch", Value::ustr(&e.epoch.to_string())),
        ("boot", Value::str(&e.boot)),
        ("at_ms", Value::ustr(&e.at_ms.to_string())),
        ("actor", Value::str(&e.actor)),
        ("request", Value::str(&e.request)),
        ("kind", Value::str(&e.kind)),
        ("value", e.value.clone()),
        (
            "causes",
            Value::Arr(e.causes.iter().map(|x| Value::str(x)).collect()),
        ),
    ])
}

fn validate_event_value(kind: &str, v: &Value) -> R<()> {
    match kind {
        "HostStarted" | "HostReady" | "HostDraining" | "HostFaulted" | "HostStopped" => {
            let m = obj(v)?;
            closed(m, &["state", "epoch", "boot", "reason"])?;
            let st = s(field(m, "state")?)?;
            if !["STARTING", "READY", "DRAINING", "FAULTED", "STOPPED"].contains(&st) {
                return Err(schem("bad host state"));
            }
            u(field(m, "epoch")?)?;
            boot(field(m, "boot")?)?;
            opt_text(field(m, "reason")?)?;
            Ok(())
        }
        "PolicyActivated" => {
            let sv = signed(v)?;
            policy(&sv.body)?;
            Ok(())
        }
        "RunOpened"
        | "ObservationAccepted"
        | "RunPaused"
        | "RunResumed"
        | "RunQuarantined"
        | "RunClosed"
        | "DriftUpdated" => {
            run(v)?;
            Ok(())
        }
        "TrailingEvaluated" => {
            let m = obj(v)?;
            closed(m, &["run", "window_start_ms", "observation", "results"])?;
            id(field(m, "run")?)?;
            u(field(m, "window_start_ms")?)?;
            let ov = field(m, "observation")?;
            if *ov != Value::Null {
                ref_(ov)?;
            }
            let rs: R<Vec<Result_>> = arr(field(m, "results")?)?.iter().map(result).collect();
            rs?;
            Ok(())
        }
        "CheckStarted" | "CheckFinalized" => {
            check(v)?;
            Ok(())
        }
        "ReviewOpened" | "ReviewClaimed" | "ReviewReleased" | "ReviewDeferred" | "ReviewWoken"
        | "ReviewAccepted" | "ReviewRejected" | "ReviewExpired" | "ReviewConsumed"
        | "ReviewClosed" => {
            review(v)?;
            Ok(())
        }
        "AlertOpened" | "AlertUpdated" | "AlertAcknowledged" | "AlertResolved" => {
            alert(v)?;
            Ok(())
        }
        "EffectRecorded" => {
            let sv = signed(v)?;
            effect_body(&sv.body)?;
            Ok(())
        }
        "EvaluationRecorded" => {
            evaluation(v)?;
            Ok(())
        }
        "ExportRecorded" => {
            let m = obj(v)?;
            closed(m, &["bundle", "through", "disclosure", "recipient"])?;
            hash(field(m, "bundle")?)?;
            head(field(m, "through")?)?;
            let dsc = s(field(m, "disclosure")?)?;
            if dsc != "FULL" && dsc != "COMMITMENTS" {
                return Err(schem("bad disclosure"));
            }
            id(field(m, "recipient")?)?;
            Ok(())
        }
        _ => Err(schem("unknown event kind")),
    }
}

// ---------------------------------------------------------------------------
// Evaluation outputs

fn fraction(v: &Value) -> R<()> {
    let m = obj(v)?;
    closed(m, &["num", "den", "value"])?;
    u(field(m, "num")?)?;
    u(field(m, "den")?)?;
    let val = field(m, "value")?;
    if *val != Value::Null {
        let st = s(val)?;
        // six decimal places
        let parts: Vec<&str> = st.split('.').collect();
        if parts.len() != 2
            || parts[1].len() != 6
            || !parts[0].chars().all(|c| c.is_ascii_digit())
            || !parts[1].chars().all(|c| c.is_ascii_digit())
        {
            return Err(schem("bad fraction value"));
        }
    }
    Ok(())
}

pub fn evaluation(v: &Value) -> R<()> {
    let m = obj(v)?;
    closed(
        m,
        &["id", "input", "watcher", "human", "paired", "late", "claim"],
    )?;
    id(field(m, "id")?)?;
    hash(field(m, "input")?)?;
    lit_str(field(m, "claim")?, "DESCRIPTIVE_NOT_CERTIFICATION")?;
    for name in ["watcher", "human"] {
        measures(field(m, name)?)?;
    }
    let p = obj(field(m, "paired")?)?;
    closed(p, &["watcher_only", "human_only", "both", "neither"])?;
    for f in ["watcher_only", "human_only", "both", "neither"] {
        u(field(p, f)?)?;
    }
    u(field(m, "late")?)?;
    Ok(())
}

fn measures(v: &Value) -> R<()> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "confusion",
            "precision",
            "recall_lower",
            "recall_decided",
            "fpr_lower",
            "fpr_upper",
            "coverage",
            "review_rate",
            "prevention",
            "recall_ci95",
            "ci_status",
        ],
    )?;
    let c = obj(field(m, "confusion")?)?;
    closed(
        c,
        &[
            "tp",
            "fp",
            "tn",
            "fn",
            "abstain_dangerous",
            "abstain_benign",
            "unlabeled",
        ],
    )?;
    for f in [
        "tp",
        "fp",
        "tn",
        "fn",
        "abstain_dangerous",
        "abstain_benign",
        "unlabeled",
    ] {
        u(field(c, f)?)?;
    }
    for f in [
        "precision",
        "recall_lower",
        "recall_decided",
        "fpr_lower",
        "fpr_upper",
        "coverage",
        "review_rate",
        "prevention",
    ] {
        fraction(field(m, f)?)?;
    }
    let ci = field(m, "recall_ci95")?;
    if *ci != Value::Null {
        let cm = obj(ci)?;
        closed(cm, &["low", "high"])?;
        s(field(cm, "low")?)?;
        s(field(cm, "high")?)?;
    }
    let st = s(field(m, "ci_status")?)?;
    if !["WILSON", "DESCRIPTIVE_ONLY", "UNDEFINED"].contains(&st) {
        return Err(schem("bad ci_status"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Bundle / trust / verification

#[derive(Debug, Clone, PartialEq)]
pub struct Inventory {
    pub tag: String,
    pub digest: String,
    pub bytes: u64,
    pub present: bool,
}

pub fn inventory(v: &Value) -> R<Inventory> {
    let m = obj(v)?;
    closed(m, &["tag", "digest", "bytes", "present"])?;
    let tag = s(field(m, "tag")?)?;
    if !["policy", "observation", "effect", "evaluation"].contains(&tag) {
        return Err(schem("bad inventory tag"));
    }
    Ok(Inventory {
        tag: tag.to_string(),
        digest: hash(field(m, "digest")?)?,
        bytes: u(field(m, "bytes")?)?,
        present: boolean(field(m, "present")?)?,
    })
}

pub fn inventory_value(i: &Inventory) -> Value {
    Value::obj(vec![
        ("tag", Value::str(&i.tag)),
        ("digest", Value::str(&i.digest)),
        ("bytes", Value::ustr(&i.bytes.to_string())),
        ("present", Value::Bool(i.present)),
    ])
}

#[derive(Debug, Clone, PartialEq)]
pub struct BundleBody {
    pub tenant: String,
    pub from: Head,
    pub through: Head,
    pub disclosure: String,
    pub inventory: Vec<Inventory>,
    pub event_hashes: Vec<String>,
    pub limitations: Vec<String>,
}

pub fn bundle_body(v: &Value) -> R<BundleBody> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "v",
            "format",
            "tenant",
            "from",
            "through",
            "disclosure",
            "inventory",
            "event_hashes",
            "limitations",
            "semantics",
        ],
    )?;
    lit_num(field(m, "v")?, 1)?;
    lit_str(field(m, "format")?, "watch-proof/1")?;
    lit_str(
        field(m, "semantics")?,
        "OBSERVATIONS_NOT_ACTION_AUTHORIZATION",
    )?;
    let disc = s(field(m, "disclosure")?)?;
    if disc != "FULL" && disc != "COMMITMENTS" {
        return Err(schem("bad disclosure"));
    }
    let inv: R<Vec<Inventory>> = arr(field(m, "inventory")?)?.iter().map(inventory).collect();
    let lims: R<Vec<String>> = arr(field(m, "limitations")?)?.iter().map(text).collect();
    Ok(BundleBody {
        tenant: id(field(m, "tenant")?)?,
        from: head(field(m, "from")?)?,
        through: head(field(m, "through")?)?,
        disclosure: disc.to_string(),
        inventory: inv?,
        event_hashes: hash_array(field(m, "event_hashes")?)?,
        limitations: lims?,
    })
}

#[derive(Debug, Clone, PartialEq)]
pub struct KeyPin {
    pub id: String,
    pub public_key: String,
    pub tags: Vec<String>,
    pub subjects: Vec<String>,
    pub from_epoch: u64,
    pub through_epoch: Option<u64>,
    pub live: bool,
    pub compromised: bool,
}

pub fn key_pin(v: &Value) -> R<KeyPin> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "id",
            "public_key",
            "tags",
            "subjects",
            "from_epoch",
            "through_epoch",
            "live",
            "compromised",
        ],
    )?;
    let tags: R<Vec<String>> = arr(field(m, "tags")?)?.iter().map(text).collect();
    let subjects: R<Vec<String>> = arr(field(m, "subjects")?)?.iter().map(id).collect();
    Ok(KeyPin {
        id: id(field(m, "id")?)?,
        public_key: pubkey(field(m, "public_key")?)?,
        tags: tags?,
        subjects: subjects?,
        from_epoch: u(field(m, "from_epoch")?)?,
        through_epoch: opt_u(field(m, "through_epoch")?)?,
        live: boolean(field(m, "live")?)?,
        compromised: boolean(field(m, "compromised")?)?,
    })
}

#[derive(Debug, Clone, PartialEq)]
pub struct Trust {
    pub tenant: String,
    pub keys: Vec<KeyPin>,
    pub sources: Vec<Source>,
    pub minimum_head: Head,
}

pub fn trust(v: &Value) -> R<Trust> {
    let m = obj(v)?;
    closed(m, &["v", "tenant", "keys", "sources", "minimum_head"])?;
    lit_num(field(m, "v")?, 1)?;
    let keys: R<Vec<KeyPin>> = arr(field(m, "keys")?)?.iter().map(key_pin).collect();
    let sources: R<Vec<Source>> = arr(field(m, "sources")?)?.iter().map(source).collect();
    Ok(Trust {
        tenant: id(field(m, "tenant")?)?,
        keys: keys?,
        sources: sources?,
        minimum_head: head(field(m, "minimum_head")?)?,
    })
}

// ---------------------------------------------------------------------------
// Config / principal / source / release

#[derive(Debug, Clone, PartialEq)]
pub struct Principal {
    pub id: String,
    pub uid: u64,
    pub roles: Vec<String>,
}

pub fn principal(v: &Value) -> R<Principal> {
    let m = obj(v)?;
    closed(m, &["id", "uid", "roles"])?;
    let roles: R<Vec<String>> = arr(field(m, "roles")?)?
        .iter()
        .map(|r| {
            let role = s(r)?;
            if !["runtime", "reviewer", "operator", "auditor"].contains(&role) {
                return Err(schem("bad role"));
            }
            Ok(role.to_string())
        })
        .collect();
    Ok(Principal {
        id: id(field(m, "id")?)?,
        uid: n(field(m, "uid")?)?,
        roles: roles?,
    })
}

#[derive(Debug, Clone, PartialEq)]
pub struct Source {
    pub id: String,
    pub runtime: String,
    pub key_id: String,
    pub key_epoch: u64,
    pub epoch: u64,
    pub profile: String,
}

pub fn source(v: &Value) -> R<Source> {
    let m = obj(v)?;
    closed(
        m,
        &["id", "runtime", "key_id", "key_epoch", "epoch", "profile"],
    )?;
    let profile = s(field(m, "profile")?)?;
    if profile != "fixture/1" && profile != "runtime-guard/1" {
        return Err(schem("bad source profile"));
    }
    Ok(Source {
        id: id(field(m, "id")?)?,
        runtime: id(field(m, "runtime")?)?,
        key_id: id(field(m, "key_id")?)?,
        key_epoch: u(field(m, "key_epoch")?)?,
        epoch: u(field(m, "epoch")?)?,
        profile: profile.to_string(),
    })
}

#[derive(Debug, Clone)]
pub struct Config {
    pub tenant: String,
    pub deployment: String,
    pub socket: String,
    pub data_dir: String,
    pub signer_key_id: String,
    pub signer_key_epoch: u64,
    pub signer_key_file: String,
    pub trust_file: String,
    pub principals: Vec<Principal>,
    pub sources: Vec<Source>,
    pub installed_artifacts: Vec<(Detector, String, String)>,
    pub certified_profiles: Vec<String>,
    pub release: Option<Signed>,
    pub storage_max_bytes: u64,
    pub storage_warn_bp: u64,
    pub storage_stop_bp: u64,
    pub storage_raw_days: u64,
    pub storage_audit_days: u64,
    pub object_key_id: String,
    pub object_key_file: String,
}

pub fn config(v: &Value) -> R<Config> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "v",
            "tenant",
            "deployment",
            "socket",
            "data_dir",
            "signer",
            "trust_file",
            "principals",
            "sources",
            "installed_artifacts",
            "certified_profiles",
            "release",
            "storage",
        ],
    )?;
    lit_num(field(m, "v")?, 1)?;
    let deployment = s(field(m, "deployment")?)?;
    if deployment != "lab" && deployment != "production" {
        return Err(schem("bad deployment"));
    }
    let sm = obj(field(m, "signer")?)?;
    closed(sm, &["key_id", "key_epoch", "key_file"])?;
    let principals: R<Vec<Principal>> = arr(field(m, "principals")?)?
        .iter()
        .map(principal)
        .collect();
    let principals = principals?;
    let sources: R<Vec<Source>> = arr(field(m, "sources")?)?.iter().map(source).collect();
    let sources = sources?;
    let arts: R<Vec<(Detector, String, String)>> = arr(field(m, "installed_artifacts")?)?
        .iter()
        .map(|a| {
            let am = obj(a)?;
            closed(am, &["detector", "digest", "path"])?;
            let d = Detector::parse(s(field(am, "detector")?)?)
                .ok_or_else(|| schem("bad artifact detector"))?;
            Ok((d, hash(field(am, "digest")?)?, text(field(am, "path")?)?))
        })
        .collect();
    let profiles: R<Vec<String>> = arr(field(m, "certified_profiles")?)?
        .iter()
        .map(|p| {
            let t = s(p)?;
            if t != "fixture/1" && t != "runtime-guard/1" {
                return Err(schem("bad certified profile"));
            }
            Ok(t.to_string())
        })
        .collect();
    let st = obj(field(m, "storage")?)?;
    closed(
        st,
        &[
            "max_bytes",
            "warn_bp",
            "stop_bp",
            "raw_days",
            "audit_days",
            "object_key_id",
            "object_key_file",
        ],
    )?;
    let rv = field(m, "release")?;
    let release = if *rv == Value::Null {
        None
    } else {
        Some(signed(rv)?)
    };
    Ok(Config {
        tenant: id(field(m, "tenant")?)?,
        deployment: deployment.to_string(),
        socket: text(field(m, "socket")?)?,
        data_dir: text(field(m, "data_dir")?)?,
        signer_key_id: id(field(sm, "key_id")?)?,
        signer_key_epoch: u(field(sm, "key_epoch")?)?,
        signer_key_file: text(field(sm, "key_file")?)?,
        trust_file: text(field(m, "trust_file")?)?,
        principals,
        sources,
        installed_artifacts: arts?,
        certified_profiles: profiles?,
        release,
        storage_max_bytes: u(field(st, "max_bytes")?)?,
        storage_warn_bp: n(field(st, "warn_bp")?)?,
        storage_stop_bp: n(field(st, "stop_bp")?)?,
        storage_raw_days: n(field(st, "raw_days")?)?,
        storage_audit_days: n(field(st, "audit_days")?)?,
        object_key_id: id(field(st, "object_key_id")?)?,
        object_key_file: text(st_field(st, "object_key_file"))?,
    })
}

fn st_field<'a>(m: &'a [(String, Value)], name: &str) -> &'a Value {
    m.iter().find(|(k, _)| k == name).map(|(_, v)| v).unwrap()
}

// ---------------------------------------------------------------------------
// Monitor job / reply

pub fn monitor_job(v: &Value) -> R<()> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "v",
            "job",
            "monitor",
            "policy",
            "observation",
            "intent",
            "drift",
            "deadline_ms",
        ],
    )?;
    lit_num(field(m, "v")?, 1)?;
    id(field(m, "job")?)?;
    monitor(field(m, "monitor")?)?;
    policy(field(m, "policy")?)?;
    let ov = field(m, "observation")?;
    let os = signed(ov)?;
    observation_body(&os.body)?;
    let iv = field(m, "intent")?;
    if *iv != Value::Null {
        intent(iv)?;
    }
    let dv = field(m, "drift")?;
    if *dv != Value::Null {
        drift(dv)?;
    }
    u(field(m, "deadline_ms")?)?;
    Ok(())
}
