//! The single-writer daemon core: startup/recovery, admission order,
//! durable mutation/commit, timers, monitor dispatch, trailing windows,
//! alerts, and the remainder queue mechanics (§2, §6.2, §7).

use std::collections::HashMap;

use ed25519_dalek::SigningKey;
use rusqlite::{Transaction, TransactionBehavior};

use crate::aggregate;
use crate::crypto::{d, signing_key_from_bytes};
use crate::events::{emit, EmitCtx};
use crate::fault::{Code, Fault};
use crate::json::{jcs, Value};
use crate::monitor::WorkerPool;
use crate::objects::ObjectStore;
use crate::schema::*;
use crate::store::Store;

/// All 23 public methods.
pub const METHODS: &[&str] = &[
    "system.status",
    "system.drain",
    "policy.activate",
    "runs.open",
    "runs.get",
    "runs.control",
    "observations.append",
    "checks.create",
    "checks.get",
    "checks.cancel",
    "effects.record",
    "reviews.list",
    "reviews.get",
    "reviews.claim",
    "reviews.resolve",
    "alerts.list",
    "alerts.resolve",
    "audit.evaluate",
    "audit.sample",
    "events.read",
    "bundle.export",
    "metrics.get",
    "monitor.evaluate", // internal only — never dispatched on the control socket
];

pub const PUBLIC_METHODS: &[&str] = &[
    "system.status",
    "system.drain",
    "policy.activate",
    "runs.open",
    "runs.get",
    "runs.control",
    "observations.append",
    "checks.create",
    "checks.get",
    "checks.cancel",
    "effects.record",
    "reviews.list",
    "reviews.get",
    "reviews.claim",
    "reviews.resolve",
    "alerts.list",
    "alerts.resolve",
    "audit.evaluate",
    "audit.sample",
    "events.read",
    "bundle.export",
    "metrics.get",
    "server.info",
];

/// Mutations consume an idempotency slot; reads do not.
pub fn is_mutation(method: &str) -> bool {
    matches!(
        method,
        "system.drain"
            | "policy.activate"
            | "runs.open"
            | "runs.control"
            | "observations.append"
            | "checks.create"
            | "checks.cancel"
            | "effects.record"
            | "reviews.claim"
            | "reviews.resolve"
            | "alerts.resolve"
            | "audit.evaluate"
            | "bundle.export"
    )
}

/// While DRAINING: reads plus settling mutations only.
pub fn draining_allowed(method: &str) -> bool {
    matches!(
        method,
        "system.status"
            | "runs.get"
            | "checks.get"
            | "reviews.list"
            | "reviews.get"
            | "alerts.list"
            | "events.read"
            | "metrics.get"
            | "runs.control"
            | "checks.cancel"
            | "effects.record"
            | "reviews.resolve"
            | "alerts.resolve"
            | "system.drain"
    )
}

/// Coarse role gate: at least one principal role may call the method.
/// Ownership and run-binding are checked inside the handlers.
pub fn role_allowed(roles: &[String], method: &str) -> bool {
    let has = |r: &str| roles.iter().any(|x| x == r);
    match method {
        "system.status" => true,
        "system.drain" | "policy.activate" => has("operator"),
        "runs.open"
        | "observations.append"
        | "checks.create"
        | "checks.cancel"
        | "effects.record" => has("runtime"),
        "runs.get" | "checks.get" => {
            has("operator") || has("auditor") || has("reviewer") || has("runtime")
        }
        "reviews.list" | "reviews.get" | "alerts.list" => {
            has("reviewer") || has("operator") || has("auditor")
        }
        "reviews.claim" | "reviews.resolve" | "alerts.resolve" => has("reviewer"),
        "runs.control" => has("operator") || has("runtime"),
        "events.read" | "metrics.get" => has("operator") || has("auditor"),
        "audit.evaluate" | "audit.sample" | "bundle.export" => has("auditor"),
        _ => false,
    }
}

/// The reply envelope shared by dispatch and the in-transaction
/// idempotency write.
pub fn reply_envelope(req_id: &str, r: Result<Value, Fault>) -> Value {
    match r {
        Ok(result) => Value::obj(vec![
            ("v", Value::num(1)),
            ("id", Value::str(req_id)),
            ("ok", Value::Bool(true)),
            ("result", result),
        ]),
        Err(f) => Value::obj(vec![
            ("v", Value::num(1)),
            ("id", Value::str(req_id)),
            ("ok", Value::Bool(false)),
            ("error", f.to_value()),
        ]),
    }
}

/// Outcome of one dispatch: a reply value, or a simulated crash (no reply).
pub enum Outcome {
    Reply(Value),
    /// Process "died" mid-mutation; caller must restart to test recovery.
    Crashed,
}

/// Fault-injection hooks for the crash campaign (§6.2/§11.3).
#[derive(Default)]
pub struct Inject {
    /// Rollback instead of commit on the next mutation.
    pub crash_before_commit: bool,
    /// Commit then crash before reply on the next mutation.
    pub crash_after_commit: bool,
    /// All durable writes fail (EIO) — audit-unavailable path.
    pub audit_fail: bool,
    /// Return a worker result that differs from recomputation once.
    pub worker_mismatch: bool,
}

pub struct Daemon {
    pub store: Store,
    pub cfg: Config,
    pub trust: Trust,
    pub sk: SigningKey,
    pub objects: Option<ObjectStore>,
    pub workers: WorkerPool,
    pub host: Host,
    pub now: u64,
    pub inject: Inject,
    /// local_notice outbox deliveries (file lines for tests).
    pub notices: Vec<String>,
    /// audit-commit latency reservoir for metrics (bounded 256).
    pub audit_write_ms: Vec<u64>,
    /// metrics counters: (name,kind,outcome) -> value
    pub counters: HashMap<(String, String, String), u64>,
    /// per-principal token bucket: (tokens×1000, last_refill_ms)
    rate: HashMap<String, (u64, u64)>,
    /// protocol-error counter for malformed frames (bounded).
    pub protocol_errors: u64,
    /// In-flight mutation's idempotency context (principal, request id,
    /// method, params hash); set by dispatch, consumed by mutate.
    pub cur_idem: Option<(String, String, String, String)>,
}

/// Mutation outcome (§7.1): committed replies persist in the idempotency
/// table; `Rejected` rolls back and stores nothing (pre-admission faults).
pub enum MOut {
    /// Commit writes; store the success reply.
    Ok(Value),
    /// Commit writes (e.g. a source-fault pause); store the fault reply.
    Fault(Fault),
    /// Roll back; no idempotency record — exact retries re-execute.
    Rejected(Fault),
}

/// Marker for a simulated crash (see `Inject`).
pub struct CrashSig;

/// Handler error: `Reject` = pre-admission fault (rollback, no idempotency
/// record); `Crash` = simulated crash (no reply at all).
pub enum HErr {
    Reject(Fault),
    Crash,
}
impl From<Fault> for HErr {
    fn from(f: Fault) -> HErr {
        HErr::Reject(f)
    }
}
impl From<CrashSig> for HErr {
    fn from(_: CrashSig) -> HErr {
        HErr::Crash
    }
}

impl Daemon {
    // ---------------------------------------------------------------
    // Startup and recovery (§2.1, §6.2, §5.1)

    /// Build a daemon over an opened store. Performs the full start sequence:
    /// gates → epoch++ → HostStarted → restart recovery → HostReady (or
    /// HostFaulted when the store is behind the pinned minimum head).
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        store: Store,
        cfg: Config,
        trust: Trust,
        objects: Option<ObjectStore>,
        workers: WorkerPool,
        now: u64,
        boot: &str,
        signer_pem: &[u8],
    ) -> Result<Daemon, Fault> {
        // Release-mode gates (§5.1, TV-W-62).
        crate::config::startup_gates(&cfg, &trust)?;

        let sk = signing_key_from_bytes(signer_pem)
            .ok_or_else(|| Fault::new(Code::Gated, "signer key unreadable"))?;
        // Signer must be a live pinned key for the Watch tags on the tenant.
        for tag in ["audit", "clearance", "bundle", "backup"] {
            crate::config::require_pin(
                &trust,
                tag,
                &cfg.tenant,
                &cfg.signer_key_id,
                cfg.signer_key_epoch,
            )
            .map_err(|e| Fault::new(Code::Gated, &format!("signer pin: {}", e.message)))?;
        }
        // Installed artifacts must verify at startup.
        crate::config::verify_artifacts(&cfg)?;

        let prev_epoch: u64 = store
            .meta_get("host_epoch")?
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let epoch = prev_epoch + 1;
        let mut d = Daemon {
            store,
            cfg,
            trust,
            sk,
            objects,
            workers,
            host: Host {
                state: HostState::Starting,
                epoch,
                boot: boot.to_string(),
                reason: None,
            },
            now,
            inject: Inject::default(),
            notices: Vec::new(),
            audit_write_ms: Vec::new(),
            counters: HashMap::new(),
            rate: HashMap::new(),
            protocol_errors: 0,
            cur_idem: None,
        };

        // HostStarted.
        {
            let tx = d.begin()?;
            let mut emitted = Vec::new();
            Store::tx_meta_set(&tx, "host_epoch", &epoch.to_string())?;
            emit(
                &tx,
                &d.emit_ctx(),
                now,
                "watchd",
                "watchd",
                "HostStarted",
                host_value(&d.host),
                vec![],
                &mut emitted,
            )?;
            tx.commit()
                .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        }

        // Behind the independent minimum head → FAULTED, read-only.
        let head = d.store.head()?;
        if head.seq < d.trust.minimum_head.seq {
            d.host.state = HostState::Faulted;
            d.host.reason = Some("restored behind minimum head".into());
            let tx = d.begin()?;
            let mut emitted = Vec::new();
            emit(
                &tx,
                &d.emit_ctx(),
                now,
                "watchd",
                "watchd",
                "HostFaulted",
                host_value(&d.host),
                vec![],
                &mut emitted,
            )?;
            tx.commit()
                .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
            return Err(Fault::new(
                Code::MigrationRequired,
                "store behind minimum head",
            ));
        }

        // Restart recovery (§2.1/§2.4): pause OPEN runs, expire active
        // reviews and EVALUATING checks — one recovery transaction.
        {
            let tx = d.begin()?;
            let mut emitted = Vec::new();
            let mut run_ids: Vec<String> = Vec::new();
            {
                let mut st = tx
                    .prepare(
                        "SELECT id,body FROM runs WHERE state IN ('OPEN','PAUSED') ORDER BY id",
                    )
                    .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
                let rows = st
                    .query_map([], |r| {
                        Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
                    })
                    .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
                for r in rows {
                    let (id, body) =
                        r.map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
                    run_ids.push(id);
                    let _ = body;
                }
            }
            for rid in &run_ids {
                let mut run = d.load_run_tx(&tx, rid)?.unwrap();
                if run.state == RunState::Open {
                    run.state = RunState::Paused;
                    run.pause_reason = Some("RESTART".into());
                    run.revision += 1;
                    let (seq, _) = emit(
                        &tx,
                        &d.emit_ctx(),
                        now,
                        "watchd",
                        "watchd",
                        "RunPaused",
                        run_value(&run),
                        vec![],
                        &mut emitted,
                    )?;
                    Store::tx_put_entity(
                        &tx,
                        "runs",
                        rid,
                        &jcs(&run_value(&run)).into_bytes(),
                        seq,
                        "runs",
                    )?;
                }
            }
            // Active reviews expire on restart.
            let review_ids = Self::entity_ids_by_state(&tx, "reviews", ACTIVE_REVIEW_STATES)?;
            for rid in &review_ids {
                let mut rv = d.load_review_tx(&tx, rid)?.unwrap();
                rv.state = ReviewState::Expired;
                rv.revision += 1;
                rv.owner = None;
                rv.lease_until_ms = None;
                let (seq, _) = emit(
                    &tx,
                    &d.emit_ctx(),
                    now,
                    "watchd",
                    "watchd",
                    "ReviewExpired",
                    review_value(&rv),
                    vec![],
                    &mut emitted,
                )?;
                Store::tx_put_entity(
                    &tx,
                    "reviews",
                    rid,
                    &jcs(&review_value(&rv)).into_bytes(),
                    seq,
                    "reviews",
                )?;
            }
            // EVALUATING checks expire RESTART.
            let check_ids = Self::entity_ids_by_state(&tx, "checks", &["EVALUATING"])?;
            for cid in &check_ids {
                let mut c = d.load_check_tx(&tx, cid)?.unwrap();
                c.state = CheckState::Expired;
                c.reason = "RESTART".into();
                c.revision += 1;
                let (seq, _) = emit(
                    &tx,
                    &d.emit_ctx(),
                    now,
                    "watchd",
                    "watchd",
                    "CheckFinalized",
                    check_value(&c),
                    vec![],
                    &mut emitted,
                )?;
                Store::tx_put_entity(
                    &tx,
                    "checks",
                    cid,
                    &jcs(&check_value(&c)).into_bytes(),
                    seq,
                    "checks",
                )?;
                d.bump(&tx, "watch_checks_total", "", "EXPIRED", 1)?;
            }
            tx.commit()
                .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        }

        d.host.state = HostState::Ready;
        {
            let tx = d.begin()?;
            let mut emitted = Vec::new();
            emit(
                &tx,
                &d.emit_ctx(),
                now,
                "watchd",
                "watchd",
                "HostReady",
                host_value(&d.host),
                vec![],
                &mut emitted,
            )?;
            tx.commit()
                .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        }
        Ok(d)
    }

    pub const ACTIVE_REVIEW: &'static [&'static str] = &["OPEN", "CLAIMED", "DEFERRED", "ACCEPTED"];

    pub fn entity_ids_by_state(
        tx: &Transaction,
        table: &str,
        states: &[&str],
    ) -> Result<Vec<String>, Fault> {
        let q = match table {
            "runs" => format!(
                "SELECT id FROM runs WHERE state IN ({}) ORDER BY id",
                states
                    .iter()
                    .map(|s| format!("'{s}'"))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            "reviews" => format!(
                "SELECT id FROM reviews WHERE state IN ({}) ORDER BY id",
                states
                    .iter()
                    .map(|s| format!("'{s}'"))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            "checks" => format!(
                "SELECT id FROM checks WHERE state IN ({}) ORDER BY id",
                states
                    .iter()
                    .map(|s| format!("'{s}'"))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            _ => return Err(Fault::new(Code::AuditUnavailable, "bad entity table")),
        };
        let mut st = tx
            .prepare(&q)
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        let rows = st
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?);
        }
        Ok(out)
    }

    pub fn emit_ctx(&self) -> EmitCtx<'_> {
        EmitCtx {
            tenant: &self.cfg.tenant,
            epoch: self.host.epoch,
            boot: &self.host.boot,
            key_id: &self.cfg.signer_key_id,
            key_epoch: self.cfg.signer_key_epoch,
            sk: &self.sk,
        }
    }

    pub fn begin(&self) -> Result<Transaction<'_>, Fault> {
        Transaction::new_unchecked(&self.store.conn, TransactionBehavior::Immediate)
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))
    }

    // ---------------------------------------------------------------
    // Loaders

    pub fn load_run_tx(&self, tx: &Transaction, id: &str) -> Result<Option<Run>, Fault> {
        use rusqlite::OptionalExtension;
        let body: Option<Vec<u8>> = tx
            .query_row(
                "SELECT body FROM runs WHERE id=?1",
                rusqlite::params![id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        match body {
            Some(b) => {
                let v = crate::json::parse(&b, &crate::json::Limits::reply())
                    .map_err(|_| Fault::new(Code::AuditUnavailable, "run body parse"))?;
                Ok(Some(run(&v)?))
            }
            None => Ok(None),
        }
    }

    pub fn load_run(&self, id: &str) -> Result<Option<Run>, Fault> {
        match self.store.get_entity_body("runs", id)? {
            Some(b) => {
                let v = crate::json::parse(&b, &crate::json::Limits::reply())
                    .map_err(|_| Fault::new(Code::AuditUnavailable, "run body parse"))?;
                Ok(Some(run(&v)?))
            }
            None => Ok(None),
        }
    }

    pub fn load_check(&self, id: &str) -> Result<Option<Check>, Fault> {
        match self.store.get_entity_body("checks", id)? {
            Some(b) => {
                let v = crate::json::parse(&b, &crate::json::Limits::reply())
                    .map_err(|_| Fault::new(Code::AuditUnavailable, "check body parse"))?;
                Ok(Some(check(&v)?))
            }
            None => Ok(None),
        }
    }

    pub fn load_check_tx(&self, tx: &Transaction, id: &str) -> Result<Option<Check>, Fault> {
        use rusqlite::OptionalExtension;
        let body: Option<Vec<u8>> = tx
            .query_row(
                "SELECT body FROM checks WHERE id=?1",
                rusqlite::params![id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        match body {
            Some(b) => {
                let v = crate::json::parse(&b, &crate::json::Limits::reply())
                    .map_err(|_| Fault::new(Code::AuditUnavailable, "check body parse"))?;
                Ok(Some(check(&v)?))
            }
            None => Ok(None),
        }
    }

    pub fn load_review(&self, id: &str) -> Result<Option<Review>, Fault> {
        match self.store.get_entity_body("reviews", id)? {
            Some(b) => {
                let v = crate::json::parse(&b, &crate::json::Limits::reply())
                    .map_err(|_| Fault::new(Code::AuditUnavailable, "review body parse"))?;
                Ok(Some(review(&v)?))
            }
            None => Ok(None),
        }
    }

    pub fn load_review_tx(&self, tx: &Transaction, id: &str) -> Result<Option<Review>, Fault> {
        use rusqlite::OptionalExtension;
        let body: Option<Vec<u8>> = tx
            .query_row(
                "SELECT body FROM reviews WHERE id=?1",
                rusqlite::params![id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        match body {
            Some(b) => {
                let v = crate::json::parse(&b, &crate::json::Limits::reply())
                    .map_err(|_| Fault::new(Code::AuditUnavailable, "review body parse"))?;
                Ok(Some(review(&v)?))
            }
            None => Ok(None),
        }
    }

    pub fn load_alert(&self, id: &str) -> Result<Option<Alert>, Fault> {
        match self.store.get_entity_body("alerts", id)? {
            Some(b) => {
                let v = crate::json::parse(&b, &crate::json::Limits::reply())
                    .map_err(|_| Fault::new(Code::AuditUnavailable, "alert body parse"))?;
                Ok(Some(alert(&v)?))
            }
            None => Ok(None),
        }
    }

    /// The active signed policy: (digest, Policy body, full envelope Value).
    pub fn active_policy(&self) -> Result<Option<(String, Policy, Value)>, Fault> {
        match self.store.policy_latest()? {
            Some(bytes) => {
                let v = crate::json::parse(&bytes, &crate::json::Limits::reply())
                    .map_err(|_| Fault::new(Code::AuditUnavailable, "policy parse"))?;
                let sv = signed(&v)?;
                let p = policy(&sv.body)?;
                Ok(Some((sv.digest.clone(), p, v)))
            }
            None => Ok(None),
        }
    }

    /// Observation envelope + parsed body by ref identity (source, epoch,
    /// seq, hash).
    pub fn observation_by_ref(
        &self,
        r: &Ref,
    ) -> Result<Option<(Signed, ObservationBody, Vec<u8>)>, Fault> {
        use rusqlite::OptionalExtension;
        let got: Option<(String, Vec<u8>)> = self
            .store
            .conn
            .query_row(
                "SELECT digest,envelope FROM observations WHERE source=?1 AND epoch=?2 AND seq=?3 AND digest=?4",
                rusqlite::params![r.source, r.epoch as i64, r.seq as i64, r.hash],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        match got {
            Some((_dg, env)) => {
                let v = crate::json::parse(&env, &crate::json::Limits::reply())
                    .map_err(|_| Fault::new(Code::AuditUnavailable, "obs parse"))?;
                let sv = signed(&v)?;
                let body = observation_body(&sv.body)?;
                Ok(Some((sv, body, env)))
            }
            None => Ok(None),
        }
    }

    pub fn bump(
        &self,
        _tx: &Transaction,
        name: &str,
        kind: &str,
        outcome: &str,
        n: u64,
    ) -> Result<(), Fault> {
        let key = (name.to_string(), kind.to_string(), outcome.to_string());
        let cur: u64 = self
            .store
            .conn
            .query_row(
                "SELECT CAST(value AS INTEGER) FROM meta WHERE k=?1",
                rusqlite::params![format!("ctr:{}|{}|{}", key.0, key.1, key.2)],
                |r| r.get::<_, i64>(0),
            )
            .map(|x| x as u64)
            .unwrap_or(0);
        Store::tx_meta_set(
            _tx,
            &format!("ctr:{}|{}|{}", key.0, key.1, key.2),
            &(cur + n).to_string(),
        )?;
        Ok(())
    }

    // ---------------------------------------------------------------
    // Dispatch — §7.1 admission order

    /// One request → reply. `principal` was resolved from SO_PEERCRED.
    pub fn dispatch(
        &mut self,
        principal: &Principal,
        req_id: &str,
        method: &str,
        params: &Value,
    ) -> Outcome {
        let reply = |r: Result<Value, Fault>| -> Value { reply_envelope(req_id, r) };

        // 1. schema — params validated per method (closed object).
        if !PUBLIC_METHODS.contains(&method) {
            return Outcome::Reply(reply(Err(Fault::new(
                Code::MethodUnknown,
                "unknown method",
            ))));
        }
        if let Err(f) = crate::methods::validate_params(method, params) {
            return Outcome::Reply(reply(Err(f)));
        }
        // 2. role gate (ownership checks inside handlers).
        if !role_allowed(&principal.roles, method) {
            return Outcome::Reply(reply(Err(Fault::new(
                Code::Forbidden,
                "role not permitted",
            ))));
        }
        // 3. idempotency (mutations only).
        let params_hash = d("request", params);
        if is_mutation(method) {
            let prior = {
                let tx = match self.begin() {
                    Ok(t) => t,
                    Err(e) => return Outcome::Reply(reply(Err(e))),
                };
                let got = Store::tx_idem_get(&tx, &principal.id, req_id);
                let _ = tx.rollback();
                match got {
                    Ok(g) => g,
                    Err(e) => return Outcome::Reply(reply(Err(e))),
                }
            };
            if let Some((m, h, stored)) = prior {
                if m == method && h == params_hash {
                    match crate::json::parse(&stored, &crate::json::Limits::reply()) {
                        Ok(v) => return Outcome::Reply(v),
                        Err(_) => {
                            return Outcome::Reply(reply(Err(Fault::new(
                                Code::AuditUnavailable,
                                "stored reply unreadable",
                            ))))
                        }
                    }
                }
                return Outcome::Reply(reply(Err(Fault::new(
                    Code::IdempotencyConflict,
                    "request id rebound",
                ))));
            }
        }
        // 4. host/release readiness.
        match self.host.state {
            HostState::Ready => {}
            HostState::Draining => {
                if !draining_allowed(method) {
                    return Outcome::Reply(reply(Err(Fault::new(
                        Code::StateConflict,
                        "host draining",
                    ))));
                }
            }
            _ => {
                return Outcome::Reply(reply(Err(Fault::new(
                    Code::AuditUnavailable,
                    "host not ready",
                ))))
            }
        }
        // Rate limit (per-principal; exact retries of admitted work bypass
        // new-work capacity but not authentication — a fresh id above the
        // bucket is RATE_LIMITED).
        if !self.rate_ok(&principal.id) {
            return Outcome::Reply(reply(Err(Fault::new(Code::RateLimited, "rate"))));
        }

        // 5+. Entity binding, source/policy/review stages, capacity, and the
        // durable event live inside the method handler. The idempotency
        // record commits in the same transaction as the mutation, so a
        // crash between commit and reply still replays exactly.
        if is_mutation(method) {
            self.cur_idem = Some((
                principal.id.clone(),
                req_id.to_string(),
                method.to_string(),
                params_hash.clone(),
            ));
        }
        let res = crate::methods::execute(self, principal, req_id, method, params);
        self.cur_idem = None;
        match res {
            Err(HErr::Crash) => Outcome::Crashed,
            Err(HErr::Reject(f)) => Outcome::Reply(reply(Err(f))),
            Ok(stage) => {
                let rv = match stage {
                    MOut::Ok(v) => reply(Ok(v)),
                    MOut::Fault(f) | MOut::Rejected(f) => reply(Err(f)),
                };
                Outcome::Reply(rv)
            }
        }
    }

    fn rate_ok(&mut self, principal: &str) -> bool {
        let now = self.now;
        let e = self
            .rate
            .entry(principal.to_string())
            .or_insert((crate::RATE_BURST * 1000, now));
        // refill: RATE_PER_SEC tokens/sec, millitoken precision
        let elapsed = now.saturating_sub(e.1);
        let refill = elapsed * crate::RATE_PER_SEC; // tokens*1000 = ms*rate
        e.0 = (e.0 + refill).min(crate::RATE_BURST * 1000);
        e.1 = now;
        if e.0 >= 1000 {
            e.0 -= 1000;
            true
        } else {
            false
        }
    }

    /// Run a mutation under BEGIN IMMEDIATE; commit + inject hooks.
    /// The closure returns `MOut`; committed outcomes store the reply.
    /// Run a mutation under BEGIN IMMEDIATE; commit + inject hooks.
    ///
    /// `f` returns `MOut`; `Err(fault)` inside the closure is a
    /// pre-admission rejection (rollback, no durable record). `MOut::Fault`
    /// commits the closure's emitted events and stores the fault reply —
    /// the "source fault pauses the run" case of §7.1.
    ///
    /// The transaction borrows the store connection through a raw pointer:
    /// `Transaction` requires an immutable `&Connection`, while `f` needs
    /// `&mut Daemon`. Single-writer + single-threaded guarantees make this
    /// sound — `f` must use the provided `&Transaction` for all DB work
    /// (and may read `self.store.conn` inside the open transaction, which
    /// SQLite resolves to the same in-flight view).
    /// Handler-facing mutate: CrashSig → HErr::Crash.
    pub fn mutate_h<F>(&mut self, now: u64, f: F) -> Result<MOut, HErr>
    where
        F: FnOnce(&mut Daemon, &Transaction, u64, &mut Vec<String>) -> Result<MOut, Fault>,
    {
        self.mutate(now, f).map_err(|_| HErr::Crash)
    }

    pub fn mutate<F>(&mut self, now: u64, f: F) -> Result<MOut, CrashSig>
    where
        F: FnOnce(&mut Daemon, &Transaction, u64, &mut Vec<String>) -> Result<MOut, Fault>,
    {
        if self.inject.audit_fail {
            self.host.state = HostState::Faulted;
            self.host.reason = Some("audit write failure".into());
            return Err(CrashSig);
        }
        let conn: &rusqlite::Connection =
            unsafe { &*(&self.store.conn as *const rusqlite::Connection) };
        let tx = match Transaction::new_unchecked(conn, TransactionBehavior::Immediate) {
            Ok(t) => t,
            Err(e) => {
                return Ok(MOut::Rejected(Fault::new(
                    Code::AuditUnavailable,
                    &e.to_string(),
                )))
            }
        };
        let mut emitted = Vec::new();
        match f(self, &tx, now, &mut emitted) {
            Err(f) => {
                let _ = tx.rollback();
                Ok(MOut::Rejected(f))
            }
            Ok(stage) => {
                // Idempotency record + reply ride the same transaction —
                // "no acknowledgement without committed audit" (§6.2).
                if let Some((pid, rid, m, ph)) = self.cur_idem.clone() {
                    let rv = reply_envelope(
                        &rid,
                        match &stage {
                            MOut::Ok(v) => Ok(v.clone()),
                            MOut::Fault(f) | MOut::Rejected(f) => Err(f.clone()),
                        },
                    );
                    if let Err(e) =
                        Store::tx_idem_put(&tx, &pid, &rid, &m, &ph, &jcs(&rv).into_bytes())
                    {
                        let _ = tx.rollback();
                        return Ok(MOut::Rejected(e));
                    }
                }
                if self.inject.crash_before_commit {
                    self.inject.crash_before_commit = false;
                    let _ = tx.rollback();
                    return Err(CrashSig);
                }
                let t0 = std::time::Instant::now();
                match tx.commit() {
                    Ok(()) => {
                        self.audit_write_ms.push(t0.elapsed().as_millis() as u64);
                        if self.audit_write_ms.len() > 256 {
                            self.audit_write_ms.remove(0);
                        }
                    }
                    Err(e) => {
                        self.host.state = HostState::Faulted;
                        self.host.reason = Some(format!("commit failed: {e}"));
                        return Err(CrashSig);
                    }
                }
                if self.inject.crash_after_commit {
                    self.inject.crash_after_commit = false;
                    return Err(CrashSig);
                }
                Ok(stage)
            }
        }
    }

    // ---------------------------------------------------------------
    // Timers (§7.3 ordering) and monitor completions

    /// Process all work due at `self.now`: run invalidation → review due →
    /// claim/wake expiry → check deadlines → window attempts → outbox →
    /// monitor replies.
    pub fn tick(&mut self) {
        if self.host.state == HostState::Faulted {
            return;
        }
        let now = self.now;
        // 1. source-silence run invalidation
        let _ = self.tick_run_silence(now);
        // 2. hard review due (before lease/wake)
        let _ = self.tick_review_due(now);
        // 3. claim lease expiry, then defer wake
        let _ = self.tick_lease_expiry(now);
        let _ = self.tick_wake(now);
        // 4. check deadlines + settled checks
        let _ = self.tick_checks(now);
        // 5. window attempts (trailing + drift + alerts)
        let _ = self.tick_windows(now);
        // 6. outbox
        let _ = self.tick_outbox(now);
        // 7. monitor completions
        self.tick_monitor_replies(now);
    }

    fn tick_run_silence(&mut self, now: u64) -> Result<(), Fault> {
        let ids = Self::entity_ids_by_state(&self.begin()?, "runs", &["OPEN"])?;
        // (uses a tx only for listing; mutation below)
        let mut paused = Vec::new();
        for id in ids {
            if let Some(run) = self.load_run(&id)? {
                if let Some(lr) = run.last_received_ms {
                    if now.saturating_sub(lr) >= self.active_freshness(&run)? {
                        paused.push(id);
                    }
                }
            }
        }
        if paused.is_empty() {
            return Ok(());
        }
        let _ = self.mutate(now, |d, tx, now, emitted| {
            for id in &paused {
                let mut run = d.load_run_tx(tx, id)?.unwrap();
                if run.state != RunState::Open {
                    continue;
                }
                run.state = RunState::Paused;
                run.pause_reason = Some("SOURCE_SILENCE".into());
                run.revision += 1;
                let (seq, _) = emit(
                    tx,
                    &d.emit_ctx(),
                    now,
                    "watchd",
                    "watchd",
                    "RunPaused",
                    run_value(&run),
                    vec![],
                    emitted,
                )?;
                Store::tx_put_entity(
                    tx,
                    "runs",
                    id,
                    &jcs(&run_value(&run)).into_bytes(),
                    seq,
                    "runs",
                )?;
                d.bump(tx, "watch_source_faults_total", "", "stale", 1)?;
                d.expire_run_checks(tx, now, emitted, id)?;
            }
            Ok(MOut::Ok(Value::Null))
        });
        Ok(())
    }

    fn active_freshness(&self, run: &Run) -> Result<u64, Fault> {
        match self.store.policy_get(&run.policy)? {
            Some(bytes) => {
                let v = crate::json::parse(&bytes, &crate::json::Limits::reply())
                    .map_err(|_| Fault::new(Code::AuditUnavailable, "policy parse"))?;
                let sv = signed(&v)?;
                Ok(policy(&sv.body)?.freshness_ms)
            }
            None => Ok(2_000),
        }
    }

    /// EVALUATING checks of a run that paused/closed → STALE (or CANCELLED
    /// on close).
    pub fn expire_run_checks(
        &mut self,
        tx: &Transaction,
        now: u64,
        emitted: &mut Vec<String>,
        run_id: &str,
    ) -> Result<(), Fault> {
        let q = "SELECT id FROM checks WHERE run=?1 AND state='EVALUATING' ORDER BY id";
        let mut st = tx
            .prepare(q)
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        let ids: Vec<String> = st
            .query_map(rusqlite::params![run_id], |r| r.get(0))
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?
            .collect::<Result<_, _>>()
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        drop(st);
        for cid in ids {
            let mut c = self.load_check_tx(tx, &cid)?.unwrap();
            c.state = CheckState::Stale;
            c.reason = "STALE".into();
            c.revision += 1;
            let (seq, _) = emit(
                tx,
                &self.emit_ctx(),
                now,
                "watchd",
                "watchd",
                "CheckFinalized",
                check_value(&c),
                vec![],
                emitted,
            )?;
            Store::tx_put_entity(
                tx,
                "checks",
                &cid,
                &jcs(&check_value(&c)).into_bytes(),
                seq,
                "checks",
            )?;
            self.bump(tx, "watch_checks_total", "", "STALE", 1)?;
        }
        Ok(())
    }

    /// Expire active reviews on run close / policy invalidation.
    pub fn expire_run_reviews(
        &mut self,
        tx: &Transaction,
        now: u64,
        emitted: &mut Vec<String>,
        run_id: &str,
    ) -> Result<(), Fault> {
        let q = "SELECT id FROM reviews WHERE run=?1 AND state IN ('OPEN','CLAIMED','DEFERRED','ACCEPTED') ORDER BY id";
        let mut st = tx
            .prepare(q)
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        let ids: Vec<String> = st
            .query_map(rusqlite::params![run_id], |r| r.get(0))
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?
            .collect::<Result<_, _>>()
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        drop(st);
        for rid in ids {
            let mut rv = self.load_review_tx(tx, &rid)?.unwrap();
            rv.state = ReviewState::Expired;
            rv.revision += 1;
            rv.owner = None;
            rv.lease_until_ms = None;
            let (seq, _) = emit(
                tx,
                &self.emit_ctx(),
                now,
                "watchd",
                "watchd",
                "ReviewExpired",
                review_value(&rv),
                vec![],
                emitted,
            )?;
            Store::tx_put_entity(
                tx,
                "reviews",
                &rid,
                &jcs(&review_value(&rv)).into_bytes(),
                seq,
                "reviews",
            )?;
        }
        Ok(())
    }

    fn tick_review_due(&mut self, now: u64) -> Result<(), Fault> {
        let due: Vec<String> = {
            let tx = self.begin()?;
            let mut st = tx
                .prepare(
                    "SELECT r.id FROM reviews r WHERE r.state IN ('OPEN','CLAIMED','DEFERRED','ACCEPTED') AND (
                       (r.state='ACCEPTED' AND json_extract(r.body,'$.accepted_until_ms') IS NOT NULL
                        AND CAST(json_extract(r.body,'$.accepted_until_ms') AS INTEGER) <= ?1)
                       OR CAST(json_extract(r.body,'$.due_ms') AS INTEGER) <= ?1)
                     ORDER BY r.id",
                )
                .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
            let rows = st
                .query_map(rusqlite::params![now as i64], |r| r.get::<_, String>(0))
                .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
            let mut v = Vec::new();
            for r in rows {
                v.push(r.map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?);
            }
            v
        };
        if due.is_empty() {
            return Ok(());
        }
        let _ = self.mutate(now, |d, tx, now, emitted| {
            for id in &due {
                let mut rv = d.load_review_tx(tx, id)?.unwrap();
                if !rv.state.active() {
                    continue;
                }
                let effective_due = if rv.state == ReviewState::Accepted {
                    rv.accepted_until_ms.unwrap_or(rv.due_ms).min(rv.due_ms)
                } else {
                    rv.due_ms
                };
                if now < effective_due {
                    continue;
                }
                rv.state = ReviewState::Expired;
                rv.revision += 1;
                rv.owner = None;
                rv.lease_until_ms = None;
                let (seq, _) = emit(
                    tx,
                    &d.emit_ctx(),
                    now,
                    "watchd",
                    "watchd",
                    "ReviewExpired",
                    review_value(&rv),
                    vec![],
                    emitted,
                )?;
                Store::tx_put_entity(
                    tx,
                    "reviews",
                    id,
                    &jcs(&review_value(&rv)).into_bytes(),
                    seq,
                    "reviews",
                )?;
            }
            Ok(MOut::Ok(Value::Null))
        });
        Ok(())
    }

    fn tick_lease_expiry(&mut self, now: u64) -> Result<(), Fault> {
        let items: Vec<String> = {
            let tx = self.begin()?;
            let mut st = tx
                .prepare(
                    "SELECT id FROM reviews WHERE state='CLAIMED' AND lease_ms IS NOT NULL AND lease_ms <= ?1 ORDER BY id",
                )
                .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
            let rows = st
                .query_map(rusqlite::params![now as i64], |r| r.get::<_, String>(0))
                .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
            let mut v = Vec::new();
            for r in rows {
                v.push(r.map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?);
            }
            v
        };
        if items.is_empty() {
            return Ok(());
        }
        let _ = self.mutate(now, |d, tx, now, emitted| {
            for id in &items {
                let mut rv = d.load_review_tx(tx, id)?.unwrap();
                if rv.state != ReviewState::Claimed {
                    continue;
                }
                if rv.lease_until_ms.map(|l| now < l).unwrap_or(true) {
                    continue;
                }
                if now >= rv.due_ms {
                    continue; // hard due handled by tick_review_due first
                }
                rv.state = ReviewState::Open;
                rv.revision += 1;
                rv.owner = None;
                rv.lease_until_ms = None;
                let (seq, _) = emit(
                    tx,
                    &d.emit_ctx(),
                    now,
                    "watchd",
                    "watchd",
                    "ReviewReleased",
                    review_value(&rv),
                    vec![],
                    emitted,
                )?;
                Store::tx_put_entity(
                    tx,
                    "reviews",
                    id,
                    &jcs(&review_value(&rv)).into_bytes(),
                    seq,
                    "reviews",
                )?;
            }
            Ok(MOut::Ok(Value::Null))
        });
        Ok(())
    }

    fn tick_wake(&mut self, now: u64) -> Result<(), Fault> {
        let items: Vec<String> = {
            let tx = self.begin()?;
            let mut st = tx
                .prepare(
                    "SELECT id FROM reviews WHERE state='DEFERRED' AND json_extract(body,'$.wake_ms') IS NOT NULL AND CAST(json_extract(body,'$.wake_ms') AS INTEGER) <= ?1 ORDER BY id",
                )
                .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
            let rows = st
                .query_map(rusqlite::params![now as i64], |r| r.get::<_, String>(0))
                .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
            let mut v = Vec::new();
            for r in rows {
                v.push(r.map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?);
            }
            v
        };
        if items.is_empty() {
            return Ok(());
        }
        let _ = self.mutate(now, |d, tx, now, emitted| {
            for id in &items {
                let mut rv = d.load_review_tx(tx, id)?.unwrap();
                if rv.state != ReviewState::Deferred {
                    continue;
                }
                if now >= rv.due_ms {
                    continue;
                }
                if rv.wake_ms.map(|w| now < w).unwrap_or(true) {
                    continue;
                }
                rv.state = ReviewState::Open;
                rv.revision += 1;
                rv.wake_ms = None;
                let (seq, _) = emit(
                    tx,
                    &d.emit_ctx(),
                    now,
                    "watchd",
                    "watchd",
                    "ReviewWoken",
                    review_value(&rv),
                    vec![],
                    emitted,
                )?;
                Store::tx_put_entity(
                    tx,
                    "reviews",
                    id,
                    &jcs(&review_value(&rv)).into_bytes(),
                    seq,
                    "reviews",
                )?;
            }
            Ok(MOut::Ok(Value::Null))
        });
        Ok(())
    }

    /// Check deadlines: slot timeouts, then finalize settled-or-expired.
    fn tick_checks(&mut self, now: u64) -> Result<(), Fault> {
        let ids = Self::entity_ids_by_state(&self.begin()?, "checks", &["EVALUATING"])?;
        for cid in ids {
            let _ = self.maybe_finalize_check(&cid, now);
        }
        Ok(())
    }

    /// Finalize an EVALUATING check when all required slots settled or the
    /// check/slot deadlines passed (§2.2/§7.1).
    pub fn maybe_finalize_check(&mut self, check_id: &str, now: u64) -> Result<(), Fault> {
        let Some(c) = self.load_check(check_id)? else {
            return Ok(());
        };
        if c.state != CheckState::Evaluating {
            return Ok(());
        }
        let slots = self.store.slots_for_check(check_id)?;
        let all_done = slots
            .iter()
            .all(|(_, dl, st, _)| st == "done" || st == "timeout" || now >= *dl);
        if !all_done && now < c.deadline_ms {
            return Ok(());
        }
        // Assemble the required result vector in monitor-ID order.
        let mut results: Vec<aggregate::Slot> = Vec::new();
        for (_mid, dl, st, res) in &slots {
            if st == "done" {
                if let Some(bytes) = res {
                    if now < *dl {
                        let v = crate::json::parse(bytes, &crate::json::Limits::reply())
                            .map_err(|_| Fault::new(Code::AuditUnavailable, "result parse"))?;
                        results.push(Some(result(&v)?));
                        continue;
                    }
                }
            }
            results.push(None);
        }
        self.finalize_check(check_id, now, &results)
    }

    /// The finalization transaction: rechecks + aggregation + commit.
    fn finalize_check(
        &mut self,
        check_id: &str,
        now: u64,
        slots: &[aggregate::Slot],
    ) -> Result<(), Fault> {
        let slots_owned: Vec<aggregate::Slot> = slots.to_vec();
        let _ = self.mutate(now, |d, tx, now, emitted| {
            let Some(mut c) = d.load_check_tx(tx, check_id)? else {
                return Ok(MOut::Ok(Value::Null));
            };
            if c.state != CheckState::Evaluating {
                return Ok(MOut::Ok(Value::Null));
            }
            let Some(run) = d.load_run_tx(tx, &c.run)? else {
                return Ok(MOut::Ok(Value::Null));
            };
            let pol_v = Store::policy_get_on(tx, &c.policy)?
                .ok_or_else(|| Fault::new(Code::AuditUnavailable, "policy lost"))?;
            let pol_env = crate::json::parse(&pol_v, &crate::json::Limits::reply())
                .map_err(|_| Fault::new(Code::AuditUnavailable, "policy parse"))?;
            let pol_sv = signed(&pol_env)?;
            let pol = policy(&pol_sv.body)?;
            // §7.1 final-transaction rechecks.
            let stale = run.state != RunState::Open || run.policy != c.policy;
            if stale {
                d.finalize_stale(tx, now, emitted, &mut c)?;
                return Ok(MOut::Ok(Value::Null));
            }
            // Observation freshness at finalization.
            let Some((obs_sv, obs_body, _obs_bytes)) = d.observation_by_ref(&c.observation)? else {
                d.finalize_stale(tx, now, emitted, &mut c)?;
                return Ok(MOut::Ok(Value::Null));
            };
            if now.saturating_sub(obs_body.cut_ms) >= pol.freshness_ms {
                d.finalize_stale(tx, now, emitted, &mut c)?;
                return Ok(MOut::Ok(Value::Null));
            }
            // A newer observation must keep the checked fields identical.
            if run.cursor.seq > c.observation.seq {
                if let Some(latest) = d.store.latest_observation(&run.id)? {
                    let lv = crate::json::parse(&latest, &crate::json::Limits::reply())
                        .map_err(|_| Fault::new(Code::AuditUnavailable, "obs parse"))?;
                    let lsv = signed(&lv)?;
                    let lb = observation_body(&lsv.body)?;
                    let a = &obs_body.snapshot;
                    let b = &lb.snapshot;
                    let same = a.scopes == b.scopes
                        && a.replicas == b.replicas
                        && a.target_revision == b.target_revision
                        && a.committed_minor == b.committed_minor
                        && a.reserved_minor == b.reserved_minor
                        && lb.source == obs_body.source
                        && lb.epoch == obs_body.epoch
                        && lb.boot == obs_body.boot;
                    if !same {
                        d.finalize_stale(tx, now, emitted, &mut c)?;
                        return Ok(MOut::Ok(Value::Null));
                    }
                }
            }
            if now >= c.deadline_ms && slots_owned.iter().any(|s| s.is_none()) {
                c.state = CheckState::Expired;
                c.reason = "MONITOR_TIMEOUT".into();
                c.revision += 1;
                let (seq, _) = emit(
                    tx,
                    &d.emit_ctx(),
                    now,
                    "watchd",
                    "watchd",
                    "CheckFinalized",
                    check_value(&c),
                    vec![c.observation.hash.clone(), c.policy.clone()],
                    emitted,
                )?;
                Store::tx_put_entity(
                    tx,
                    "checks",
                    &c.id.clone(),
                    &jcs(&check_value(&c)).into_bytes(),
                    seq,
                    "checks",
                )?;
                d.bump(tx, "watch_checks_total", "", "EXPIRED", 1)?;
                return Ok(MOut::Ok(Value::Null));
            }
            // Aggregate.
            let settled: Vec<Result_> = slots_owned.iter().filter_map(|s| s.clone()).collect();
            let queue_depth = d.active_review_count(tx, None)?;
            let per_run = d.active_review_count(tx, Some(&run.id))?;
            let uncertain: Vec<Result_> = settled
                .iter()
                .filter(|r| r.verdict == Verdict::Uncertain)
                .cloned()
                .collect();
            let cand_basis = Basis {
                run: run.id.clone(),
                intent: aggregate::intent_digest(&c.intent),
                policy: c.policy.clone(),
                guard_epoch: run.guard_epoch,
                target_revision: c.intent.target_revision,
                max_total_minor: obs_body
                    .snapshot
                    .committed_minor
                    .saturating_add(obs_body.snapshot.reserved_minor)
                    .saturating_add(c.intent.cost_minor),
                findings: aggregate::findings_digest(&uncertain),
            };
            let cand_basis_digest = aggregate::basis_digest(&cand_basis);
            let existing = d.find_active_basis_review(tx, &run.id, &cand_basis_digest)?;
            let outcome = aggregate::aggregate(
                &slots_owned,
                &aggregate::QueueCtx {
                    depth: queue_depth,
                    per_run_open: per_run,
                    queue_capacity: pol.queue_capacity,
                    per_run_cap: pol.per_run_open_reviews,
                    existing_basis: existing.is_some(),
                },
            );
            // Supplied review consumption predicate (§2.2).
            let supplied = c.review.clone();
            let mut consume_review: Option<Review> = None;
            if let Some(rid) = &supplied {
                if let Some(rv) = d.load_review_tx(tx, rid)? {
                    let ok = rv.state == ReviewState::Accepted
                        && rv.accepted_until_ms.map(|a| now < a).unwrap_or(false)
                        && rv.basis.as_ref().map(|b| {
                            b.run == run.id
                                && b.intent == aggregate::intent_digest(&c.intent)
                                && b.policy == c.policy
                                && b.guard_epoch == run.guard_epoch
                                && b.target_revision == c.intent.target_revision
                                && cand_basis.max_total_minor <= b.max_total_minor
                                && b.findings == cand_basis.findings
                        }) == Some(true);
                    if ok {
                        consume_review = Some(rv);
                    }
                }
            }
            // An accepted review whose basis covers the uncertain findings
            // resolves them: the check clears instead of holding (§2.2).
            // Hard flags (Deny) and expiry are never overridden.
            let outcome =
                if consume_review.is_some() && matches!(outcome, aggregate::Outcome::Held { .. }) {
                    aggregate::Outcome::Clear
                } else {
                    outcome
                };
            // The finalized check carries its monitor results.
            c.results = settled.clone();
            d.apply_outcome(
                tx,
                now,
                emitted,
                &mut c,
                &run,
                &pol,
                &obs_sv,
                &obs_body,
                &settled,
                outcome,
                existing,
                consume_review,
                cand_basis,
            )?;
            Ok(MOut::Ok(Value::Null))
        });
        Ok(())
    }

    fn finalize_stale(
        &mut self,
        tx: &Transaction,
        now: u64,
        emitted: &mut Vec<String>,
        c: &mut Check,
    ) -> Result<(), Fault> {
        c.state = CheckState::Stale;
        c.reason = "STALE".into();
        c.revision += 1;
        let (seq, _) = emit(
            tx,
            &self.emit_ctx(),
            now,
            "watchd",
            "watchd",
            "CheckFinalized",
            check_value(c),
            vec![c.observation.hash.clone(), c.policy.clone()],
            emitted,
        )?;
        Store::tx_put_entity(
            tx,
            "checks",
            &c.id.clone(),
            &jcs(&check_value(c)).into_bytes(),
            seq,
            "checks",
        )?;
        self.bump(tx, "watch_checks_total", "", "STALE", 1)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_outcome(
        &mut self,
        tx: &Transaction,
        now: u64,
        emitted: &mut Vec<String>,
        c: &mut Check,
        run: &Run,
        pol: &Policy,
        _obs_sv: &Signed,
        obs_body: &ObservationBody,
        _settled: &[Result_],
        outcome: aggregate::Outcome,
        existing: Option<String>,
        consume_review: Option<Review>,
        cand_basis: Basis,
    ) -> Result<(), Fault> {
        match outcome {
            aggregate::Outcome::Deny(reason) => {
                c.state = CheckState::Deny;
                c.reason = reason;
            }
            aggregate::Outcome::Expired(reason) => {
                c.state = CheckState::Expired;
                c.reason = reason;
            }
            aggregate::Outcome::Held { reason, new_review } => {
                c.state = CheckState::Held;
                c.reason = reason.clone();
                if new_review {
                    let rid = aggregate::review_id(
                        &run.id,
                        Some(&aggregate::basis_digest(&cand_basis)),
                        None,
                        Some(&c.id),
                    );
                    let due = now.saturating_add(pol.review_ttl_ms);
                    let review = Review {
                        id: rid.clone(),
                        revision: 1,
                        run: run.id.clone(),
                        check: Some(c.id.clone()),
                        alert: None,
                        basis: Some(cand_basis.clone()),
                        kind: "blocking".into(),
                        state: ReviewState::Open,
                        level: Level::Warning,
                        created_seq: 0, // set after event seq known
                        due_ms: due,
                        owner: None,
                        lease_until_ms: None,
                        wake_ms: None,
                        accepted_until_ms: None,
                        reason: reason.clone(),
                        resolution: None,
                        resolved_by: None,
                    };
                    // created_seq is the event's own seq; emit with a
                    // provisional value then fix via two-phase: emit after
                    // computing seq = head+1.
                    let head = Store::tx_head(tx)?;
                    let mut review = review;
                    review.created_seq = head.seq + 1;
                    c.review = Some(rid.clone());
                    c.revision += 1;
                    let (cseq, _) = emit(
                        tx,
                        &self.emit_ctx(),
                        now,
                        "watchd",
                        "watchd",
                        "CheckFinalized",
                        check_value(c),
                        vec![c.observation.hash.clone(), c.policy.clone()],
                        emitted,
                    )?;
                    Store::tx_put_entity(
                        tx,
                        "checks",
                        &c.id.clone(),
                        &jcs(&check_value(c)).into_bytes(),
                        cseq,
                        "checks",
                    )?;
                    let (rseq, _) = emit(
                        tx,
                        &self.emit_ctx(),
                        now,
                        "watchd",
                        "watchd",
                        "ReviewOpened",
                        review_value(&review),
                        vec![],
                        emitted,
                    )?;
                    Store::tx_put_entity(
                        tx,
                        "reviews",
                        &rid,
                        &jcs(&review_value(&review)).into_bytes(),
                        rseq,
                        "reviews",
                    )?;
                    self.bump(tx, "watch_checks_total", "", "HELD", 1)?;
                    self.bump(tx, "watch_remainder_opened_total", "", "warning", 1)?;
                    return Ok(());
                }
                // existing basis → reference it
                if let Some(rid) = &existing {
                    c.review = Some(rid.clone());
                }
            }
            aggregate::Outcome::Clear => {
                c.state = CheckState::Clear;
                c.reason = "CLEAR".into();
                // Consume the supplied review first (event order), then the
                // clearance + CheckFinalized.
                let basis_digest = if let Some(rv) = &consume_review {
                    aggregate::basis_digest(rv.basis.as_ref().unwrap())
                } else {
                    aggregate::basis_digest(&cand_basis)
                };
                let issued = now;
                let expires = issued
                    .saturating_add(pol.clearance_ms)
                    .min(obs_body.cut_ms.saturating_add(pol.freshness_ms));
                let cl = Clearance {
                    tenant: self.cfg.tenant.clone(),
                    run: run.id.clone(),
                    runtime: run.runtime.clone(),
                    guard_epoch: run.guard_epoch,
                    boot: run.boot.clone(),
                    check: c.id.clone(),
                    intent: aggregate::intent_digest(&c.intent),
                    policy: c.policy.clone(),
                    observation: c.observation.clone(),
                    basis: basis_digest,
                    issued_ms: issued,
                    expires_ms: expires,
                    mode: run.mode.clone(),
                };
                let cl_env = crate::crypto::sign_envelope(
                    "clearance",
                    &clearance_body_value(&cl),
                    &self.cfg.signer_key_id,
                    &self.cfg.signer_key_epoch.to_string(),
                    &self.sk,
                );
                let cl_signed = signed(&cl_env)?;
                c.clearance = Some(cl_signed);
                c.revision += 1;
                if let Some(mut rv) = consume_review {
                    rv.state = ReviewState::Consumed;
                    rv.revision += 1;
                    let (rseq, rdig) = emit(
                        tx,
                        &self.emit_ctx(),
                        now,
                        "watchd",
                        "watchd",
                        "ReviewConsumed",
                        review_value(&rv),
                        vec![],
                        emitted,
                    )?;
                    Store::tx_put_entity(
                        tx,
                        "reviews",
                        &rv.id.clone(),
                        &jcs(&review_value(&rv)).into_bytes(),
                        rseq,
                        "reviews",
                    )?;
                    let _ = rdig;
                }
                let mut causes = vec![c.observation.hash.clone(), c.policy.clone()];
                // Include the just-emitted ReviewConsumed digest.
                if c.review.is_some() {
                    if let Some(last) = emitted.last() {
                        causes.push(last.clone());
                    }
                }
                let (seq, _) = emit(
                    tx,
                    &self.emit_ctx(),
                    now,
                    "watchd",
                    "watchd",
                    "CheckFinalized",
                    check_value(c),
                    causes,
                    emitted,
                )?;
                Store::tx_put_entity(
                    tx,
                    "checks",
                    &c.id.clone(),
                    &jcs(&check_value(c)).into_bytes(),
                    seq,
                    "checks",
                )?;
                self.bump(tx, "watch_checks_total", "", "CLEAR", 1)?;
                return Ok(());
            }
        }
        // Non-clear path: plain CheckFinalized.
        c.revision += 1;
        let (seq, _) = emit(
            tx,
            &self.emit_ctx(),
            now,
            "watchd",
            "watchd",
            "CheckFinalized",
            check_value(c),
            vec![c.observation.hash.clone(), c.policy.clone()],
            emitted,
        )?;
        Store::tx_put_entity(
            tx,
            "checks",
            &c.id.clone(),
            &jcs(&check_value(c)).into_bytes(),
            seq,
            "checks",
        )?;
        self.bump(tx, "watch_checks_total", "", c.state.as_str(), 1)?;
        Ok(())
    }

    pub fn active_review_count(&self, tx: &Transaction, run: Option<&str>) -> Result<u64, Fault> {
        let n: i64 = match run {
            Some(r) => tx
                .query_row(
                    "SELECT COUNT(*) FROM reviews WHERE run=?1 AND state IN ('OPEN','CLAIMED','DEFERRED','ACCEPTED')",
                    rusqlite::params![r],
                    |x| x.get(0),
                )
                .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?,
            None => tx
                .query_row(
                    "SELECT COUNT(*) FROM reviews WHERE state IN ('OPEN','CLAIMED','DEFERRED','ACCEPTED')",
                    [],
                    |x| x.get(0),
                )
                .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?,
        };
        Ok(n as u64)
    }

    pub fn find_active_basis_review(
        &self,
        tx: &Transaction,
        run: &str,
        basis_digest: &str,
    ) -> Result<Option<String>, Fault> {
        use rusqlite::OptionalExtension;
        tx.query_row(
            "SELECT r.id FROM reviews r WHERE r.run=?1 AND r.basis=?2 AND r.state IN ('OPEN','CLAIMED','DEFERRED','ACCEPTED') LIMIT 1",
            rusqlite::params![run, basis_digest],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))
    }

    // ---- window/trailing processing ----

    fn tick_windows(&mut self, now: u64) -> Result<(), Fault> {
        let run_ids: Vec<String> = {
            let tx = self.begin()?;
            let mut st = tx
                .prepare("SELECT id FROM runs WHERE state IN ('OPEN','PAUSED') ORDER BY id")
                .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
            let rows = st
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
            let mut v = Vec::new();
            for r in rows {
                v.push(r.map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?);
            }
            v
        };
        for rid in run_ids {
            let _ = self.process_windows(&rid, now);
        }
        Ok(())
    }

    /// First expected window boundary for a run: the first 10000-ms boundary
    /// at/after the RunOpened event's at_ms.
    pub fn run_opened_ms(&self, run_id: &str) -> Result<u64, Fault> {
        let n: Option<i64> = self
            .store
            .conn
            .query_row(
                "SELECT CAST(json_extract(a.body,'$.at_ms') AS INTEGER) FROM audit a
                 WHERE a.kind='RunOpened' AND json_extract(a.body,'$.value.id')=?1
                 ORDER BY a.seq LIMIT 1",
                rusqlite::params![run_id],
                |r| r.get(0),
            )
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        Ok(n.map(|x| x as u64).unwrap_or(0))
    }

    /// Emit TrailingEvaluated + DriftUpdated + alert events for every
    /// expected window due at `now` that has not been attempted.
    pub fn process_windows(&mut self, run_id: &str, now: u64) -> Result<(), Fault> {
        let opened = self.run_opened_ms(run_id)?;
        let first_boundary = opened.div_ceil(crate::WINDOW_MS) * crate::WINDOW_MS;
        // due when start + WINDOW_MS + 500 <= now
        let mut due: Vec<u64> = Vec::new();
        let mut start = first_boundary;
        while start.saturating_add(crate::WINDOW_MS + crate::WINDOW_DUE_MS) <= now {
            if !self.store.window_attempted(run_id, start)? {
                due.push(start);
            }
            start += crate::WINDOW_MS;
            if due.len() > 4096 {
                break;
            }
        }
        if due.is_empty() {
            return Ok(());
        }
        let _ = self.mutate(now, |d, tx, now, emitted| {
            for start in &due {
                d.process_one_window(tx, now, emitted, run_id, *start)?;
            }
            Ok(MOut::Ok(Value::Null))
        });
        Ok(())
    }

    fn process_one_window(
        &mut self,
        tx: &Transaction,
        now: u64,
        emitted: &mut Vec<String>,
        run_id: &str,
        start: u64,
    ) -> Result<(), Fault> {
        let Some(run) = self.load_run_tx(tx, run_id)? else {
            return Ok(());
        };
        if !(run.state == RunState::Open || run.state == RunState::Paused) {
            return Ok(());
        }
        let pol_v = Store::policy_get_on(tx, &run.policy)?
            .ok_or_else(|| Fault::new(Code::AuditUnavailable, "policy lost"))?;
        let pol_env = crate::json::parse(&pol_v, &crate::json::Limits::reply())
            .map_err(|_| Fault::new(Code::AuditUnavailable, "policy parse"))?;
        let pol_sv = signed(&pol_env)?;
        let pol = policy(&pol_sv.body)?;

        // Find supplied counts + the observation that carried them.
        let supplied: Option<([u64; 4], Ref)> = {
            let mut st = tx
                .prepare(
                    "SELECT o.digest,o.envelope FROM observations o
                     JOIN windows w ON w.run=o.run AND w.start_ms=?2
                     WHERE o.run=?1 AND w.counts IS NOT NULL
                     ORDER BY o.seq DESC LIMIT 1",
                )
                .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
            let rows = st
                .query_map(rusqlite::params![run_id, start as i64], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
                })
                .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
            let mut found = None;
            for r in rows {
                let (_dg, env) =
                    r.map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
                let v = crate::json::parse(&env, &crate::json::Limits::reply())
                    .map_err(|_| Fault::new(Code::AuditUnavailable, "obs parse"))?;
                let sv = signed(&v)?;
                let b = observation_body(&sv.body)?;
                if let Some(w) = &b.snapshot.window {
                    if w.start_ms == start {
                        found = Some((
                            w.counts,
                            Ref {
                                source: b.source.clone(),
                                epoch: b.epoch,
                                seq: b.seq,
                                hash: sv.digest.clone(),
                            },
                        ));
                    }
                }
            }
            found
        };
        // Also scan observations directly for the window (windows.counts may
        // be unset if the observation arrived but wasn't linked yet).
        let supplied = match supplied {
            Some(s) => Some(s),
            None => {
                let mut st = tx
                    .prepare(
                        "SELECT digest,envelope FROM observations WHERE run=?1 ORDER BY seq ASC",
                    )
                    .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
                let rows = st
                    .query_map(rusqlite::params![run_id], |r| {
                        Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
                    })
                    .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
                let mut found = None;
                for r in rows {
                    let (dg, env) =
                        r.map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
                    let v = crate::json::parse(&env, &crate::json::Limits::reply())
                        .map_err(|_| Fault::new(Code::AuditUnavailable, "obs parse"))?;
                    let sv = signed(&v)?;
                    let b = observation_body(&sv.body)?;
                    if let Some(w) = &b.snapshot.window {
                        if w.start_ms == start {
                            found = Some((
                                w.counts,
                                Ref {
                                    source: b.source.clone(),
                                    epoch: b.epoch,
                                    seq: b.seq,
                                    hash: dg,
                                },
                            ));
                        }
                    }
                }
                found
            }
        };

        // Latest known observation ref (for missing-window evidence).
        let latest_ref: Option<Ref> = if run.cursor.seq > 0 {
            let mut st = tx
                .prepare(
                    "SELECT digest,envelope FROM observations WHERE run=?1 ORDER BY seq DESC LIMIT 1",
                )
                .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
            let row = st
                .query_row(rusqlite::params![run_id], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
                })
                .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))
                .ok();
            row.and_then(|(dg, env)| {
                let v = crate::json::parse(&env, &crate::json::Limits::reply()).ok()?;
                let sv = signed(&v).ok()?;
                let b = observation_body(&sv.body).ok()?;
                Some(Ref {
                    source: b.source,
                    epoch: b.epoch,
                    seq: b.seq,
                    hash: dg,
                })
            })
        } else {
            None
        };

        // Compute the two trailing results deterministically.
        let mut results: Vec<Result_> = Vec::new();
        let trailing: Vec<&Monitor> = pol
            .monitors
            .iter()
            .filter(|m| m.mode == "trailing")
            .collect();
        let obs_ref_for_results = supplied.as_ref().map(|(_, r)| r.clone());
        for m in &trailing {
            let r = match &supplied {
                Some((counts, oref)) => {
                    // Build a synthetic observation body carrying this window.
                    let mut body = observation_body(&{
                        let env_bytes: Vec<u8> = tx
                            .query_row(
                                "SELECT envelope FROM observations WHERE digest=?1",
                                rusqlite::params![oref.hash],
                                |r| r.get(0),
                            )
                            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
                        crate::json::parse(&env_bytes, &crate::json::Limits::reply())
                            .map_err(|_| Fault::new(Code::AuditUnavailable, "obs parse"))?
                            .get("body")
                            .unwrap()
                            .clone()
                    })?;
                    body.snapshot.window = Some(Window {
                        start_ms: start,
                        counts: *counts,
                    });
                    let prior_drift = run.drift.clone();
                    crate::detect::evaluate(
                        m,
                        &pol,
                        &body,
                        Some(oref.clone()),
                        None,
                        if m.detector == Detector::Distribution {
                            Some(&prior_drift)
                        } else {
                            None
                        },
                    )
                }
                None => Result_ {
                    monitor: m.id.clone(),
                    detector: m.detector,
                    verdict: Verdict::Unavailable,
                    reason: "WINDOW_MISSING".into(),
                    score_bp: None,
                    evidence: latest_ref.clone().into_iter().collect(),
                },
            };
            results.push(r);
        }
        results.sort_by(|a, b| a.monitor.cmp(&b.monitor));

        // Mark attempted (with supplied counts if any).
        let counts_bytes = supplied.as_ref().map(|(c, _)| {
            jcs(&crate::schema::window_value(&Window {
                start_ms: start,
                counts: *c,
            }))
            .into_bytes()
        });
        Store::tx_window_put(tx, run_id, start, counts_bytes.as_deref())?;
        // Mark attempted via counts NULL marker even when missing: record a
        // row regardless.
        if counts_bytes.is_none() {
            Store::tx_window_put(tx, run_id, start, None)?;
        }

        // TrailingEvaluated event.
        let te = Value::obj(vec![
            ("run", Value::str(run_id)),
            ("window_start_ms", Value::ustr(&start.to_string())),
            (
                "observation",
                obs_ref_for_results
                    .clone()
                    .map(|r| ref_value(&r))
                    .unwrap_or(Value::Null),
            ),
            (
                "results",
                Value::Arr(results.iter().map(result_value).collect()),
            ),
        ]);
        emit(
            tx,
            &self.emit_ctx(),
            now,
            "watchd",
            "watchd",
            "TrailingEvaluated",
            te,
            vec![],
            emitted,
        )?;

        // Drift step for this window slot.
        let input = match &supplied {
            Some((counts, _)) => {
                let samples: u64 = counts.iter().sum();
                let score = crate::detect::tvd_bp(&pol.baseline.counts, counts).unwrap_or(0);
                crate::drift::WindowInput::Complete { samples, score }
            }
            None => crate::drift::WindowInput::Missing,
        };
        let prior_drift = run.drift.clone();
        let mut new_run = run.clone();
        new_run.drift = crate::drift::step(&prior_drift, start, input, &pol);
        if new_run.drift != prior_drift {
            new_run.revision += 1;
            let (seq, _) = emit(
                tx,
                &self.emit_ctx(),
                now,
                "watchd",
                "watchd",
                "DriftUpdated",
                run_value(&new_run),
                vec![],
                emitted,
            )?;
            Store::tx_put_entity(
                tx,
                "runs",
                run_id,
                &jcs(&run_value(&new_run)).into_bytes(),
                seq,
                "runs",
            )?;
        }

        // Alert episodes.
        for r in &results {
            match r.verdict {
                Verdict::Flag => {
                    let level = match r.detector {
                        Detector::Distribution => Level::Critical,
                        _ => Level::Warning,
                    };
                    self.alert_episode(
                        tx,
                        now,
                        emitted,
                        &new_run,
                        &pol,
                        r,
                        obs_ref_for_results.clone().or(latest_ref.clone()),
                        level,
                    )?;
                }
                _ => {
                    // condition-clear resolution: rate monitor clears when a
                    // supplied window produces a non-flag verdict; the
                    // distribution alert resolves only when drift leaves DRIFT.
                    if r.detector == Detector::Rate && supplied.is_some() {
                        self.resolve_episode_if_active(
                            tx,
                            now,
                            emitted,
                            run_id,
                            &r.monitor,
                            &pol.baseline.id,
                        )?;
                    }
                }
            }
        }
        // Distribution resolves when drift exits DRIFT.
        if prior_drift.state == DriftState::Drift && new_run.drift.state != DriftState::Drift {
            if let Some(m) = pol
                .monitors
                .iter()
                .find(|m| m.detector == Detector::Distribution)
            {
                self.resolve_episode_if_active(tx, now, emitted, run_id, &m.id, &pol.baseline.id)?;
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn alert_episode(
        &mut self,
        tx: &Transaction,
        now: u64,
        emitted: &mut Vec<String>,
        run: &Run,
        pol: &Policy,
        r: &Result_,
        ev: Option<Ref>,
        level: Level,
    ) -> Result<(), Fault> {
        let Some(first) = ev else { return Ok(()) };
        let ek = aggregate::episode_key(&run.id, &r.monitor, &pol.baseline.id);
        let existing: Option<String> = {
            use rusqlite::OptionalExtension;
            tx.query_row(
                "SELECT id FROM alerts WHERE episode_key=?1 AND state IN ('OPEN','ACKNOWLEDGED')",
                rusqlite::params![ek],
                |x| x.get(0),
            )
            .optional()
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?
        };
        if let Some(aid) = existing {
            let mut a = self.load_alert_tx(tx, &aid)?.unwrap();
            a.occurrences += 1;
            a.last = first.clone();
            a.revision += 1;
            let (seq, _) = emit(
                tx,
                &self.emit_ctx(),
                now,
                "watchd",
                "watchd",
                "AlertUpdated",
                alert_value(&a),
                vec![],
                emitted,
            )?;
            Store::tx_put_entity(
                tx,
                "alerts",
                &aid,
                &jcs(&alert_value(&a)).into_bytes(),
                seq,
                "alerts",
            )?;
            return Ok(());
        }
        let aid = aggregate::alert_id(&run.id, &r.monitor, &pol.baseline.id, &first);
        let _head = Store::tx_head(tx)?;
        let a = Alert {
            id: aid.clone(),
            revision: 1,
            run: run.id.clone(),
            monitor: r.monitor.clone(),
            baseline: pol.baseline.id.clone(),
            state: AlertState::Open,
            level,
            first: first.clone(),
            last: first.clone(),
            occurrences: 1,
            review: None,
            reason: r.reason.clone(),
            resolved_by: None,
        };
        let (seq, _) = emit(
            tx,
            &self.emit_ctx(),
            now,
            "watchd",
            "watchd",
            "AlertOpened",
            alert_value(&a),
            vec![],
            emitted,
        )?;
        Store::tx_put_entity(
            tx,
            "alerts",
            &aid,
            &jcs(&alert_value(&a)).into_bytes(),
            seq,
            "alerts",
        )?;
        self.bump(tx, "watch_drift_episodes_total", r.detector.as_str(), "", 1)?;
        // Trailing review card for the episode.
        let rid = aggregate::review_id(&run.id, None, Some(&aid), None);
        let head2 = Store::tx_head(tx)?;
        let rv = Review {
            id: rid.clone(),
            revision: 1,
            run: run.id.clone(),
            check: None,
            alert: Some(aid.clone()),
            basis: None,
            kind: "trailing".into(),
            state: ReviewState::Open,
            level,
            created_seq: head2.seq + 1,
            due_ms: now.saturating_add(pol.review_ttl_ms),
            owner: None,
            lease_until_ms: None,
            wake_ms: None,
            accepted_until_ms: None,
            reason: r.reason.clone(),
            resolution: None,
            resolved_by: None,
        };
        let (rseq, _) = emit(
            tx,
            &self.emit_ctx(),
            now,
            "watchd",
            "watchd",
            "ReviewOpened",
            review_value(&rv),
            vec![],
            emitted,
        )?;
        Store::tx_put_entity(
            tx,
            "reviews",
            &rid,
            &jcs(&review_value(&rv)).into_bytes(),
            rseq,
            "reviews",
        )?;
        // Link review into the alert.
        let mut a2 = a;
        a2.review = Some(rid);
        a2.revision += 1;
        let (seq2, _) = emit(
            tx,
            &self.emit_ctx(),
            now,
            "watchd",
            "watchd",
            "AlertUpdated",
            alert_value(&a2),
            vec![],
            emitted,
        )?;
        Store::tx_put_entity(
            tx,
            "alerts",
            &aid,
            &jcs(&alert_value(&a2)).into_bytes(),
            seq2,
            "alerts",
        )?;
        // local_notice outbox entry for the alert.
        let notice = jcs(&Value::obj(vec![
            ("kind", Value::str("alert")),
            ("alert", Value::str(&aid)),
            ("run", Value::str(&run.id)),
            ("reason", Value::str(&r.reason)),
        ]));
        Store::tx_outbox_put(tx, "local_notice", &aid, now, notice.as_bytes())?;
        Ok(())
    }

    fn resolve_episode_if_active(
        &mut self,
        tx: &Transaction,
        now: u64,
        emitted: &mut Vec<String>,
        run_id: &str,
        monitor_id: &str,
        baseline: &str,
    ) -> Result<(), Fault> {
        let ek = aggregate::episode_key(run_id, monitor_id, baseline);
        let aid: Option<String> = {
            use rusqlite::OptionalExtension;
            tx.query_row(
                "SELECT id FROM alerts WHERE episode_key=?1 AND state IN ('OPEN','ACKNOWLEDGED')",
                rusqlite::params![ek],
                |x| x.get(0),
            )
            .optional()
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?
        };
        if let Some(aid) = aid {
            let mut a = self.load_alert_tx(tx, &aid)?.unwrap();
            a.state = AlertState::Resolved;
            a.resolved_by = Some("watchd".into());
            a.revision += 1;
            let (seq, _) = emit(
                tx,
                &self.emit_ctx(),
                now,
                "watchd",
                "watchd",
                "AlertResolved",
                alert_value(&a),
                vec![],
                emitted,
            )?;
            Store::tx_put_entity(
                tx,
                "alerts",
                &aid,
                &jcs(&alert_value(&a)).into_bytes(),
                seq,
                "alerts",
            )?;
        }
        Ok(())
    }

    pub fn load_alert_tx(&self, tx: &Transaction, id: &str) -> Result<Option<Alert>, Fault> {
        use rusqlite::OptionalExtension;
        let body: Option<Vec<u8>> = tx
            .query_row(
                "SELECT body FROM alerts WHERE id=?1",
                rusqlite::params![id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        match body {
            Some(b) => {
                let v = crate::json::parse(&b, &crate::json::Limits::reply())
                    .map_err(|_| Fault::new(Code::AuditUnavailable, "alert body parse"))?;
                Ok(Some(alert(&v)?))
            }
            None => Ok(None),
        }
    }

    /// Load a run's bound policy body.
    pub fn policy_for_run(&self, run_id: &str) -> Result<Option<Policy>, Fault> {
        let Some(run) = self.load_run(run_id)? else {
            return Ok(None);
        };
        match self.store.policy_get(&run.policy)? {
            Some(b) => {
                let v = crate::json::parse(&b, &crate::json::Limits::reply())
                    .map_err(|_| Fault::new(Code::AuditUnavailable, "policy parse"))?;
                let sv = signed(&v)?;
                Ok(Some(policy(&sv.body)?))
            }
            None => Ok(None),
        }
    }

    pub fn tick_outbox(&mut self, now: u64) -> Result<(), Fault> {
        let items = self.store.outbox_due(now)?;
        if items.is_empty() {
            return Ok(());
        }
        let _ = self.mutate(now, |d, tx, _now, _emitted| {
            for (id, kind, subject, body) in &items {
                match kind.as_str() {
                    "local_notice" => {
                        d.notices.push(String::from_utf8_lossy(body).to_string());
                        Store::tx_outbox_delete(tx, *id)?;
                    }
                    "monitor_job" => {
                        let v = crate::json::parse(body, &crate::json::Limits::request())
                            .map_err(|_| Fault::new(Code::AuditUnavailable, "job parse"))?;
                        let mid = v
                            .get("monitor")
                            .and_then(|m| m.get("id"))
                            .and_then(|x| x.as_str())
                            .unwrap_or("?")
                            .to_string();
                        if d.workers.dispatch(subject, &mid, &v) {
                            Store::tx_outbox_delete(tx, *id)?;
                        }
                    }
                    "expiry" => {
                        Store::tx_outbox_delete(tx, *id)?;
                    }
                    _ => {
                        Store::tx_outbox_delete(tx, *id)?;
                    }
                }
            }
            Ok(MOut::Ok(Value::Null))
        });
        Ok(())
    }

    fn tick_monitor_replies(&mut self, now: u64) {
        for comp in self.workers.drain() {
            let _ = self.apply_monitor_reply(&comp, now);
        }
    }

    /// One worker reply: verify by recomputation, store the slot, finalize
    /// the check when all required slots are settled.
    fn apply_monitor_reply(
        &mut self,
        comp: &crate::monitor::Completion,
        now: u64,
    ) -> Result<(), Fault> {
        // job id: job_{check}_{monitor}; resolve the check by testing each
        // known slot suffix so monitor ids containing '_' stay unambiguous.
        let job = comp.job.strip_prefix("job_").unwrap_or(&comp.job);
        let mut resolved: Option<(String, String, u64, String)> = None;
        {
            let mut st = self
                .store
                .conn
                .prepare("SELECT check_id,monitor_id,deadline_ms,state FROM monitor_slots")
                .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
            let rows = st
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, String>(3)?,
                    ))
                })
                .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
            for r in rows {
                let (cid, mid, dl, stt) =
                    r.map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
                if job == format!("{cid}_{mid}") {
                    resolved = Some((cid, mid, dl as u64, stt));
                    break;
                }
            }
        }
        let Some((check_id, _mid, dl, st)) = resolved else {
            return Ok(());
        };
        let Some(c) = self.load_check(&check_id)? else {
            return Ok(());
        };
        if c.state != CheckState::Evaluating {
            return Ok(()); // late evidence only
        }
        if st == "done" {
            return Ok(());
        }
        if now >= dl {
            // Late — deadline already passed; evidence cannot settle the slot.
            let _ = self.mutate(now, |_d, tx, _n, _e| {
                Store::tx_slot_put(tx, &check_id, &comp.monitor, dl, "timeout", None)?;
                Ok(MOut::Ok(Value::Null))
            });
            return self.maybe_finalize_check(&check_id, now);
        }
        // Coordinator recomputation (§3.4/§7.3): mismatch faults the host.
        let result_bytes = match &comp.result {
            Ok(r) => jcs(&result_value(r)).into_bytes(),
            Err(e) => {
                // Worker-side schema failure counts as an unavailable slot.
                let _ = e;
                return Ok(());
            }
        };
        let expected = self.recompute(&c, &comp.monitor)?;
        let mismatch = self.inject.worker_mismatch
            || match (&comp.result, &expected) {
                (Ok(a), Some(b)) => *a != *b,
                (Ok(_), None) => false,
                (Err(_), _) => false,
            };
        if mismatch {
            self.inject.worker_mismatch = false;
            // Host fault: no unchecked worker Result may reach signing.
            let _ = self.mutate(now, |d, tx, now, emitted| {
                d.host.state = HostState::Faulted;
                d.host.reason = Some("MONITOR_RESULT_MISMATCH".into());
                emit(
                    tx,
                    &d.emit_ctx(),
                    now,
                    "watchd",
                    "watchd",
                    "HostFaulted",
                    host_value(&d.host),
                    vec![],
                    emitted,
                )?;
                Ok(MOut::Ok(Value::Null))
            });
            return Ok(());
        }
        let _ = self.mutate(now, |_d, tx, _n, _e| {
            Store::tx_slot_put(
                tx,
                &check_id,
                &comp.monitor,
                dl,
                "done",
                Some(&result_bytes),
            )?;
            Ok(MOut::Ok(Value::Null))
        });
        self.maybe_finalize_check(&check_id, now)
    }

    /// Recompute a required slot's expected Result for worker integrity.
    fn recompute(&self, c: &Check, monitor_id: &str) -> Result<Option<Result_>, Fault> {
        let Some(pol_bytes) = self.store.policy_get(&c.policy)? else {
            return Ok(None);
        };
        let pol_env = crate::json::parse(&pol_bytes, &crate::json::Limits::reply())
            .map_err(|_| Fault::new(Code::AuditUnavailable, "policy parse"))?;
        let pol_sv = signed(&pol_env)?;
        let pol = policy(&pol_sv.body)?;
        let Some((_sv, body, _)) = self.observation_by_ref(&c.observation)? else {
            return Ok(None);
        };
        let Some(m) = pol.monitors.iter().find(|m| m.id == monitor_id) else {
            return Ok(None);
        };
        Ok(Some(crate::detect::evaluate(
            m,
            &pol,
            &body,
            Some(c.observation.clone()),
            Some(&c.intent),
            None,
        )))
    }

    /// Dispatch monitor jobs for a newly created check (post-commit).
    pub fn dispatch_check_jobs(&mut self, c: &Check, run_policy: &Policy, obs_env: &Value) {
        let required: Vec<&Monitor> = run_policy
            .monitors
            .iter()
            .filter(|m| m.mode == "blocking" && m.required)
            .collect();
        for m in required {
            let job = Value::obj(vec![
                ("v", Value::num(1)),
                ("job", Value::str(&format!("job_{}_{}", c.id, m.id))),
                ("monitor", monitor_value(m)),
                ("policy", policy_value(run_policy)),
                ("observation", obs_env.clone()),
                ("intent", intent_value(&c.intent)),
                ("drift", Value::Null),
                (
                    "deadline_ms",
                    Value::ustr(&(c.created_ms + m.deadline_ms).to_string()),
                ),
            ]);
            let job_id = format!("job_{}_{}", c.id, m.id);
            self.workers.dispatch(&job_id, &m.id, &job);
        }
    }

    /// Next due instant across all timer classes, for the event loop's sleep.
    pub fn next_due(&self) -> Option<u64> {
        let mut best: Option<u64> = None;
        let mut consider = |t: Option<u64>| {
            if let Some(t) = t {
                best = Some(best.map(|b: u64| b.min(t)).unwrap_or(t));
            }
        };
        let conn = &self.store.conn;
        let q = |sql: &str| -> Option<u64> {
            conn.query_row(sql, [], |r| r.get::<_, Option<i64>>(0))
                .ok()
                .flatten()
                .map(|x| x as u64)
        };
        consider(q(
            "SELECT MIN(deadline_ms) FROM checks WHERE state='EVALUATING'",
        ));
        consider(q(
            "SELECT MIN(due_ms) FROM reviews WHERE state IN ('OPEN','CLAIMED','DEFERRED','ACCEPTED')",
        ));
        consider(q(
            "SELECT MIN(lease_ms) FROM reviews WHERE state='CLAIMED' AND lease_ms IS NOT NULL",
        ));
        consider(q("SELECT MIN(due_ms) FROM outbox"));
        consider(q(
            "SELECT MIN(CAST(json_extract(body,'$.wake_ms') AS INTEGER)) FROM reviews WHERE state='DEFERRED'",
        ));
        consider(q(
            "SELECT MIN(CAST(json_extract(body,'$.accepted_until_ms') AS INTEGER)) FROM reviews WHERE state='ACCEPTED'",
        ));
        best
    }
}

const ACTIVE_REVIEW_STATES: &[&str] = &["OPEN", "CLAIMED", "DEFERRED", "ACCEPTED"];
