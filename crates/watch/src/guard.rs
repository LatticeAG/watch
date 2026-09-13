//! §7.2 certified-runtime dispatch guard — the runtime-side validation
//! that turns a Watch clearance into an allowed inert fixture effect.
//! This is the conformance guard: it enforces signature/domain/tenant/
//! runtime/run/epoch/boot/policy/intent/observation/mode/expiry and the
//! runtime's durable consume-once record. It never treats CLEAR as
//! authorization; the runtime's own authority/quota checks are independent.

use crate::crypto::b64u_decode;
use crate::fault::{Code, Fault};
use crate::schema::*;
use rusqlite::Connection;

pub struct Guard {
    /// Runtime's own durable store (separate from watch.db).
    conn: std::cell::RefCell<Connection>,
    pub runtime: String,
    pub tenant: String,
    pub trust: Trust,
    /// Independent runtime-side authorization decisions (test hook).
    pub authority_ok: bool,
    /// Runtime-owned quota ledger: (tenant,run) → committed_minor.
    pub cap_minor: u64,
}

/// One dispatch attempt's outcome.
pub struct GuardOutcome {
    pub dispatched: bool,
    pub code: Option<Code>,
}

impl Guard {
    pub fn new_in_memory(runtime: &str, tenant: &str, trust: Trust, cap_minor: u64) -> Guard {
        let conn = std::cell::RefCell::new(Connection::open_in_memory().expect("guard db"));
        conn.borrow().execute_batch(
            "CREATE TABLE consumed(tenant TEXT, run TEXT, guard_epoch INTEGER, check_id TEXT, PRIMARY KEY(tenant,run,guard_epoch,check_id)) STRICT;
             CREATE TABLE dispatched(tenant TEXT, run TEXT, action TEXT, UNIQUE(tenant,run,action)) STRICT;
             CREATE TABLE records(record TEXT PRIMARY KEY, value TEXT, revision INTEGER) STRICT;
             CREATE TABLE reservations(run TEXT, action TEXT, cost INTEGER, UNIQUE(run,action)) STRICT;",
        )
        .expect("guard schema");
        Guard {
            conn,
            runtime: runtime.to_string(),
            tenant: tenant.to_string(),
            trust,
            authority_ok: true,
            cap_minor,
        }
    }

    /// §7.2 step 5-7: validate the signed clearance, recheck independent
    /// authority/quota, then atomically consume + declare. Returns the
    /// dispatch decision (dispatched=true means the effect was declared).
    pub fn dispatch(
        &self,
        clearance_env: &crate::json::Value,
        run: &Run,
        check_intent: &Intent,
        now: u64,
        target_revision: u64,
        cost_minor: u64,
    ) -> Result<GuardOutcome, Fault> {
        let no = |c: Code| {
            Ok(GuardOutcome {
                dispatched: false,
                code: Some(c),
            })
        };
        let sv = match signed(clearance_env) {
            Ok(s) => s,
            Err(_) => return no(Code::SignatureInvalid),
        };
        let cb = match clearance_body(&sv.body) {
            Ok(b) => b,
            Err(_) => return no(Code::SignatureInvalid),
        };
        if cb.tenant != self.tenant || cb.runtime != self.runtime {
            return no(Code::Forbidden);
        }
        if cb.mode != "GUARDED" {
            return no(Code::Forbidden);
        }
        // Verify the Watch signer pin for tag "clearance".
        let Some(pin) = self.trust.keys.iter().find(|k| {
            k.id == sv.key_id
                && k.live
                && !k.compromised
                && k.tags.iter().any(|t| t == "clearance")
                && k.subjects.contains(&self.tenant)
                && sv.key_epoch >= k.from_epoch
                && k.through_epoch.map(|t| sv.key_epoch <= t).unwrap_or(true)
        }) else {
            return no(Code::Forbidden);
        };
        let Some(b) = b64u_decode(&pin.public_key) else {
            return no(Code::Forbidden);
        };
        let Ok(pk) = <[u8; 32]>::try_from(b.as_slice()) else {
            return no(Code::Forbidden);
        };
        if !crate::crypto::verify_envelope(
            "clearance",
            &sv.body,
            &sv.digest,
            &sv.key_id,
            &sv.key_epoch.to_string(),
            &sv.signature,
            &pk,
        ) {
            return no(Code::Forbidden);
        }
        // Bindings: run, guard epoch, boot, policy, intent, observation.
        if cb.run != run.id
            || cb.guard_epoch != run.guard_epoch
            || cb.boot != run.boot
            || cb.policy != run.policy
            || cb.intent != crate::aggregate::intent_digest(check_intent)
        {
            return no(Code::Forbidden);
        }
        // Half-open expiry: now < expires_ms required (equality invalid).
        if now >= cb.expires_ms || now < cb.issued_ms {
            return no(Code::LeaseExpired);
        }
        // Independent runtime authority/target/quota checks.
        if !self.authority_ok {
            return no(Code::Forbidden);
        }
        if target_revision != check_intent.target_revision {
            return no(Code::TargetStale);
        }
        // Consume-once + dispatch record, under the runtime's own lock.
        use rusqlite::TransactionBehavior;
        let mut conn_ref = self.conn.borrow_mut();
        let tx = conn_ref
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        let consumed: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM consumed WHERE tenant=?1 AND run=?2 AND guard_epoch=?3 AND check_id=?4",
                rusqlite::params![self.tenant, cb.run, cb.guard_epoch as i64, cb.check],
                |r| r.get(0),
            )
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        if consumed > 0 {
            let _ = tx.rollback();
            return no(Code::StateConflict);
        }
        let prior: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM dispatched WHERE tenant=?1 AND run=?2 AND action=?3",
                rusqlite::params![self.tenant, cb.run, check_intent.action],
                |r| r.get(0),
            )
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        if prior > 0 {
            let _ = tx.rollback();
            return no(Code::StateConflict);
        }
        // Runtime-side quota: committed + this cost ≤ cap.
        let committed: i64 = tx
            .query_row(
                "SELECT COALESCE(SUM(cost),0) FROM reservations WHERE run=?1",
                rusqlite::params![cb.run],
                |r| r.get(0),
            )
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        if (committed as u64) + cost_minor > self.cap_minor {
            let _ = tx.rollback();
            return no(Code::Forbidden);
        }
        tx.execute(
            "INSERT INTO reservations(run,action,cost) VALUES(?1,?2,?3)",
            rusqlite::params![cb.run, check_intent.action, cost_minor as i64],
        )
        .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        tx.execute(
            "INSERT INTO consumed(tenant,run,guard_epoch,check_id) VALUES(?1,?2,?3,?4)",
            rusqlite::params![self.tenant, cb.run, cb.guard_epoch as i64, cb.check],
        )
        .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        tx.execute(
            "INSERT INTO dispatched(tenant,run,action) VALUES(?1,?2,?3)",
            rusqlite::params![self.tenant, cb.run, check_intent.action],
        )
        .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        tx.commit()
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        Ok(GuardOutcome {
            dispatched: true,
            code: None,
        })
    }
}
