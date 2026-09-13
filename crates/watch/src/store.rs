//! SQLite authority (§6.1): WAL, synchronous=FULL, single writer, strict
//! schema, audit chain, projections, history, idempotency, objects, outbox.

use rusqlite::{params, Connection, OptionalExtension};

use crate::fault::{Code, Fault};
use crate::json::Value;
use crate::schema::{empty_head, Head};

/// Outbox row: (id, kind, subject, body).
pub type OutboxRow = (i64, String, String, Vec<u8>);
/// Monitor-slot row: (monitor_id, deadline_ms, state, result).
pub type SlotRow = (String, u64, String, Option<Vec<u8>>);
/// Events page: (rows, next_after).
pub type EventsPage = (Vec<(u64, Vec<u8>)>, Option<u64>);

const SCHEMA: &str = r#"
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, value BLOB NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY, hash TEXT NOT NULL UNIQUE, prev TEXT NOT NULL, epoch INTEGER NOT NULL, kind TEXT NOT NULL, body BLOB NOT NULL, envelope BLOB NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS policies(digest TEXT PRIMARY KEY, generation INTEGER NOT NULL UNIQUE, body BLOB NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, revision INTEGER NOT NULL, state TEXT NOT NULL, source TEXT NOT NULL, epoch INTEGER NOT NULL, body BLOB NOT NULL, changed_seq INTEGER NOT NULL REFERENCES audit(seq)) STRICT;
CREATE TABLE IF NOT EXISTS observations(run TEXT NOT NULL REFERENCES runs(id), source TEXT NOT NULL, epoch INTEGER NOT NULL, seq INTEGER NOT NULL, digest TEXT NOT NULL UNIQUE, envelope BLOB NOT NULL, PRIMARY KEY(source,epoch,run,seq)) STRICT;
CREATE TABLE IF NOT EXISTS actions(run TEXT NOT NULL REFERENCES runs(id), action TEXT NOT NULL, intent_digest TEXT NOT NULL, rejected INTEGER NOT NULL CHECK(rejected IN (0,1)), PRIMARY KEY(run,action)) STRICT;
CREATE TABLE IF NOT EXISTS checks(id TEXT PRIMARY KEY, run TEXT NOT NULL REFERENCES runs(id), state TEXT NOT NULL, revision INTEGER NOT NULL, deadline_ms INTEGER NOT NULL, body BLOB NOT NULL, changed_seq INTEGER NOT NULL REFERENCES audit(seq)) STRICT;
CREATE TABLE IF NOT EXISTS reviews(id TEXT PRIMARY KEY, run TEXT NOT NULL REFERENCES runs(id), basis TEXT, state TEXT NOT NULL, revision INTEGER NOT NULL, due_ms INTEGER NOT NULL, lease_ms INTEGER, body BLOB NOT NULL, changed_seq INTEGER NOT NULL REFERENCES audit(seq)) STRICT;
CREATE TABLE IF NOT EXISTS alerts(id TEXT PRIMARY KEY, run TEXT NOT NULL REFERENCES runs(id), episode_key TEXT NOT NULL, state TEXT NOT NULL, body BLOB NOT NULL, changed_seq INTEGER NOT NULL REFERENCES audit(seq)) STRICT;
CREATE TABLE IF NOT EXISTS effects(digest TEXT PRIMARY KEY, run TEXT NOT NULL REFERENCES runs(id), action TEXT NOT NULL, predecessor TEXT UNIQUE, state TEXT NOT NULL, envelope BLOB NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS idempotency(principal TEXT NOT NULL, request TEXT NOT NULL, method TEXT NOT NULL, params_hash TEXT NOT NULL, reply BLOB NOT NULL, PRIMARY KEY(principal,request)) STRICT;
CREATE TABLE IF NOT EXISTS evaluations(id TEXT PRIMARY KEY, input_digest TEXT NOT NULL UNIQUE, output BLOB NOT NULL, changed_seq INTEGER NOT NULL REFERENCES audit(seq)) STRICT;
CREATE TABLE IF NOT EXISTS objects(digest TEXT PRIMARY KEY, kind TEXT NOT NULL, bytes INTEGER NOT NULL, state TEXT NOT NULL, expires_utc TEXT NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS outbox(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, subject TEXT NOT NULL, due_ms INTEGER NOT NULL, attempts INTEGER NOT NULL, body BLOB NOT NULL, UNIQUE(kind,subject)) STRICT;
CREATE TABLE IF NOT EXISTS history(entity TEXT NOT NULL, id TEXT NOT NULL, seq INTEGER NOT NULL REFERENCES audit(seq), body BLOB NOT NULL, PRIMARY KEY(entity,id,seq)) STRICT;
CREATE TABLE IF NOT EXISTS monitor_slots(check_id TEXT NOT NULL, monitor_id TEXT NOT NULL, deadline_ms INTEGER NOT NULL, state TEXT NOT NULL, result BLOB, PRIMARY KEY(check_id,monitor_id)) STRICT;
CREATE TABLE IF NOT EXISTS windows(run TEXT NOT NULL, start_ms INTEGER NOT NULL, counts BLOB, PRIMARY KEY(run,start_ms)) STRICT;
CREATE INDEX IF NOT EXISTS checks_due ON checks(state,deadline_ms);
CREATE INDEX IF NOT EXISTS checks_run ON checks(run,state);
CREATE INDEX IF NOT EXISTS reviews_due ON reviews(state,due_ms);
CREATE INDEX IF NOT EXISTS reviews_lease ON reviews(state,lease_ms);
CREATE INDEX IF NOT EXISTS reviews_queue ON reviews(state,changed_seq,run);
CREATE UNIQUE INDEX IF NOT EXISTS review_active_basis ON reviews(run,basis) WHERE basis IS NOT NULL AND state IN ('OPEN','CLAIMED','DEFERRED','ACCEPTED');
CREATE UNIQUE INDEX IF NOT EXISTS alert_active_episode ON alerts(episode_key) WHERE state IN ('OPEN','ACKNOWLEDGED');
CREATE INDEX IF NOT EXISTS outbox_due ON outbox(due_ms,id);
CREATE INDEX IF NOT EXISTS history_cut ON history(entity,seq,id);
CREATE INDEX IF NOT EXISTS effects_action ON effects(run,action);
CREATE UNIQUE INDEX IF NOT EXISTS effect_root ON effects(run,action) WHERE predecessor IS NULL;
"#;

/// The store. All mutations run under BEGIN IMMEDIATE in one transaction.
pub struct Store {
    pub conn: Connection,
}

fn ferr(e: rusqlite::Error) -> Fault {
    Fault::new(Code::AuditUnavailable, &format!("sqlite: {e}"))
}

impl Store {
    pub fn open(path: &std::path::Path) -> Result<Store, Fault> {
        let conn = Connection::open(path).map_err(ferr)?;
        conn.execute_batch(SCHEMA).map_err(ferr)?;
        let uv: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(ferr)?;
        if uv != 1 && uv != 0 {
            return Err(Fault::new(
                Code::MigrationRequired,
                "store user_version ahead",
            ));
        }
        if uv == 0 {
            conn.execute_batch("PRAGMA user_version=1").map_err(ferr)?;
        }
        Ok(Store { conn })
    }

    pub fn open_memory() -> Result<Store, Fault> {
        let conn = Connection::open_in_memory().map_err(ferr)?;
        conn.execute_batch(SCHEMA).map_err(ferr)?;
        conn.execute_batch("PRAGMA user_version=1").map_err(ferr)?;
        Ok(Store { conn })
    }

    // ---- meta ----
    pub fn meta_get(&self, k: &str) -> Result<Option<String>, Fault> {
        self.conn
            .query_row("SELECT value FROM meta WHERE k=?1", params![k], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .optional()
            .map_err(ferr)
            .map(|o| o.map(|b| String::from_utf8_lossy(&b).to_string()))
    }
    pub fn meta_set(&self, k: &str, v: &str) -> Result<(), Fault> {
        self.conn
            .execute(
                "INSERT INTO meta(k,value) VALUES(?1,?2) ON CONFLICT(k) DO UPDATE SET value=?2",
                params![k, v.as_bytes()],
            )
            .map_err(ferr)?;
        Ok(())
    }

    /// meta inside a transaction.
    pub fn tx_meta_set(tx: &rusqlite::Transaction, k: &str, v: &str) -> Result<(), Fault> {
        tx.execute(
            "INSERT INTO meta(k,value) VALUES(?1,?2) ON CONFLICT(k) DO UPDATE SET value=?2",
            params![k, v.as_bytes()],
        )
        .map_err(ferr)?;
        Ok(())
    }

    // ---- audit head ----
    pub fn head(&self) -> Result<Head, Fault> {
        Self::head_on(&self.conn)
    }
    pub fn head_on(conn: &Connection) -> Result<Head, Fault> {
        let row = conn
            .query_row(
                "SELECT seq,hash FROM audit ORDER BY seq DESC LIMIT 1",
                [],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(ferr)?;
        Ok(match row {
            Some((s, h)) => Head {
                seq: s as u64,
                hash: h,
            },
            None => empty_head(),
        })
    }
    pub fn tx_head(tx: &rusqlite::Transaction) -> Result<Head, Fault> {
        let row = tx
            .query_row(
                "SELECT seq,hash FROM audit ORDER BY seq DESC LIMIT 1",
                [],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(ferr)?;
        Ok(match row {
            Some((s, h)) => Head {
                seq: s as u64,
                hash: h,
            },
            None => empty_head(),
        })
    }

    /// Does a digest name a durable local commitment (audit/policies/
    /// observations/effects/evaluations)?
    pub fn tx_known_commitment(tx: &rusqlite::Transaction, digest: &str) -> Result<bool, Fault> {
        let mut found = false;
        for q in [
            "SELECT COUNT(*) FROM audit WHERE hash=?1",
            "SELECT COUNT(*) FROM policies WHERE digest=?1",
            "SELECT COUNT(*) FROM observations WHERE digest=?1",
            "SELECT COUNT(*) FROM effects WHERE digest=?1",
            "SELECT COUNT(*) FROM evaluations WHERE input_digest=?1",
            "SELECT COUNT(*) FROM objects WHERE digest=?1",
        ] {
            let n: i64 = tx
                .query_row(q, params![digest], |r| r.get(0))
                .map_err(ferr)?;
            if n == 1 {
                found = true;
                break;
            }
        }
        Ok(found)
    }

    /// Append a signed audit event. Returns its seq and body digest.
    #[allow(clippy::too_many_arguments)]
    pub fn tx_append_audit(
        tx: &rusqlite::Transaction,
        body_bytes: &[u8],
        envelope_bytes: &[u8],
        seq: u64,
        hash: &str,
        prev: &str,
        epoch: u64,
        kind: &str,
    ) -> Result<(), Fault> {
        tx.execute(
            "INSERT INTO audit(seq,hash,prev,epoch,kind,body,envelope) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![seq as i64, hash, prev, epoch as i64, kind, body_bytes, envelope_bytes],
        )
        .map_err(ferr)?;
        Ok(())
    }

    // ---- generic entity projection helpers ----
    pub fn tx_put_entity(
        tx: &rusqlite::Transaction,
        table: &str,
        id: &str,
        body: &[u8],
        changed_seq: u64,
        entity: &str,
    ) -> Result<(), Fault> {
        match table {
            "runs" => {
                let v: Value = crate::json::parse(body, &crate::json::Limits::reply())
                    .map_err(|_| Fault::new(Code::AuditUnavailable, "bad run body"))?;
                let r = crate::schema::run(&v)
                    .map_err(|_| Fault::new(Code::AuditUnavailable, "bad run body"))?;
                tx.execute(
                    "INSERT INTO runs(id,revision,state,source,epoch,body,changed_seq) VALUES(?1,?2,?3,?4,?5,?6,?7)
                     ON CONFLICT(id) DO UPDATE SET revision=?2,state=?3,source=?4,epoch=?5,body=?6,changed_seq=?7",
                    params![id, r.revision as i64, r.state.as_str(), r.source, r.source_epoch as i64, body, changed_seq as i64],
                ).map_err(ferr)?;
            }
            "checks" => {
                let v: Value = crate::json::parse(body, &crate::json::Limits::reply())
                    .map_err(|_| Fault::new(Code::AuditUnavailable, "bad check body"))?;
                let c = crate::schema::check(&v)
                    .map_err(|_| Fault::new(Code::AuditUnavailable, "bad check body"))?;
                tx.execute(
                    "INSERT INTO checks(id,run,state,revision,deadline_ms,body,changed_seq) VALUES(?1,?2,?3,?4,?5,?6,?7)
                     ON CONFLICT(id) DO UPDATE SET run=?2,state=?3,revision=?4,deadline_ms=?5,body=?6,changed_seq=?7",
                    params![id, c.run, c.state.as_str(), c.revision as i64, c.deadline_ms as i64, body, changed_seq as i64],
                ).map_err(ferr)?;
            }
            "reviews" => {
                let v: Value = crate::json::parse(body, &crate::json::Limits::reply())
                    .map_err(|_| Fault::new(Code::AuditUnavailable, "bad review body"))?;
                let r = crate::schema::review(&v)
                    .map_err(|_| Fault::new(Code::AuditUnavailable, "bad review body"))?;
                let basis_d = r.basis.as_ref().map(crate::aggregate::basis_digest);
                tx.execute(
                    "INSERT INTO reviews(id,run,basis,state,revision,due_ms,lease_ms,body,changed_seq) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)
                     ON CONFLICT(id) DO UPDATE SET run=?2,basis=?3,state=?4,revision=?5,due_ms=?6,lease_ms=?7,body=?8,changed_seq=?9",
                    params![id, r.run, basis_d, r.state.as_str(), r.revision as i64, r.due_ms as i64,
                            r.lease_until_ms.map(|x| x as i64), body, changed_seq as i64],
                ).map_err(ferr)?;
            }
            "alerts" => {
                let v: Value = crate::json::parse(body, &crate::json::Limits::reply())
                    .map_err(|_| Fault::new(Code::AuditUnavailable, "bad alert body"))?;
                let a = crate::schema::alert(&v)
                    .map_err(|_| Fault::new(Code::AuditUnavailable, "bad alert body"))?;
                let ek = crate::aggregate::episode_key(&a.run, &a.monitor, &a.baseline);
                tx.execute(
                    "INSERT INTO alerts(id,run,episode_key,state,body,changed_seq) VALUES(?1,?2,?3,?4,?5,?6)
                     ON CONFLICT(id) DO UPDATE SET run=?2,episode_key=?3,state=?4,body=?5,changed_seq=?6",
                    params![id, a.run, ek, a.state.as_str(), body, changed_seq as i64],
                ).map_err(ferr)?;
            }
            _ => return Err(Fault::new(Code::AuditUnavailable, "unknown entity table")),
        }
        tx.execute(
            "INSERT INTO history(entity,id,seq,body) VALUES(?1,?2,?3,?4)",
            params![entity, id, changed_seq as i64, body],
        )
        .map_err(ferr)?;
        Ok(())
    }

    pub fn get_entity_body(&self, table: &str, id: &str) -> Result<Option<Vec<u8>>, Fault> {
        let q = match table {
            "runs" => "SELECT body FROM runs WHERE id=?1",
            "checks" => "SELECT body FROM checks WHERE id=?1",
            "reviews" => "SELECT body FROM reviews WHERE id=?1",
            "alerts" => "SELECT body FROM alerts WHERE id=?1",
            _ => return Err(Fault::new(Code::AuditUnavailable, "bad table")),
        };
        self.conn
            .query_row(q, params![id], |r| r.get::<_, Vec<u8>>(0))
            .optional()
            .map_err(ferr)
    }

    /// Entity body as of an audit cut (via history), or latest when
    /// `through` is None.
    pub fn get_entity_at(
        &self,
        entity: &str,
        id: &str,
        through: Option<u64>,
    ) -> Result<Option<Vec<u8>>, Fault> {
        match through {
            None => self.get_entity_body(entity, id),
            Some(cut) => self
                .conn
                .query_row(
                    "SELECT body FROM history WHERE entity=?1 AND id=?2 AND seq<=?3
                     ORDER BY seq DESC LIMIT 1",
                    params![entity, id, cut as i64],
                    |r| r.get::<_, Vec<u8>>(0),
                )
                .optional()
                .map_err(ferr),
        }
    }

    /// Does a `through` head name a retained audit position?
    pub fn head_exists(&self, h: &Head) -> Result<bool, Fault> {
        if h.seq == 0 {
            return Ok(h.hash == crate::ids::ZERO_HASH);
        }
        let got: Option<String> = self
            .conn
            .query_row(
                "SELECT hash FROM audit WHERE seq=?1",
                params![h.seq as i64],
                |r| r.get(0),
            )
            .optional()
            .map_err(ferr)?;
        Ok(got.as_deref() == Some(h.hash.as_str()))
    }

    // ---- observations ----
    pub fn tx_insert_observation(
        tx: &rusqlite::Transaction,
        run_id: &str,
        source: &str,
        epoch: u64,
        seq: u64,
        digest: &str,
        envelope: &[u8],
    ) -> Result<(), Fault> {
        tx.execute(
            "INSERT INTO observations(run,source,epoch,seq,digest,envelope) VALUES(?1,?2,?3,?4,?5,?6)",
            params![run_id, source, epoch as i64, seq as i64, digest, envelope],
        )
        .map_err(ferr)?;
        Ok(())
    }

    pub fn get_observation(&self, digest: &str) -> Result<Option<Vec<u8>>, Fault> {
        self.conn
            .query_row(
                "SELECT envelope FROM observations WHERE digest=?1",
                params![digest],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(ferr)
    }

    pub fn get_observation_by_ref(
        &self,
        source: &str,
        epoch: u64,
        run: &str,
        seq: u64,
    ) -> Result<Option<(String, Vec<u8>)>, Fault> {
        self.conn
            .query_row(
                "SELECT digest,envelope FROM observations WHERE source=?1 AND epoch=?2 AND run=?3 AND seq=?4",
                params![source, epoch as i64, run, seq as i64],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(ferr)
    }

    /// Latest observation envelope for a run.
    pub fn latest_observation(&self, run: &str) -> Result<Option<Vec<u8>>, Fault> {
        self.conn
            .query_row(
                "SELECT envelope FROM observations WHERE run=?1 ORDER BY seq DESC LIMIT 1",
                params![run],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(ferr)
    }

    // ---- actions (intent binding + rejection latch) ----
    pub fn tx_action_get(
        tx: &rusqlite::Transaction,
        run: &str,
        action: &str,
    ) -> Result<Option<(String, bool)>, Fault> {
        tx.query_row(
            "SELECT intent_digest,rejected FROM actions WHERE run=?1 AND action=?2",
            params![run, action],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? == 1)),
        )
        .optional()
        .map_err(ferr)
    }
    pub fn tx_action_put(
        tx: &rusqlite::Transaction,
        run: &str,
        action: &str,
        intent_digest: &str,
        rejected: bool,
    ) -> Result<(), Fault> {
        tx.execute(
            "INSERT INTO actions(run,action,intent_digest,rejected) VALUES(?1,?2,?3,?4)
             ON CONFLICT(run,action) DO UPDATE SET intent_digest=?3,rejected=?4",
            params![run, action, intent_digest, rejected as i64],
        )
        .map_err(ferr)?;
        Ok(())
    }

    // ---- effects ----
    pub fn tx_effect_head(
        tx: &rusqlite::Transaction,
        run: &str,
        action: &str,
    ) -> Result<Option<(String, String)>, Fault> {
        tx.query_row(
            "SELECT digest,state FROM effects WHERE run=?1 AND action=?2 ORDER BY rowid DESC LIMIT 1",
            params![run, action],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(ferr)
    }
    pub fn tx_effect_insert(
        tx: &rusqlite::Transaction,
        digest: &str,
        run: &str,
        action: &str,
        predecessor: Option<&str>,
        state: &str,
        envelope: &[u8],
    ) -> Result<(), Fault> {
        tx.execute(
            "INSERT INTO effects(digest,run,action,predecessor,state,envelope) VALUES(?1,?2,?3,?4,?5,?6)",
            params![digest, run, action, predecessor, state, envelope],
        )
        .map_err(ferr)?;
        Ok(())
    }
    pub fn effect_get(&self, digest: &str) -> Result<Option<Vec<u8>>, Fault> {
        self.conn
            .query_row(
                "SELECT envelope FROM effects WHERE digest=?1",
                params![digest],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(ferr)
    }

    // ---- idempotency ----
    pub fn tx_idem_get(
        tx: &rusqlite::Transaction,
        principal: &str,
        request: &str,
    ) -> Result<Option<(String, String, Vec<u8>)>, Fault> {
        tx.query_row(
            "SELECT method,params_hash,reply FROM idempotency WHERE principal=?1 AND request=?2",
            params![principal, request],
            |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, Vec<u8>>(2)?)),
        )
        .optional()
        .map_err(ferr)
    }
    pub fn tx_idem_put(
        tx: &rusqlite::Transaction,
        principal: &str,
        request: &str,
        method: &str,
        params_hash: &str,
        reply: &[u8],
    ) -> Result<(), Fault> {
        tx.execute(
            "INSERT INTO idempotency(principal,request,method,params_hash,reply) VALUES(?1,?2,?3,?4,?5)",
            params![principal, request, method, params_hash, reply],
        )
        .map_err(ferr)?;
        Ok(())
    }

    // ---- policies ----
    pub fn tx_policy_put(
        tx: &rusqlite::Transaction,
        digest: &str,
        generation: u64,
        body: &[u8],
    ) -> Result<(), Fault> {
        tx.execute(
            "INSERT INTO policies(digest,generation,body) VALUES(?1,?2,?3)",
            params![digest, generation as i64, body],
        )
        .map_err(ferr)?;
        Ok(())
    }
    pub fn policy_get(&self, digest: &str) -> Result<Option<Vec<u8>>, Fault> {
        self.conn
            .query_row(
                "SELECT body FROM policies WHERE digest=?1",
                params![digest],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(ferr)
    }
    pub fn policy_get_on(conn: &Connection, digest: &str) -> Result<Option<Vec<u8>>, Fault> {
        conn.query_row(
            "SELECT body FROM policies WHERE digest=?1",
            params![digest],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(ferr)
    }
    pub fn policy_latest(&self) -> Result<Option<Vec<u8>>, Fault> {
        self.conn
            .query_row(
                "SELECT body FROM policies ORDER BY generation DESC LIMIT 1",
                [],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(ferr)
    }

    // ---- evaluations ----
    pub fn tx_evaluation_put(
        tx: &rusqlite::Transaction,
        id: &str,
        input_digest: &str,
        output: &[u8],
        changed_seq: u64,
    ) -> Result<(), Fault> {
        tx.execute(
            "INSERT INTO evaluations(id,input_digest,output,changed_seq) VALUES(?1,?2,?3,?4)",
            params![id, input_digest, output, changed_seq as i64],
        )
        .map_err(ferr)?;
        Ok(())
    }
    pub fn evaluation_by_input(&self, input_digest: &str) -> Result<Option<Vec<u8>>, Fault> {
        self.conn
            .query_row(
                "SELECT output FROM evaluations WHERE input_digest=?1",
                params![input_digest],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(ferr)
    }
    pub fn evaluation_by_id(&self, id: &str) -> Result<Option<Vec<u8>>, Fault> {
        self.conn
            .query_row(
                "SELECT output FROM evaluations WHERE id=?1",
                params![id],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(ferr)
    }

    // ---- objects ----
    pub fn tx_object_put(
        tx: &rusqlite::Transaction,
        digest: &str,
        kind: &str,
        bytes: u64,
        state: &str,
        expires_utc: &str,
    ) -> Result<(), Fault> {
        tx.execute(
            "INSERT INTO objects(digest,kind,bytes,state,expires_utc) VALUES(?1,?2,?3,?4,?5)
             ON CONFLICT(digest) DO UPDATE SET kind=?2,bytes=?3,state=?4,expires_utc=?5",
            params![digest, kind, bytes as i64, state, expires_utc],
        )
        .map_err(ferr)?;
        Ok(())
    }

    // ---- outbox ----
    pub fn tx_outbox_put(
        tx: &rusqlite::Transaction,
        kind: &str,
        subject: &str,
        due_ms: u64,
        body: &[u8],
    ) -> Result<(), Fault> {
        tx.execute(
            "INSERT INTO outbox(kind,subject,due_ms,attempts,body) VALUES(?1,?2,?3,0,?4)
             ON CONFLICT(kind,subject) DO UPDATE SET due_ms=?3,body=?4",
            params![kind, subject, due_ms as i64, body],
        )
        .map_err(ferr)?;
        Ok(())
    }
    pub fn outbox_due(&self, now: u64) -> Result<Vec<OutboxRow>, Fault> {
        let mut st = self
            .conn
            .prepare("SELECT id,kind,subject,body FROM outbox WHERE due_ms<=?1 ORDER BY due_ms,id")
            .map_err(ferr)?;
        let rows = st
            .query_map(params![now as i64], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get::<_, Vec<u8>>(3)?))
            })
            .map_err(ferr)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(ferr)?);
        }
        Ok(out)
    }
    pub fn tx_outbox_delete(tx: &rusqlite::Transaction, id: i64) -> Result<(), Fault> {
        tx.execute("DELETE FROM outbox WHERE id=?1", params![id])
            .map_err(ferr)?;
        Ok(())
    }

    // ---- monitor slots ----
    pub fn tx_slot_put(
        tx: &rusqlite::Transaction,
        check: &str,
        monitor: &str,
        deadline_ms: u64,
        state: &str,
        result: Option<&[u8]>,
    ) -> Result<(), Fault> {
        tx.execute(
            "INSERT INTO monitor_slots(check_id,monitor_id,deadline_ms,state,result) VALUES(?1,?2,?3,?4,?5)
             ON CONFLICT(check_id,monitor_id) DO UPDATE SET deadline_ms=?3,state=?4,result=?5",
            params![check, monitor, deadline_ms as i64, state, result],
        )
        .map_err(ferr)?;
        Ok(())
    }
    pub fn slots_for_check(&self, check: &str) -> Result<Vec<SlotRow>, Fault> {
        let mut st = self
            .conn
            .prepare(
                "SELECT monitor_id,deadline_ms,state,result FROM monitor_slots WHERE check_id=?1 ORDER BY monitor_id",
            )
            .map_err(ferr)?;
        let rows = st
            .query_map(params![check], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)? as u64,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<Vec<u8>>>(3)?,
                ))
            })
            .map_err(ferr)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(ferr)?);
        }
        Ok(out)
    }

    // ---- windows ----
    pub fn tx_window_put(
        tx: &rusqlite::Transaction,
        run: &str,
        start_ms: u64,
        counts: Option<&[u8]>,
    ) -> Result<(), Fault> {
        tx.execute(
            "INSERT INTO windows(run,start_ms,counts) VALUES(?1,?2,?3)
             ON CONFLICT(run,start_ms) DO UPDATE SET counts=COALESCE(?3,counts)",
            params![run, start_ms as i64, counts],
        )
        .map_err(ferr)?;
        Ok(())
    }
    pub fn window_counts(
        &self,
        run: &str,
        start_ms: u64,
    ) -> Result<Option<Option<Vec<u8>>>, Fault> {
        self.conn
            .query_row(
                "SELECT counts FROM windows WHERE run=?1 AND start_ms=?2",
                params![run, start_ms as i64],
                |r| r.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()
            .map_err(ferr)
    }
    /// Attempted (processed) windows are those with a non-NULL counts entry
    /// OR a recorded TrailingEvaluated; we track attempts via a marker row
    /// counts=NULL meaning "attempted, missing".
    pub fn window_attempted(&self, run: &str, start_ms: u64) -> Result<bool, Fault> {
        let n: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM windows WHERE run=?1 AND start_ms=?2",
                params![run, start_ms as i64],
                |r| r.get(0),
            )
            .map_err(ferr)?;
        Ok(n > 0)
    }

    // ---- list queries ----
    /// Reviews/alerts visible at cut `through`, latest change seq in
    /// `(after, through]`, ascending, limited.
    pub fn list_at(
        &self,
        entity: &str, // "reviews" | "alerts"
        run: Option<&str>,
        after: u64,
        through: u64,
        limit: usize,
    ) -> Result<EventsPage, Fault> {
        // The entity's *latest* change seq at the cut determines ordering and
        // pagination: one row per entity = max(seq) ≤ through.
        let mut st = self
            .conn
            .prepare(
                "SELECT h.id, h.seq, h.body FROM history h
                 WHERE h.entity=?1 AND h.seq<=?2 AND h.seq=(
                   SELECT MAX(seq) FROM history WHERE entity=?1 AND id=h.id AND seq<=?2)
                 ORDER BY h.seq ASC, h.id ASC",
            )
            .map_err(ferr)?;
        let rows = st
            .query_map(params![entity, through as i64], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(ferr)?;
        let mut items = Vec::new();
        for r in rows {
            let (_id, seq, body) = r.map_err(ferr)?;
            if seq as u64 <= after {
                continue;
            }
            if let Some(rf) = run {
                // cheap run filter on stored body
                let v: Value = crate::json::parse(&body, &crate::json::Limits::reply())
                    .map_err(|_| Fault::new(Code::AuditUnavailable, "bad body"))?;
                let run_id = v.get("run").and_then(|x| x.as_str().map(|s| s.to_string()));
                if run_id.as_deref() != Some(rf) {
                    continue;
                }
            }
            items.push((seq as u64, body));
        }
        let next_after = if items.len() > limit {
            items.truncate(limit);
            items.last().map(|(s, _)| *s)
        } else {
            None
        };
        Ok((items, next_after))
    }

    /// Audit events in `(after, through]` ascending, limited.
    pub fn events_page(
        &self,
        after: u64,
        through: u64,
        limit: usize,
    ) -> Result<(Vec<Vec<u8>>, Option<u64>), Fault> {
        let mut st = self
            .conn
            .prepare("SELECT seq,envelope FROM audit WHERE seq>?1 AND seq<=?2 ORDER BY seq ASC")
            .map_err(ferr)?;
        let rows = st
            .query_map(params![after as i64, through as i64], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(ferr)?;
        let mut items: Vec<(i64, Vec<u8>)> = Vec::new();
        let mut last = None;
        for r in rows {
            let (s, b) = r.map_err(ferr)?;
            if items.len() == limit {
                last = Some(items.last().unwrap().0 as u64);
                break;
            }
            items.push((s, b));
        }
        let envs: Vec<Vec<u8>> = items.iter().map(|(_, b)| b.clone()).collect();
        Ok((envs, last))
    }

    /// All audit envelopes with seq ≤ through (ascending).
    pub fn events_to(&self, through: u64) -> Result<Vec<Vec<u8>>, Fault> {
        let mut st = self
            .conn
            .prepare("SELECT envelope FROM audit WHERE seq<=?1 ORDER BY seq ASC")
            .map_err(ferr)?;
        let rows = st
            .query_map(params![through as i64], |r| r.get::<_, Vec<u8>>(0))
            .map_err(ferr)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(ferr)?);
        }
        Ok(out)
    }
}
