//! §9.1 operational metrics: sorted by (name, kind, outcome); counter
//! values decimal strings; ratios six-place strings; absent dims empty.

use crate::daemon::Daemon;
use crate::fault::{Code, Fault};
use crate::json::Value;
use crate::schema::*;

type R<T> = Result<T, Fault>;

pub fn get(d: &Daemon) -> R<Value> {
    let head = d.store.head()?;
    let mut rows: Vec<(String, String, String, String)> = Vec::new(); // name,kind,outcome,value

    // Counters recorded under meta ctr:* keys.
    {
        let mut st = d
            .store
            .conn
            .prepare("SELECT k,value FROM meta WHERE k LIKE 'ctr:%'")
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        let rr = st
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        for r in rr {
            let (k, v) = r.map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
            let rest = k.trim_start_matches("ctr:");
            let mut it = rest.splitn(3, '|');
            let (name, kind, outcome) = (
                it.next().unwrap_or("").to_string(),
                it.next().unwrap_or("").to_string(),
                it.next().unwrap_or("").to_string(),
            );
            let val = String::from_utf8_lossy(&v).to_string();
            if val != "0" {
                rows.push((name, kind, outcome, val));
            }
        }
    }

    // Gauges computed from live projections.
    let q = |sql: &str, args: &[&dyn rusqlite::ToSql]| -> R<i64> {
        d.store
            .conn
            .query_row(sql, args, |r| r.get(0))
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))
    };
    for (lvl, lname) in [
        ("critical", "critical"),
        ("warning", "warning"),
        ("info", "info"),
    ] {
        let n = q(
            "SELECT COUNT(*) FROM reviews r WHERE r.state IN ('OPEN','CLAIMED','DEFERRED','ACCEPTED')
             AND json_extract(r.body,'$.level')=?1",
            &[&lvl],
        )?;
        if n > 0 {
            rows.push((
                "watch_remainder_depth".into(),
                lname.into(),
                "".into(),
                n.to_string(),
            ));
        }
        let oldest: Option<i64> = d
            .store
            .conn
            .query_row(
                "SELECT MIN(due_ms) - ?1 FROM reviews WHERE state IN ('OPEN','CLAIMED','DEFERRED','ACCEPTED') AND json_extract(body,'$.level')=?2",
                rusqlite::params![0i64, lvl],
                |r| r.get(0),
            )
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        let _ = oldest;
    }
    // Oldest open review age per level (uses due-ttl as creation proxy via
    // created_seq → audit at_ms).
    {
        let mut st = d
            .store
            .conn
            .prepare(
                "SELECT json_extract(r.body,'$.level'), MIN(CAST(json_extract(a.body,'$.at_ms') AS INTEGER))
                 FROM reviews r JOIN audit a ON a.seq = CAST(json_extract(r.body,'$.created_seq') AS INTEGER)
                 WHERE r.state IN ('OPEN','CLAIMED','DEFERRED','ACCEPTED') GROUP BY 1",
            )
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        let rr = st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        for r in rr {
            let (lvl, at) = r.map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
            rows.push((
                "watch_remainder_oldest_ms".into(),
                lvl,
                "".into(),
                d.now.saturating_sub(at as u64).to_string(),
            ));
        }
    }
    // Source lag: max(now - last_received_ms) over OPEN runs with telemetry.
    {
        let lag: Option<i64> = d
            .store
            .conn
            .query_row(
                "SELECT MAX(?1 - CAST(json_extract(body,'$.last_received_ms') AS INTEGER))
                 FROM runs WHERE state='OPEN' AND json_extract(body,'$.last_received_ms') IS NOT NULL",
                rusqlite::params![d.now as i64],
                |r| r.get(0),
            )
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        if let Some(l) = lag {
            rows.push((
                "watch_source_lag_ms".into(),
                "".into(),
                "max".into(),
                l.to_string(),
            ));
        }
    }
    // Storage used bp.
    {
        let page_count: i64 = d
            .store
            .conn
            .query_row("PRAGMA page_count", [], |r| r.get(0))
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        let page_size: i64 = d
            .store
            .conn
            .query_row("PRAGMA page_size", [], |r| r.get(0))
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        let used = (page_count as u64) * (page_size as u64);
        if let Some(bp) = used
            .saturating_mul(10000)
            .checked_div(d.cfg.storage_max_bytes)
        {
            rows.push((
                "watch_storage_used_bp".into(),
                "".into(),
                "".into(),
                bp.to_string(),
            ));
        }
    }
    // Outbox oldest.
    {
        let oldest: Option<i64> = d
            .store
            .conn
            .query_row("SELECT MIN(due_ms) FROM outbox", [], |r| r.get(0))
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        if let Some(o) = oldest {
            rows.push((
                "watch_outbox_oldest_ms".into(),
                "".into(),
                "".into(),
                d.now.saturating_sub(o as u64).to_string(),
            ));
        }
    }
    // Unresolved external-effect ambiguity: UNKNOWN effects without a later
    // terminal record.
    {
        let n: i64 = d
            .store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM effects e WHERE e.state='UNKNOWN' AND NOT EXISTS
                   (SELECT 1 FROM effects e2 WHERE e2.run=e.run AND e2.action=e.action
                    AND e2.predecessor IS NOT NULL AND e2.predecessor!=e.digest)",
                [],
                |r| r.get(0),
            )
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        if n > 0 {
            rows.push((
                "watch_guard_unknown_effects".into(),
                "".into(),
                "".into(),
                n.to_string(),
            ));
        }
    }
    // Audit write p99 from the reservoir.
    if !d.audit_write_ms.is_empty() {
        let mut v = d.audit_write_ms.clone();
        v.sort();
        let p99 = v[(v.len() * 99 / 100).min(v.len() - 1)];
        rows.push((
            "watch_audit_write_ms".into(),
            "".into(),
            "p99".into(),
            p99.to_string(),
        ));
    }
    // Observation coverage ratio per profile.
    {
        let mut st = d
            .store
            .conn
            .prepare("SELECT json_extract(body,'$.profile') FROM runs GROUP BY 1")
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        let rr = st
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        for r in rr {
            let prof = r.map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
            let (got, total): (i64, i64) = d
                .store
                .conn
                .query_row(
                    "SELECT COALESCE(SUM(CASE WHEN counts IS NOT NULL THEN 1 ELSE 0 END),0), COUNT(*)
                     FROM windows w JOIN runs r ON r.id=w.run WHERE json_extract(r.body,'$.profile')=?1",
                    rusqlite::params![prof],
                    |x| Ok((x.get(0)?, x.get(1)?)),
                )
                .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
            if total > 0 {
                let ratio = format!("{:.6}", (got as f64) / (total as f64));
                rows.push(("watch_observation_coverage".into(), prof, "".into(), ratio));
            }
        }
    }

    rows.sort();
    let values: Vec<Value> = rows
        .into_iter()
        .map(|(name, kind, outcome, value)| {
            Value::obj(vec![
                (
                    "labels",
                    Value::obj(vec![
                        ("kind", Value::str(&kind)),
                        ("outcome", Value::str(&outcome)),
                    ]),
                ),
                ("name", Value::str(&name)),
                ("value", Value::str(&value)),
            ])
        })
        .collect();
    Ok(Value::obj(vec![
        ("at", head_value(&head)),
        ("values", Value::Arr(values)),
    ]))
}
