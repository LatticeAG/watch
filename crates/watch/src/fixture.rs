//! The inert fixture adapter (§1.2): record.read / record.write over a
//! private record table. This is the only OSS-core adapter — no shell,
//! SQL, URL, alias, or arbitrary request execution exists.

use crate::crypto::d;
use crate::fault::{Code, Fault};
use crate::json::{jcs, Value};
use crate::schema::*;

type R<T> = Result<T, Fault>;

/// A parsed ToolRequest: read or write.
#[derive(Debug, Clone)]
pub enum ToolReq {
    Read {
        record: String,
    },
    Write {
        record: String,
        value: String,
        cost_minor: u64,
    },
}

pub fn tool_request_value(t: &ToolReq) -> Value {
    match t {
        ToolReq::Read { record } => Value::obj(vec![
            ("op", Value::str("read")),
            ("record", Value::str(record)),
        ]),
        ToolReq::Write {
            record,
            value,
            cost_minor,
        } => Value::obj(vec![
            ("op", Value::str("write")),
            ("record", Value::str(record)),
            ("value", Value::str(value)),
            ("cost_minor", Value::ustr(&cost_minor.to_string())),
        ]),
    }
}

/// request_hash = D("raw-request", ToolRequest); authority_hash =
/// D("authority", {principal:runtime_id, record:record_id}).
pub fn intent_for(t: &ToolReq, runtime: &str, target_revision: u64, cost_minor: u64) -> Intent {
    let req_v = tool_request_value(t);
    let (record, tool, scopes, cost) = match t {
        ToolReq::Read { record } => (
            record.clone(),
            "record.read",
            vec!["read".to_string()],
            0u64,
        ),
        ToolReq::Write { record, .. } => (
            record.clone(),
            "record.write",
            vec!["write".to_string()],
            cost_minor,
        ),
    };
    let authority = d(
        "authority",
        &Value::obj(vec![
            ("principal", Value::str(runtime)),
            ("record", Value::str(&record)),
        ]),
    );
    Intent {
        action: format!("act_{}", &d("raw-request", &req_v)[..16]),
        request_hash: d("raw-request", &req_v),
        tool: tool.to_string(),
        target_revision,
        authority_hash: authority,
        scopes,
        cost_minor: cost,
    }
}

/// Execute an admitted ToolRequest against the runtime-owned record table
/// (inside the guard's store transaction). `read` never mutates; `write`
/// replaces the bounded value and increments the record's revision.
pub fn execute_on(conn: &rusqlite::Connection, t: &ToolReq) -> R<(Option<String>, u64)> {
    match t {
        ToolReq::Read { record } => {
            use rusqlite::OptionalExtension;
            let row: Option<(String, i64)> = conn
                .query_row(
                    "SELECT value,revision FROM records WHERE record=?1",
                    rusqlite::params![record],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
            match row {
                Some((v, r)) => Ok((Some(v), r as u64)),
                None => Ok((None, 0)),
            }
        }
        ToolReq::Write { record, value, .. } => {
            if value.len() > crate::TEXT_MAX {
                return Err(Fault::new(Code::SchemaInvalid, "value too large"));
            }
            use rusqlite::OptionalExtension;
            let cur: Option<i64> = conn
                .query_row(
                    "SELECT revision FROM records WHERE record=?1",
                    rusqlite::params![record],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
            let next = cur.unwrap_or(0) + 1;
            conn.execute(
                "INSERT INTO records(record,value,revision) VALUES(?1,?2,?3)
                 ON CONFLICT(record) DO UPDATE SET value=?2,revision=?3",
                rusqlite::params![record, value, next],
            )
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
            Ok((None, next as u64))
        }
    }
}

/// Canonical bytes of a ToolRequest (J serialization).
pub fn request_bytes(t: &ToolReq) -> Vec<u8> {
    jcs(&tool_request_value(t)).into_bytes()
}
