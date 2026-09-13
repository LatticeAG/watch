//! §6.2 backup/restore: SQLite consistent backup plus encrypted object
//! files and Signed<BackupManifest> (tag "backup"). Restore refuses when
//! the store's head is behind the independent minimum_head pin.

use std::path::{Path, PathBuf};

use crate::crypto::{d, sha256_hex, sign_envelope};
use crate::fault::{Code, Fault};
use crate::json::{jcs, Value};
use crate::schema::*;
use crate::store::Store;

type R<T> = Result<T, Fault>;

fn ferr<E: std::fmt::Display>(e: E) -> Fault {
    Fault::new(Code::AuditUnavailable, &e.to_string())
}

/// `store backup`: consistent DB copy + object files + signed manifest.
/// Offline only (daemon stopped). Returns {manifest:Hash, head:Head}.
#[allow(clippy::too_many_arguments)]
pub fn backup(
    db_path: &Path,
    objects_dir: &Path,
    out_dir: &Path,
    tenant: &str,
    key_id: &str,
    key_epoch: u64,
    sk: &ed25519_dalek::SigningKey,
    created_utc: &str,
) -> R<Value> {
    let store = Store::open(db_path)?;
    let head = store.head()?;
    std::fs::create_dir_all(out_dir).map_err(ferr)?;
    let db_out = out_dir.join("watch.db");
    // Consistent SQLite backup.
    {
        let mut dest = rusqlite::Connection::open(&db_out).map_err(ferr)?;
        let src = &store.conn;
        let b = rusqlite::backup::Backup::new(src, &mut dest).map_err(ferr)?;
        b.run_to_completion(64, std::time::Duration::from_millis(10), None)
            .map_err(ferr)?;
    }
    let db_bytes = std::fs::read(&db_out).map_err(ferr)?;
    let db_sha = sha256_hex(&db_bytes);
    // Copy object files, hashing stored bytes.
    let mut files: Vec<(String, u64, String)> = Vec::new();
    if objects_dir.is_dir() {
        let mut stack = vec![objects_dir.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(&dir).map_err(ferr)? {
                let e = e.map_err(ferr)?;
                let p = e.path();
                let rel = p
                    .strip_prefix(objects_dir)
                    .unwrap()
                    .to_string_lossy()
                    .to_string();
                if rel.contains("..") || rel.starts_with('/') {
                    return Err(Fault::new(Code::SchemaInvalid, "unsafe object path"));
                }
                if p.is_dir() {
                    stack.push(p);
                } else {
                    let b = std::fs::read(&p).map_err(ferr)?;
                    let h = sha256_hex(&b);
                    let dest = out_dir.join("objects").join(&rel);
                    std::fs::create_dir_all(dest.parent().unwrap()).map_err(ferr)?;
                    std::fs::write(&dest, &b).map_err(ferr)?;
                    files.push((rel, b.len() as u64, h));
                }
            }
        }
    }
    files.sort();
    let manifest_body = Value::obj(vec![
        ("v", Value::num(1)),
        ("format", Value::str("watch-backup/1")),
        ("tenant", Value::str(tenant)),
        ("schema", Value::num(1)),
        ("head", head_value(&head)),
        ("db_bytes", Value::ustr(&db_bytes.len().to_string())),
        ("db_sha256", Value::str(&db_sha)),
        (
            "files",
            Value::Arr(
                files
                    .iter()
                    .map(|(p, n, h)| {
                        Value::obj(vec![
                            ("path", Value::str(p)),
                            ("bytes", Value::ustr(&n.to_string())),
                            ("sha256", Value::str(h)),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("created_utc", Value::str(created_utc)),
    ]);
    let manifest = sign_envelope("backup", &manifest_body, key_id, &key_epoch.to_string(), sk);
    let mpath = out_dir.join("manifest.json");
    // Exclusive creation, no overwrite.
    if mpath.exists() {
        return Err(Fault::new(Code::StateConflict, "manifest exists"));
    }
    std::fs::write(&mpath, jcs(&manifest)).map_err(ferr)?;
    let mdigest = d("backup", &manifest_body);
    Ok(Value::obj(vec![
        ("manifest", Value::str(&mdigest)),
        ("head", head_value(&head)),
    ]))
}

/// Restore check: refuse when the local head is behind the independent
/// minimum_head pin (§6.2). Returns nothing; the caller starts FAULTED.
pub fn restore_head_check(local: &Head, minimum: &Head) -> R<()> {
    if local.seq < minimum.seq {
        return Err(Fault::new(
            Code::MigrationRequired,
            "restored behind independent minimum head",
        ));
    }
    Ok(())
}

/// `store migrate --target 1`: identity migration — verify the store is
/// already at user_version 1 and emit MigrationResult.
pub fn migrate(db_path: &Path) -> R<Value> {
    let store = Store::open(db_path)?;
    let v: i64 = store
        .conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(ferr)?;
    if v != 1 {
        return Err(Fault::new(
            Code::MigrationRequired,
            "unsupported schema version",
        ));
    }
    let head = store.head()?;
    Ok(Value::obj(vec![
        ("from", Value::num(1)),
        ("to", Value::num(1)),
        ("state", Value::str("VERIFIED_NO_CHANGE")),
        ("head", head_value(&head)),
    ]))
}

/// Collect every file under `dir` (for doctor/manifests).
pub fn list_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(list_files(&p));
            } else {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}
