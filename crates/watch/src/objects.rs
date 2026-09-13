//! Encrypted immutable object store (§6.1): XChaCha20-Poly1305 with
//! AAD `J({v,tenant,key_id,kind,digest})`, fsynced temp-file + rename writes.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;

use crate::crypto::{b64u_decode, b64u_encode};
use crate::fault::{Code, Fault};
use crate::json::{jcs, Value};

pub struct ObjectStore {
    pub dir: std::path::PathBuf,
    pub key_id: String,
    pub key: [u8; 32],
}

fn aead(key: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(key).expect("32-byte key")
}

fn aad(tenant: &str, key_id: &str, kind: &str, digest: &str) -> Vec<u8> {
    jcs(&Value::obj(vec![
        ("v", Value::num(1)),
        ("tenant", Value::str(tenant)),
        ("key_id", Value::str(key_id)),
        ("kind", Value::str(kind)),
        ("digest", Value::str(digest)),
    ]))
    .into_bytes()
}

impl ObjectStore {
    pub fn new(dir: std::path::PathBuf, key_id: &str, key: [u8; 32]) -> ObjectStore {
        ObjectStore {
            dir,
            key_id: key_id.to_string(),
            key,
        }
    }

    fn path(&self, digest: &str) -> std::path::PathBuf {
        self.dir.join(&digest[..2]).join(digest)
    }

    /// Store plaintext canonical bytes under `digest`; returns the file path.
    /// Writes via exclusive temp file, fsync, atomic rename, dir fsync.
    pub fn put(
        &self,
        tenant: &str,
        kind: &str,
        digest: &str,
        plaintext: &[u8],
    ) -> Result<std::path::PathBuf, Fault> {
        let fail = |m: &str| Fault::new(Code::ArtifactUnavailable, m);
        let mut nonce = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ct = aead(&self.key)
            .encrypt(
                XNonce::from_slice(&nonce),
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad: &aad(tenant, &self.key_id, kind, digest),
                },
            )
            .map_err(|_| fail("object encryption failed"))?;
        let file = Value::obj(vec![
            ("v", Value::num(1)),
            ("tenant", Value::str(tenant)),
            ("key_id", Value::str(&self.key_id)),
            ("kind", Value::str(kind)),
            ("digest", Value::str(digest)),
            ("nonce", Value::str(&b64u_encode(&nonce))),
            ("ciphertext", Value::str(&b64u_encode(&ct))),
        ]);
        let bytes = jcs(&file).into_bytes();

        let path = self.path(digest);
        let shard = path.parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&shard).map_err(|e| fail(&format!("object shard dir: {e}")))?;
        let tmp = shard.join(format!(".{digest}.tmp"));
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(|e| fail(&format!("object temp: {e}")))?;
            f.write_all(&bytes)
                .map_err(|e| fail(&format!("object write: {e}")))?;
            f.sync_all()
                .map_err(|e| fail(&format!("object fsync: {e}")))?;
        }
        std::fs::rename(&tmp, &path).map_err(|e| fail(&format!("object rename: {e}")))?;
        if let Ok(d) = std::fs::File::open(&shard) {
            let _ = d.sync_all();
        }
        Ok(path)
    }

    /// Load and decrypt an object, verifying digest, header, and tag.
    pub fn get(&self, tenant: &str, kind: &str, digest: &str) -> Result<Vec<u8>, Fault> {
        let fail = |m: &str| Fault::new(Code::ArtifactUnavailable, m);
        let path = self.path(digest);
        let bytes = std::fs::read(&path).map_err(|_| fail("object missing"))?;
        let v = crate::json::parse(&bytes, &crate::json::Limits::bundle())
            .map_err(|_| fail("object parse"))?;
        let m = v.as_obj().ok_or_else(|| fail("object shape"))?;
        let get =
            |k: &str| -> Result<&Value, Fault> { v.get(k).ok_or_else(|| fail("object field")) };
        let _ = m;
        if get("v")?.as_int() != Some(1) {
            return Err(fail("object v"));
        }
        if get("tenant")?.as_str() != Some(tenant)
            || get("key_id")?.as_str() != Some(self.key_id.as_str())
            || get("kind")?.as_str() != Some(kind)
            || get("digest")?.as_str() != Some(digest)
        {
            return Err(fail("object header mismatch"));
        }
        let nonce = b64u_decode(get("nonce")?.as_str().ok_or_else(|| fail("nonce"))?)
            .filter(|n| n.len() == 24)
            .ok_or_else(|| fail("nonce decode"))?;
        let ct = b64u_decode(get("ciphertext")?.as_str().ok_or_else(|| fail("ct"))?)
            .ok_or_else(|| fail("ciphertext decode"))?;
        let pt = aead(&self.key)
            .decrypt(
                XNonce::from_slice(&nonce),
                chacha20poly1305::aead::Payload {
                    msg: &ct,
                    aad: &aad(tenant, &self.key_id, kind, digest),
                },
            )
            .map_err(|_| fail("object auth failed"))?;
        // The AAD binds the digest; callers that need content-digest
        // verification check the plaintext against the relevant D-tag.
        Ok(pt)
    }
}
