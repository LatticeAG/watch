//! The control socket: Linux AF_UNIX SOCK_STREAM, 4-byte big-endian frame
//! length + canonical JSON, SO_PEERCRED authentication, one in-flight
//! request per connection, ≤8 connections/principal, ≤64 total.

use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::daemon::{Daemon, Outcome};
use crate::fault::{Code, Fault};
use crate::json::{jcs, parse, Limits, Value};
use crate::schema::Principal;

/// Peer credentials from SO_PEERCRED.
pub fn peer_uid(s: &UnixStream) -> Option<u32> {
    #[repr(C)]
    struct Ucred {
        pid: i32,
        uid: u32,
        gid: u32,
    }
    let mut c = Ucred {
        pid: 0,
        uid: u32::MAX,
        gid: 0,
    };
    let mut len = std::mem::size_of::<Ucred>() as u32;
    let rc = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut c as *mut Ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 && len as usize == std::mem::size_of::<Ucred>() {
        Some(c.uid)
    } else {
        None
    }
}

fn fault_reply(id: &str, f: &Fault) -> Value {
    Value::obj(vec![
        ("v", Value::num(1)),
        ("id", Value::str(id)),
        ("ok", Value::Bool(false)),
        ("error", f.to_value()),
    ])
}

pub fn mget<'a>(m: &'a [(String, Value)], k: &str) -> Option<&'a Value> {
    m.iter().find(|(k2, _)| k2 == k).map(|(_, v)| v)
}

fn write_reply(s: &mut UnixStream, v: &Value) -> std::io::Result<()> {
    let b = jcs(v).into_bytes();
    if b.len() > crate::REPLY_MAX {
        let e = fault_reply(
            "unknown",
            &Fault::new(Code::BundleLimit, "reply over bound"),
        );
        let eb = jcs(&e).into_bytes();
        s.write_all(&(eb.len() as u32).to_be_bytes())?;
        return s.write_all(&eb);
    }
    s.write_all(&(b.len() as u32).to_be_bytes())?;
    s.write_all(&b)
}

/// Serve the daemon on the configured socket until stopped. Blocking.
/// `stop` is flipped by the drain path; the loop polls it every 50 ms.
pub fn serve(
    d: Arc<Mutex<Daemon>>,
    socket_path: &Path,
    stop: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<()> {
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;
    // The socket must be connectable by every configured principal UID;
    // SO_PEERCRED binds the principal and rejects unmapped UIDs with
    // UNAUTHENTICATED (§3.1). Filesystem mode is not the auth boundary.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o666))?;
    }
    listener.set_nonblocking(true)?;
    let conns = Arc::new(AtomicU64::new(0));
    let per_principal: Arc<Mutex<std::collections::HashMap<String, u64>>> =
        Arc::new(Mutex::new(std::collections::HashMap::new()));
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let d = d.clone();
                let conns = conns.clone();
                let per_principal = per_principal.clone();
                std::thread::spawn(move || {
                    handle_conn(stream, d, conns, per_principal);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn handle_conn(
    mut s: UnixStream,
    d: Arc<Mutex<Daemon>>,
    conns: Arc<AtomicU64>,
    per_principal: Arc<Mutex<std::collections::HashMap<String, u64>>>,
) {
    // SO_PEERCRED → configured principal. Unknown UID: UNAUTHENTICATED
    // replies to well-formed requests; malformed framing just closes.
    let principal: Option<Principal> = {
        let dg = d.lock().unwrap();
        let uid = peer_uid(&s);
        uid.and_then(|u| {
            dg.cfg
                .principals
                .iter()
                .find(|p| p.uid == u as u64)
                .cloned()
        })
    };
    // Connection caps.
    {
        let total = conns.fetch_add(1, Ordering::SeqCst) + 1;
        if total > crate::CONN_TOTAL as u64 {
            conns.fetch_sub(1, Ordering::SeqCst);
            return;
        }
        if let Some(p) = &principal {
            let mut m = per_principal.lock().unwrap();
            let e = m.entry(p.id.clone()).or_insert(0);
            *e += 1;
            if *e > crate::CONN_PER_PRINCIPAL as u64 {
                *e -= 1;
                conns.fetch_sub(1, Ordering::SeqCst);
                return;
            }
        }
    }
    let cleanup = |conns: &AtomicU64,
                   per: &Mutex<std::collections::HashMap<String, u64>>,
                   p: &Option<Principal>| {
        conns.fetch_sub(1, Ordering::SeqCst);
        if let Some(p) = p {
            if let Some(e) = per.lock().unwrap().get_mut(&p.id) {
                *e = e.saturating_sub(1);
            }
        }
    };
    loop {
        // One in-flight request: read exactly one frame, then respond.
        let mut lenb = [0u8; 4];
        if s.read_exact(&mut lenb).is_err() {
            break;
        }
        let n = u32::from_be_bytes(lenb) as usize;
        if n == 0 || n > crate::REQ_MAX {
            let mut g = d.lock().unwrap();
            g.protocol_errors += 1;
            break; // BAD_FRAME → close
        }
        let mut buf = vec![0u8; n];
        if s.read_exact(&mut buf).is_err() {
            break;
        }
        let req = match parse(&buf, &Limits::request()) {
            Ok(v) => v,
            Err(_) => {
                let mut g = d.lock().unwrap();
                g.protocol_errors += 1;
                break; // BAD_JSON → close per malformed framing
            }
        };
        // Request envelope {v:1, id:Id, method, params}.
        let rm = match &req {
            Value::Obj(m) => m,
            _ => break,
        };
        let id = mget(rm, "id")
            .and_then(|x| x.as_str())
            .unwrap_or("unknown")
            .to_string();
        let method = mget(rm, "method")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let params = mget(rm, "params").cloned().unwrap_or(Value::Null);
        // Envelope checks.
        let v_ok = mget(rm, "v").map(|x| *x == Value::num(1)).unwrap_or(false);
        if !v_ok {
            let _ = write_reply(
                &mut s,
                &fault_reply(&id, &Fault::new(Code::UnsupportedVersion, "v must be 1")),
            );
            continue;
        }
        let Some(p) = &principal else {
            let _ = write_reply(
                &mut s,
                &fault_reply(&id, &Fault::new(Code::Unauthenticated, "unknown peer")),
            );
            continue;
        };
        let mut g = d.lock().unwrap();
        // Advance the daemon clock (BOOTTIME surrogate: real ms since boot
        // approximated by wall monotonic via CLOCK_BOOTTIME).
        g.now = crate::clock::boottime_ms();
        g.tick();
        let out = g.dispatch(p, &id, &method, &params);
        g.tick();
        match out {
            Outcome::Reply(rv) => {
                if write_reply(&mut s, &rv).is_err() {
                    break;
                }
            }
            Outcome::Crashed => break,
        }
    }
    cleanup(&conns, &per_principal, &principal);
}
