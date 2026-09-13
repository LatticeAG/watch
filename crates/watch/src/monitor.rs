//! Monitor worker pool (§3.4): pinned deterministic detectors executed in
//! worker threads connected by daemon-created socketpairs. Framing is the
//! same 4-byte big-endian length + canonical JSON as the control socket.
//!
//! OSS-core note: the spec's production sandbox is WASM+namespaces+seccomp;
//! the open-source pool runs the same pure detector ABI in threads with the
//! same bounded job/reply contract. The containment downgrade is explicit in
//! STATUS.md — it never weakens any detector, signature, or durability rule.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::mpsc;

use crate::fault::{Code, Fault};
use crate::json::{jcs, Value};
use crate::schema::*;

/// A completed worker job.
pub struct Completion {
    pub job: String,
    pub monitor: String,
    pub result: Result<Result_, String>,
}

pub struct WorkerPool {
    streams: Vec<UnixStream>,
    completions: mpsc::Receiver<Completion>,
    next: usize,
    pub enabled: bool,
}

fn read_frame(s: &mut UnixStream) -> Option<Vec<u8>> {
    let mut lenb = [0u8; 4];
    s.read_exact(&mut lenb).ok()?;
    let len = u32::from_be_bytes(lenb) as usize;
    if len == 0 || len > crate::REQ_MAX {
        return None;
    }
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf).ok()?;
    Some(buf)
}

fn write_frame(s: &mut UnixStream, v: &Value) -> std::io::Result<()> {
    let b = jcs(v).into_bytes();
    s.write_all(&(b.len() as u32).to_be_bytes())?;
    s.write_all(&b)
}

/// Evaluate a parsed MonitorJob into a MonitorReply value.
fn evaluate_job(v: &Value) -> Result<Value, Fault> {
    monitor_job(v)?;
    let monitor = monitor(v.get("monitor").unwrap())?;
    let policy = policy(v.get("policy").unwrap())?;
    let osv = signed(v.get("observation").unwrap())?;
    let body = observation_body(&osv.body)?;
    let intent_v = v.get("intent").unwrap();
    let int = if *intent_v == Value::Null {
        None
    } else {
        Some(intent(intent_v)?)
    };
    let drift_v = v.get("drift").unwrap();
    let dr = if *drift_v == Value::Null {
        None
    } else {
        Some(drift(drift_v)?)
    };
    // Blocking detectors with null intent are invalid jobs (§3.4).
    if int.is_none()
        && matches!(
            monitor.detector,
            Detector::Scope | Detector::Spend | Detector::Replicas
        )
    {
        return Err(Fault::new(
            Code::SchemaInvalid,
            "blocking monitor needs intent",
        ));
    }
    let obs_ref = Ref {
        source: body.source.clone(),
        epoch: body.epoch,
        seq: body.seq,
        hash: osv.digest.clone(),
    };
    let r = crate::detect::evaluate(
        &monitor,
        &policy,
        &body,
        Some(obs_ref),
        int.as_ref(),
        dr.as_ref(),
    );
    Ok(Value::obj(vec![
        ("v", Value::num(1)),
        ("job", v.get("job").unwrap().clone()),
        ("result", result_value(&r)),
    ]))
}

/// Worker thread: reads framed MonitorJob, replies framed MonitorReply.
fn worker_loop(mut sock: UnixStream) {
    while let Some(buf) = read_frame(&mut sock) {
        let reply = match crate::json::parse(&buf, &crate::json::Limits::request()) {
            Ok(v) => match evaluate_job(&v) {
                Ok(r) => r,
                Err(e) => Value::obj(vec![
                    ("v", Value::num(1)),
                    ("job", v.get("job").cloned().unwrap_or(Value::str("?"))),
                    ("error", Value::str(&e.message)),
                ]),
            },
            Err(_) => continue,
        };
        if write_frame(&mut sock, &reply).is_err() {
            return;
        }
    }
}

/// Reader thread: forwards framed replies to the completion channel.
fn reader_loop(mut sock: UnixStream, done: mpsc::Sender<Completion>) {
    while let Some(buf) = read_frame(&mut sock) {
        let Ok(v) = crate::json::parse(&buf, &crate::json::Limits::request()) else {
            continue;
        };
        let job = v
            .get("job")
            .and_then(|x| x.as_str())
            .unwrap_or("?")
            .to_string();
        let comp = match v.get("result") {
            Some(rv) => match result(rv) {
                Ok(r) => Completion {
                    monitor: r.monitor.clone(),
                    job,
                    result: Ok(r),
                },
                Err(e) => Completion {
                    monitor: "?".into(),
                    job,
                    result: Err(e.message),
                },
            },
            None => Completion {
                monitor: "?".into(),
                job,
                result: Err(v
                    .get("error")
                    .and_then(|x| x.as_str())
                    .unwrap_or("worker error")
                    .to_string()),
            },
        };
        if done.send(comp).is_err() {
            return;
        }
    }
}

impl WorkerPool {
    /// `n` workers on real socketpairs; `enabled=false` simulates an
    /// unreachable pool (jobs pend to deadline — the partition op).
    pub fn new(n: usize, enabled: bool) -> WorkerPool {
        let (done_tx, done_rx) = mpsc::channel();
        let mut streams = Vec::new();
        for _ in 0..(if enabled { n.max(1) } else { 0 }) {
            let (main_side, worker_side) = match UnixStream::pair() {
                Ok(p) => p,
                Err(_) => break,
            };
            let reader_side = match main_side.try_clone() {
                Ok(s) => s,
                Err(_) => break,
            };
            std::thread::spawn(move || worker_loop(worker_side));
            let dtx = done_tx.clone();
            std::thread::spawn(move || reader_loop(reader_side, dtx));
            streams.push(main_side);
        }
        WorkerPool {
            streams,
            completions: done_rx,
            next: 0,
            enabled,
        }
    }

    /// Dispatch one MonitorJob (framed canonical bytes). False if disabled.
    pub fn dispatch(&mut self, _job_id: &str, _monitor_id: &str, job: &Value) -> bool {
        if !self.enabled || self.streams.is_empty() {
            return false;
        }
        let i = self.next % self.streams.len();
        self.next += 1;
        write_frame(&mut self.streams[i], job).is_ok()
    }

    /// Drain completed replies (nonblocking).
    pub fn drain(&self) -> Vec<Completion> {
        let mut out = Vec::new();
        while let Ok(c) = self.completions.try_recv() {
            out.push(c);
        }
        out
    }
}
