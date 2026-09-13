//! watchctl — the operator/runtime CLI (§4/§10). Exit codes per §10.5.

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::ExitCode;

use watch::crypto::{hex_decode, sign_envelope, signing_key_from_bytes};
use watch::json::{jcs, parse, Limits, Value};
use watch::schema::*;

const DEFAULT_SOCK: &str = "/run/lattice-watch/control.sock";

struct Args {
    socket: String,
    json: bool,
    timeout_ms: u64,
    wait: bool,
    request: Option<String>,
    rest: Vec<String>,
}

fn parse_args() -> Args {
    let mut a = Args {
        socket: DEFAULT_SOCK.into(),
        json: false,
        timeout_ms: 15000,
        wait: false,
        request: None,
        rest: vec![],
    };
    let mut it = std::env::args().skip(1);
    while let Some(x) = it.next() {
        match x.as_str() {
            "--socket" => a.socket = it.next().unwrap_or_else(|| usage()),
            "--json" => a.json = true,
            "--timeout-ms" => {
                a.timeout_ms = it
                    .next()
                    .unwrap_or_else(|| usage())
                    .parse()
                    .unwrap_or(15000)
            }
            "--wait" => a.wait = true,
            "--request" => a.request = it.next(),
            "--follow" => {} // handled per-command
            "--version" => {
                println!("watchctl {} v:1", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            _ => a.rest.push(x),
        }
    }
    a
}

fn usage() -> ! {
    eprintln!(
        "usage: watchctl [--socket P] [--json] [--timeout-ms N] [--wait] [--request ID] <command>\n\
         commands: status | drain | policy sign|validate|activate |\n\
         run open|show|pause|resume|close | observe | check | check show|cancel |\n\
         effect record | review list|show|claim|next|resolve | alert list|resolve |\n\
         audit evaluate|sample | events [--follow] | export | verify | metrics |\n\
         doctor | store backup | store migrate"
    );
    std::process::exit(2);
}

fn idem() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("cli-{:x}-{:x}", std::process::id(), n)
}

fn die(msg: &str, code: u8) -> ! {
    eprintln!("{msg}");
    std::process::exit(code.into());
}

/// ISO-8601 UTC timestamp for manifests (no chrono dep).
fn chrono_now_utc() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (d, t) = (s / 86400, s % 86400);
    // Civil-from-days (Howard Hinnant).
    let z = d as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let (day, mon) = (
        doy - (153 * mp + 2) / 5 + 1,
        if mp < 10 { mp + 3 } else { mp - 9 },
    );
    let yr = if mon <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        yr,
        mon,
        day,
        t / 3600,
        (t % 3600) / 60,
        t % 60
    )
}

fn flag(args: &[String], name: &str) -> Option<String> {
    let mut it = args.iter();
    while let Some(x) = it.next() {
        if x == name {
            return it.next().cloned();
        }
        if let Some(v) = x.strip_prefix(&format!("{name}=")) {
            return Some(v.to_string());
        }
    }
    None
}

fn json_file(path: &str) -> Value {
    let s = std::fs::read_to_string(path).unwrap_or_else(|e| die(&format!("read {path}: {e}"), 2));
    parse(s.as_bytes(), &Limits::reply())
        .unwrap_or_else(|e| die(&format!("{path}: {}", e.code().as_str()), 2))
}

fn head_file(path: &str) -> Value {
    let v = json_file(path);
    match head(&v) {
        Ok(_) => v,
        Err(e) => die(&format!("{path}: bad head: {}", e.message), 2),
    }
}

/// Send one request; returns the reply value. Retries RATE_LIMITED once
/// with a fresh request id; all other faults return immediately.
fn call(a: &Args, method: &str, params: Value) -> Value {
    let mut rid = a.request.clone().unwrap_or_else(idem);
    for _attempt in 0..2 {
        let req = Value::obj(vec![
            ("v", Value::num(1)),
            ("id", Value::str(&rid)),
            ("method", Value::str(method)),
            ("params", params.clone()),
        ]);
        let body = jcs(&req).into_bytes();
        if body.len() > watch::REQ_MAX {
            die("request over 1 MiB", 2);
        }
        let mut st = match UnixStream::connect(&a.socket) {
            Ok(s) => s,
            Err(e) => die(&format!("socket {}: {e}", a.socket), 2),
        };
        st.set_read_timeout(Some(std::time::Duration::from_millis(a.timeout_ms)))
            .ok();
        let n = (body.len() as u32).to_be_bytes();
        if st.write_all(&n).is_err() || st.write_all(&body).is_err() {
            die("write", 2);
        }
        let mut lb = [0u8; 4];
        if std::io::Read::read_exact(&mut st, &mut lb).is_err() {
            die("reply frame", 2);
        }
        let len = u32::from_be_bytes(lb) as usize;
        if len > watch::REPLY_MAX {
            die("reply over 8 MiB", 2);
        }
        let mut buf = vec![0u8; len];
        if std::io::Read::read_exact(&mut st, &mut buf).is_err() {
            die("reply body", 2);
        }
        let rep = match parse(&buf, &Limits::reply()) {
            Ok(v) => v,
            Err(_) => die("bad reply", 2),
        };
        let code = rep
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(|x| x.as_str())
            .unwrap_or("");
        if code == "RATE_LIMITED" && a.request.is_none() {
            rid = idem();
            continue;
        }
        return rep;
    }
    die("retry exhausted", 2)
}

/// Print the reply and return the mapped exit code.
fn emit(a: &Args, rep: &Value) -> i32 {
    if let Some(e) = rep.get("error") {
        let code = e.get("code").and_then(|x| x.as_str()).unwrap_or("?");
        if a.json {
            println!("{}", jcs(rep));
        } else {
            eprintln!(
                "error {code}: {}",
                e.get("message").and_then(|x| x.as_str()).unwrap_or("")
            );
        }
        return watch::doctor::exit_for_code(code);
    }
    if a.json {
        println!("{}", jcs(rep.get("result").unwrap()));
    }
    0
}

fn list_params(args: &[String], default_limit: u64) -> Value {
    Value::obj(vec![
        (
            "run",
            flag(args, "--run")
                .map(|x| Value::str(&x))
                .unwrap_or(Value::Null),
        ),
        (
            "after",
            Value::str(&flag(args, "--after").unwrap_or_else(|| "0".into())),
        ),
        (
            "through",
            flag(args, "--through-file")
                .map(|f| head_file(&f))
                .unwrap_or(Value::Null),
        ),
        (
            "limit",
            Value::num(
                flag(args, "--limit")
                    .and_then(|x| x.parse().ok())
                    .unwrap_or(default_limit),
            ),
        ),
    ])
}

fn main() -> ExitCode {
    let a = parse_args();
    if a.rest.is_empty() {
        usage();
    }
    let args: Vec<String> = a.rest.clone();
    let cmd = args[0].as_str();
    let sub = args.get(1).map(|s| s.as_str());

    // Offline commands reject --socket.
    let socket_explicit = std::env::args().any(|x| x == "--socket");
    let offline = matches!(
        (cmd, sub),
        ("policy", Some("sign"))
            | ("policy", Some("validate"))
            | ("verify", _)
            | ("doctor", _)
            | ("store", Some("backup"))
            | ("store", Some("migrate"))
            | ("serve", _)
    );
    if offline && socket_explicit {
        die("--socket not permitted on offline commands", 2);
    }

    let code = match (cmd, sub) {
        ("status", _) => emit(&a, &call(&a, "system.status", Value::obj(vec![]))),
        ("drain", _) => emit(&a, &call(&a, "system.drain", Value::obj(vec![]))),
        ("check", Some("show")) => {
            let rep = call(
                &a,
                "checks.get",
                Value::obj(vec![(
                    "id",
                    Value::str(&flag(&args, "--id").unwrap_or_else(|| die("--id", 2))),
                )]),
            );
            emit(&a, &rep)
        }
        ("check", Some("cancel")) => {
            let rep = call(
                &a,
                "checks.cancel",
                Value::obj(vec![
                    (
                        "id",
                        Value::str(&flag(&args, "--id").unwrap_or_else(|| die("--id", 2))),
                    ),
                    (
                        "expected_revision",
                        Value::str(
                            &flag(&args, "--revision").unwrap_or_else(|| die("--revision", 2)),
                        ),
                    ),
                ]),
            );
            emit(&a, &rep)
        }
        ("check", _) => {
            // watchctl check --file PARAMS.json [--wait]
            let f = flag(&args, "--file").unwrap_or_else(|| die("--file required", 2));
            let params = json_file(&f);
            let id = params
                .get("id")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let rep = call(&a, "checks.create", params);
            let mut exit = emit(&a, &rep);
            if a.wait && exit == 0 {
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    let g = call(&a, "checks.get", Value::obj(vec![("id", Value::str(&id))]));
                    let r = g.get("result").cloned().unwrap_or(Value::Null);
                    let st = r.get("state").and_then(|x| x.as_str()).unwrap_or("?");
                    if a.json {
                        println!("{}", jcs(&r));
                    }
                    if matches!(
                        st,
                        "CLEAR" | "DENY" | "EXPIRED" | "HELD" | "CANCELLED" | "STALE"
                    ) {
                        exit = watch::doctor::exit_for_terminal("check", st);
                        break;
                    }
                }
            } else if exit == 0 && !a.json {
                println!("check {id} admitted (EVALUATING)");
            }
            exit
        }
        ("observe", _) => {
            let f = flag(&args, "--file").unwrap_or_else(|| die("--file required", 2));
            let rep = call(
                &a,
                "observations.append",
                Value::obj(vec![("observation", json_file(&f))]),
            );
            emit(&a, &rep)
        }
        ("effect", Some("record")) => {
            let f = flag(&args, "--file").unwrap_or_else(|| die("--file required", 2));
            let rep = call(
                &a,
                "effects.record",
                Value::obj(vec![("effect", json_file(&f))]),
            );
            emit(&a, &rep)
        }
        ("policy", Some("sign")) => {
            // Offline Ed25519 signing; key material never in argv/env —
            // --key PATH (0600 file) or --key-fd N.
            let body_f = flag(&args, "--body")
                .or_else(|| flag(&args, "--file"))
                .unwrap_or_else(|| die("--body required", 2));
            let body = json_file(&body_f);
            let raw = if let Some(fd) = flag(&args, "--key-fd") {
                use std::os::unix::io::FromRawFd;
                let fdn: i32 = fd.parse().unwrap_or_else(|_| die("bad --key-fd", 2));
                let mut buf = Vec::new();
                let mut f = unsafe { std::fs::File::from_raw_fd(fdn) };
                std::io::Read::read_to_end(&mut f, &mut buf)
                    .unwrap_or_else(|e| die(&format!("key fd: {e}"), 2));
                std::mem::forget(f);
                buf
            } else {
                let key_f = flag(&args, "--key").unwrap_or_else(|| die("--key or --key-fd", 2));
                std::fs::read(&key_f).unwrap_or_else(|e| die(&format!("key: {e}"), 2))
            };
            let sk = if raw.len() == 32 {
                signing_key_from_bytes(&raw).unwrap_or_else(|| die("bad key", 2))
            } else {
                signing_key_from_bytes(
                    &hex_decode(String::from_utf8_lossy(&raw).trim())
                        .unwrap_or_else(|| die("bad key", 2)),
                )
                .unwrap_or_else(|| die("bad key", 2))
            };
            let kid = flag(&args, "--key-id").unwrap_or_else(|| "local_key".into());
            let kepoch = flag(&args, "--key-epoch").unwrap_or_else(|| "1".into());
            let env = sign_envelope("policy", &body, &kid, &kepoch, &sk);
            if let Some(out) = flag(&args, "--out") {
                // Exclusive create, mode 0600, fsync, rename (§4).
                let tmp = format!("{out}.tmp");
                std::fs::write(&tmp, jcs(&env)).unwrap_or_else(|e| die(&format!("out: {e}"), 2));
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
                }
                if PathBuf::from(&out).exists() {
                    die("output exists — refusing overwrite", 2);
                }
                std::fs::rename(&tmp, &out).unwrap_or_else(|e| die(&format!("rename: {e}"), 2));
                println!("{out}");
            } else {
                println!("{}", jcs(&env));
            }
            0
        }
        ("policy", Some("validate")) => {
            let f = flag(&args, "--file").unwrap_or_else(|| die("--file required", 2));
            let v = json_file(&f);
            match signed(&v) {
                Ok(sv) => match policy(&sv.body) {
                    Ok(_) => {
                        if a.json {
                            println!(
                                "{}",
                                jcs(&Value::obj(vec![
                                    ("valid", Value::Bool(true)),
                                    ("digest", Value::str(&sv.digest)),
                                ]))
                            );
                        } else {
                            println!("valid:true digest:{}", sv.digest);
                        }
                        0
                    }
                    Err(e) => die(&format!("invalid: {}", e.message), 2),
                },
                Err(e) => die(&format!("invalid: {}", e.message), 2),
            }
        }
        ("policy", Some("activate")) => {
            let f = flag(&args, "--file").unwrap_or_else(|| die("--file required", 2));
            let rep = call(
                &a,
                "policy.activate",
                Value::obj(vec![
                    ("policy", json_file(&f)),
                    (
                        "expected_generation",
                        Value::str(
                            &flag(&args, "--expected-generation").unwrap_or_else(|| "0".into()),
                        ),
                    ),
                ]),
            );
            emit(&a, &rep)
        }
        ("run", Some("open")) => {
            let f = flag(&args, "--file").unwrap_or_else(|| die("--file required", 2));
            emit(&a, &call(&a, "runs.open", json_file(&f)))
        }
        ("run", Some("show")) => {
            let rep = call(
                &a,
                "runs.get",
                Value::obj(vec![(
                    "id",
                    Value::str(&flag(&args, "--id").unwrap_or_else(|| die("--id", 2))),
                )]),
            );
            emit(&a, &rep)
        }
        ("run", Some(a2 @ ("pause" | "resume" | "close"))) => {
            let rep = call(
                &a,
                "runs.control",
                Value::obj(vec![
                    (
                        "id",
                        Value::str(&flag(&args, "--id").unwrap_or_else(|| die("--id", 2))),
                    ),
                    (
                        "expected_revision",
                        Value::str(
                            &flag(&args, "--revision").unwrap_or_else(|| die("--revision", 2)),
                        ),
                    ),
                    ("action", Value::str(a2)),
                    (
                        "reason",
                        Value::str(&flag(&args, "--reason").unwrap_or_else(|| "operator".into())),
                    ),
                ]),
            );
            emit(&a, &rep)
        }
        ("review", Some("list")) => emit(&a, &call(&a, "reviews.list", list_params(&args, 20))),
        ("review", Some("show")) => {
            let rep = call(
                &a,
                "reviews.get",
                Value::obj(vec![(
                    "id",
                    Value::str(&flag(&args, "--id").unwrap_or_else(|| die("--id", 2))),
                )]),
            );
            emit(&a, &rep)
        }
        ("review", Some("claim")) => {
            let rep = call(
                &a,
                "reviews.claim",
                Value::obj(vec![
                    (
                        "id",
                        Value::str(&flag(&args, "--id").unwrap_or_else(|| die("--id", 2))),
                    ),
                    (
                        "expected_revision",
                        Value::str(
                            &flag(&args, "--revision").unwrap_or_else(|| die("--revision", 2)),
                        ),
                    ),
                ]),
            );
            emit(&a, &rep)
        }
        ("review", Some("next")) => {
            // reviews.claim with id=null/expected_revision=null; empty
            // queue exits 4 (NOT_FOUND).
            let rep = call(
                &a,
                "reviews.claim",
                Value::obj(vec![
                    ("id", Value::Null),
                    ("expected_revision", Value::Null),
                ]),
            );
            emit(&a, &rep)
        }
        ("review", Some("resolve")) => {
            let rep = call(
                &a,
                "reviews.resolve",
                Value::obj(vec![
                    (
                        "id",
                        Value::str(&flag(&args, "--id").unwrap_or_else(|| die("--id", 2))),
                    ),
                    (
                        "expected_revision",
                        Value::str(
                            &flag(&args, "--revision").unwrap_or_else(|| die("--revision", 2)),
                        ),
                    ),
                    (
                        "action",
                        Value::str(&flag(&args, "--action").unwrap_or_else(|| die("--action", 2))),
                    ),
                    (
                        "reason",
                        Value::str(&flag(&args, "--reason").unwrap_or_else(|| die("--reason", 2))),
                    ),
                    (
                        "wake_ms",
                        flag(&args, "--wake-ms")
                            .map(|x| Value::str(&x))
                            .unwrap_or(Value::Null),
                    ),
                ]),
            );
            emit(&a, &rep)
        }
        ("alert", Some("list")) => emit(&a, &call(&a, "alerts.list", list_params(&args, 20))),
        ("alert", Some("resolve")) => {
            let rep = call(
                &a,
                "alerts.resolve",
                Value::obj(vec![
                    (
                        "id",
                        Value::str(&flag(&args, "--id").unwrap_or_else(|| die("--id", 2))),
                    ),
                    (
                        "expected_revision",
                        Value::str(
                            &flag(&args, "--revision").unwrap_or_else(|| die("--revision", 2)),
                        ),
                    ),
                    (
                        "action",
                        Value::str(&flag(&args, "--action").unwrap_or_else(|| die("--action", 2))),
                    ),
                    (
                        "reason",
                        Value::str(&flag(&args, "--reason").unwrap_or_else(|| die("--reason", 2))),
                    ),
                ]),
            );
            emit(&a, &rep)
        }
        ("audit", Some("evaluate")) => {
            let f = flag(&args, "--file").unwrap_or_else(|| die("--file required", 2));
            let rep = call(
                &a,
                "audit.evaluate",
                Value::obj(vec![("input", json_file(&f))]),
            );
            emit(&a, &rep)
        }
        ("audit", Some("sample")) => {
            let f = flag(&args, "--file").unwrap_or_else(|| die("--file required", 2));
            emit(&a, &call(&a, "audit.sample", json_file(&f)))
        }
        ("events", _) => {
            let follow = a.rest.iter().any(|x| x == "--follow") || {
                // parse_args consumed it; re-scan raw argv.
                std::env::args().any(|x| x == "--follow")
            };
            let mut after = flag(&args, "--after").unwrap_or_else(|| "0".into());
            loop {
                let rep = call(
                    &a,
                    "events.read",
                    Value::obj(vec![
                        ("after", Value::str(&after)),
                        (
                            "through",
                            flag(&args, "--through-file")
                                .map(|f| head_file(&f))
                                .unwrap_or(Value::Null),
                        ),
                        (
                            "limit",
                            Value::num(
                                flag(&args, "--limit")
                                    .and_then(|x| x.parse().ok())
                                    .unwrap_or(100),
                            ),
                        ),
                    ]),
                );
                if let Some(e) = rep.get("error") {
                    let code = e.get("code").and_then(|x| x.as_str()).unwrap_or("?");
                    eprintln!("error {code}");
                    return ExitCode::from(watch::doctor::exit_for_code(code) as u8);
                }
                let res = rep.get("result").cloned().unwrap_or(Value::Null);
                if let Some(items) = res.get("items").and_then(|x| x.as_arr()) {
                    for it in items {
                        println!("{}", jcs(it));
                    }
                }
                if !follow {
                    break;
                }
                // Client-side poll cursor: last emitted seq → after.
                if let Some(nx) = res.get("next_after").and_then(|x| x.as_str()) {
                    after = nx.to_string();
                } else if let Some(items) = res.get("items").and_then(|x| x.as_arr()) {
                    if let Some(last) = items.last() {
                        if let Some(sq) =
                            last.get("seq").and_then(|x| x.as_str()).map(str::to_string)
                        {
                            after = sq;
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
            0
        }
        ("export", _) => {
            let disclosure = flag(&args, "--disclosure").unwrap_or_else(|| "COMMITMENTS".into());
            if disclosure != "FULL" && disclosure != "COMMITMENTS" {
                die("--disclosure FULL|COMMITMENTS", 2);
            }
            let through = flag(&args, "--through-file")
                .map(|f| head_file(&f))
                .unwrap_or(Value::Null);
            let rep = call(
                &a,
                "bundle.export",
                Value::obj(vec![
                    ("through", through),
                    ("disclosure", Value::str(&disclosure)),
                    (
                        "recipient",
                        Value::str(
                            &flag(&args, "--recipient").unwrap_or_else(|| die("--recipient", 2)),
                        ),
                    ),
                ]),
            );
            if let Some(out) = flag(&args, "--out") {
                if rep.get("ok") == Some(&Value::Bool(true)) {
                    let tmp = format!("{out}.tmp");
                    std::fs::write(&tmp, jcs(rep.get("result").unwrap()))
                        .unwrap_or_else(|e| die(&format!("out: {e}"), 2));
                    if PathBuf::from(&out).exists() {
                        die("output exists — refusing overwrite", 2);
                    }
                    std::fs::rename(&tmp, &out).unwrap_or_else(|e| die(&format!("rename: {e}"), 2));
                    println!("{out}");
                    0
                } else {
                    emit(&a, &rep)
                }
            } else {
                emit(&a, &rep)
            }
        }
        ("verify", _) => {
            let bundle_f = flag(&args, "--bundle").unwrap_or_else(|| die("--bundle", 2));
            let trust_f = flag(&args, "--trust").unwrap_or_else(|| die("--trust", 2));
            let bundle = json_file(&bundle_f);
            let trust_v = json_file(&trust_f);
            let t = match trust(&trust_v) {
                Ok(t) => t,
                Err(e) => die(&format!("trust: {}", e.message), 2),
            };
            let v = watch::verify::verify(&bundle, &t);
            if a.json {
                println!("{}", jcs(&v));
            } else {
                println!(
                    "{}",
                    v.get("status")
                        .and_then(|x| x.as_str())
                        .unwrap_or("INVALID")
                );
            }
            match v
                .get("status")
                .and_then(|x| x.as_str())
                .unwrap_or("INVALID")
            {
                "FULL_REPLAY" => 0,
                "INCOMPLETE" | "INTEGRITY_ONLY" => 4,
                _ => 6,
            }
        }
        ("metrics", _) => emit(&a, &call(&a, "metrics.get", Value::obj(vec![]))),
        ("doctor", _) => {
            let cfg_f = flag(&args, "--config").unwrap_or_else(|| die("--config", 2));
            let trust_f = flag(&args, "--trust").unwrap_or_else(|| die("--trust", 2));
            let r = watch::doctor::run(
                PathBuf::from(&cfg_f).as_path(),
                PathBuf::from(&trust_f).as_path(),
            );
            if a.json {
                println!("{}", jcs(&r));
            } else if let Some(cs) = r.get("checks").and_then(|x| x.as_arr()) {
                for c in cs {
                    println!(
                        "{}:{}",
                        c.get("name").and_then(|x| x.as_str()).unwrap_or("?"),
                        if c.get("ok") == Some(&Value::Bool(true)) {
                            "ok"
                        } else {
                            "fail"
                        }
                    );
                }
            }
            if r.get("ready") == Some(&Value::Bool(true)) {
                0
            } else {
                // First failing check's code drives the exit (§10.5).
                r.get("checks")
                    .and_then(|x| x.as_arr())
                    .and_then(|cs| {
                        cs.iter()
                            .find(|c| c.get("ok") == Some(&Value::Bool(false)))
                            .and_then(|c| c.get("code"))
                            .and_then(|x| x.as_str().map(str::to_string))
                    })
                    .map(|c| watch::doctor::exit_for_code(&c))
                    .unwrap_or(2)
            }
        }
        ("store", Some("backup")) => {
            let cfg_f = flag(&args, "--config").unwrap_or_else(|| die("--config", 2));
            let out = flag(&args, "--out").unwrap_or_else(|| die("--out", 2));
            let cfg = watch::config::load_config(PathBuf::from(&cfg_f).as_path())
                .unwrap_or_else(|e| die(&format!("config: {}", e.message), 2));
            let sk = watch::config::load_signer(PathBuf::from(&cfg.signer_key_file).as_path())
                .unwrap_or_else(|e| die(&format!("signer: {}", e.message), 2));
            let db = PathBuf::from(&cfg.data_dir).join("watch.db");
            let objects = PathBuf::from(&cfg.data_dir).join("objects");
            match watch::backup::backup(
                &db,
                &objects,
                PathBuf::from(&out).as_path(),
                &cfg.tenant,
                &cfg.signer_key_id,
                cfg.signer_key_epoch,
                &sk,
                &chrono_now_utc(),
            ) {
                Ok(v) => {
                    println!("{}", jcs(&v));
                    0
                }
                Err(e) => die(&format!("backup: {}", e.message), 7),
            }
        }
        ("store", Some("migrate")) => {
            let cfg_f = flag(&args, "--config").unwrap_or_else(|| die("--config", 2));
            let cfg = watch::config::load_config(PathBuf::from(&cfg_f).as_path())
                .unwrap_or_else(|e| die(&format!("config: {}", e.message), 2));
            let db = PathBuf::from(&cfg.data_dir).join("watch.db");
            match watch::backup::migrate(&db) {
                Ok(v) => {
                    println!("{}", jcs(&v));
                    0
                }
                Err(e) => {
                    println!(
                        "{}",
                        jcs(&Value::obj(vec![("code", Value::str(e.code.as_str()))]))
                    );
                    7
                }
            }
        }
        ("serve", _) => {
            // Start the local daemon in the foreground (replaces this
            // process). --lab requires deployment=lab and never relaxes
            // containment; watchd enforces that in config validation.
            let cfg_f = flag(&args, "--config").unwrap_or_else(|| die("--config", 2));
            let mut cmdline = std::process::Command::new("watchd");
            cmdline.arg("--config").arg(&cfg_f);
            if std::env::args().any(|x| x == "--lab") {
                cmdline.arg("--lab");
            }
            let err = cmdline.exec();
            die(&format!("serve: {err}"), 7);
        }
        _ => usage(),
    };
    ExitCode::from(code as u8)
}
