// Writes a complete lab deployment to /tmp/watch-smoke for the live CLI smoke.
use watch::conform::*;
use watch::json::{jcs, Value};
use watch::schema::*;

use watch::conform::s as sign_fixture;

fn main() {
    let dir = std::path::Path::new("/tmp/watch-smoke");
    let argv: Vec<String> = std::env::args().collect();
    let obs_only = argv.get(1).map(|x| x.as_str()) == Some("obs");
    std::fs::create_dir_all(dir).unwrap();
    if obs_only {
        let seq: u64 = argv.get(2).and_then(|x| x.parse().ok()).unwrap_or(1);
        let prev = argv.get(3).cloned().unwrap_or_else(|| "0".repeat(64));
        write_obs(dir, seq, &prev);
        println!("obs refreshed seq={seq}");
        return;
    }
    for m in monitors() {
        std::fs::write(
            dir.join(format!("{}.artifact", m.detector.as_str())),
            jcs(&Value::str(m.detector.as_str())),
        )
        .unwrap();
    }
    std::fs::write(dir.join("test-key.bin"), test_key().to_bytes()).unwrap();
    std::fs::write(dir.join("object-key.bin"), [7u8; 32]).unwrap();
    // Signed policy body for `watchctl policy sign` is produced by the
    // daemon fixture; here we write the UNSIGNED policy body so the CLI
    // signs it live.
    // Smoke policy: fixture P but with a 120 s freshness window so the
    // multi-step CLI flow doesn't trip source-silence mid-run. The
    // conformance vectors still use the canonical P (freshness 2000).
    let mut pol = policy_p();
    pol.freshness_ms = 120_000;
    std::fs::write(dir.join("policy.json"), jcs(&policy_value(&pol))).unwrap();
    std::fs::write(dir.join("intent.json"), jcs(&intent_value(&intent_i()))).unwrap();
    write_obs(dir, 1, &"0".repeat(64));

    let art = |name: &str| {
        Value::obj(vec![
            ("detector", Value::str(name)),
            (
                "digest",
                Value::str(&watch::crypto::d("artifact", &Value::str(name))),
            ),
            (
                "path",
                Value::str(&format!("/tmp/watch-smoke/{name}.artifact")),
            ),
        ])
    };
    let principal = |id: &str, uid: u64, roles: &[&str]| {
        Value::obj(vec![
            ("id", Value::str(id)),
            ("uid", Value::num(uid)),
            (
                "roles",
                Value::Arr(roles.iter().map(|r| Value::str(r)).collect()),
            ),
        ])
    };
    let cfg = Value::obj(vec![
        ("v", Value::num(1)),
        ("tenant", Value::str("tenant1")),
        ("deployment", Value::str("lab")),
        ("socket", Value::str("/tmp/watch-smoke/control.sock")),
        ("data_dir", Value::str("/tmp/watch-smoke")),
        (
            "signer",
            Value::obj(vec![
                ("key_id", Value::str("test_key")),
                ("key_epoch", Value::ustr("1")),
                ("key_file", Value::str("/tmp/watch-smoke/test-key.bin")),
            ]),
        ),
        ("trust_file", Value::str("/tmp/watch-smoke/trust.json")),
        (
            "principals",
            Value::Arr(vec![
                principal("runtime1", 1002, &["runtime"]),
                principal("reviewer1", 1004, &["reviewer"]),
                principal("operator1", 1003, &["operator"]),
                principal("auditor1", 1005, &["auditor"]),
            ]),
        ),
        (
            "sources",
            Value::Arr(vec![Value::obj(vec![
                ("id", Value::str("source1")),
                ("runtime", Value::str("runtime1")),
                ("key_id", Value::str("test_key")),
                ("key_epoch", Value::ustr("1")),
                ("epoch", Value::ustr("1")),
                ("profile", Value::str("fixture/1")),
            ])]),
        ),
        (
            "installed_artifacts",
            Value::Arr(vec![
                art("scope"),
                art("spend"),
                art("replicas"),
                art("rate"),
                art("distribution"),
            ]),
        ),
        (
            "certified_profiles",
            Value::Arr(vec![Value::str("fixture/1")]),
        ),
        ("release", Value::Null),
        (
            "storage",
            Value::obj(vec![
                ("max_bytes", Value::ustr("10737418240")),
                ("warn_bp", Value::num(8000)),
                ("stop_bp", Value::num(9500)),
                ("raw_days", Value::num(7)),
                ("audit_days", Value::num(365)),
                ("object_key_id", Value::str("object_key1")),
                (
                    "object_key_file",
                    Value::str("/tmp/watch-smoke/object-key.bin"),
                ),
            ]),
        ),
    ]);
    std::fs::write(dir.join("config.json"), jcs(&cfg)).unwrap();
    let trust = Value::obj(vec![
        ("v", Value::num(1)),
        ("tenant", Value::str("tenant1")),
        (
            "keys",
            Value::Arr(vec![Value::obj(vec![
                ("id", Value::str("test_key")),
                ("public_key", Value::str(&pub_key())),
                (
                    "tags",
                    Value::Arr(vec![
                        Value::str("audit"),
                        Value::str("backup"),
                        Value::str("bundle"),
                        Value::str("clearance"),
                        Value::str("effect"),
                        Value::str("observation"),
                        Value::str("policy"),
                    ]),
                ),
                (
                    "subjects",
                    Value::Arr(vec![
                        Value::str("runtime1"),
                        Value::str("source1"),
                        Value::str("tenant1"),
                    ]),
                ),
                ("from_epoch", Value::ustr("1")),
                ("through_epoch", Value::Null),
                ("live", Value::Bool(true)),
                ("compromised", Value::Bool(false)),
            ])]),
        ),
        (
            "sources",
            Value::Arr(vec![Value::obj(vec![
                ("id", Value::str("source1")),
                ("runtime", Value::str("runtime1")),
                ("key_id", Value::str("test_key")),
                ("key_epoch", Value::ustr("1")),
                ("epoch", Value::ustr("1")),
                ("profile", Value::str("fixture/1")),
            ])]),
        ),
        (
            "minimum_head",
            Value::obj(vec![
                ("seq", Value::ustr("0")),
                ("hash", Value::str(&"0".repeat(64))),
            ]),
        ),
    ]);
    std::fs::write(dir.join("trust.json"), jcs(&trust)).unwrap();

    // audit.evaluate input (EI-style): two rows, one dangerous/flagged.
    let rows = Value::Arr(vec![
        Value::obj(vec![
            ("unit", Value::str("u1")),
            ("cluster", Value::str("c1")),
            ("truth", Value::str("dangerous")),
            ("watcher", Value::str("flag")),
            ("human", Value::str("clear")),
            ("prevention", Value::str("blocked")),
            ("late", Value::Bool(false)),
            ("review", Value::Bool(false)),
        ]),
        Value::obj(vec![
            ("unit", Value::str("u2")),
            ("cluster", Value::str("c2")),
            ("truth", Value::str("benign")),
            ("watcher", Value::str("clear")),
            ("human", Value::str("clear")),
            ("prevention", Value::str("dispatched")),
            ("late", Value::Bool(false)),
            ("review", Value::Bool(false)),
        ]),
    ]);
    std::fs::write(
        dir.join("eval.json"),
        jcs(&Value::obj(vec![
            ("id", Value::str("wte_smoke1")),
            ("dataset", Value::str(&watch::crypto::d("dataset", &rows))),
            // policy field takes the activated policy digest; mk_smoke
            // cannot know it — the smoke script patches it in.
            ("policy", Value::str(&"0".repeat(64))),
            ("split", Value::str("heldout")),
            ("sampling", Value::str("census")),
            ("independent_units", Value::Bool(true)),
            ("population_count", Value::ustr("2")),
            ("rows", rows.clone()),
        ])),
    )
    .unwrap();
    // audit.sample params.
    let pop = Value::Arr(vec![
        Value::str("u1"),
        Value::str("u2"),
        Value::str("u3"),
        Value::str("u4"),
        Value::str("u5"),
        Value::str("u6"),
        Value::str("u7"),
        Value::str("u8"),
    ]);
    std::fs::write(
        dir.join("sample.json"),
        jcs(&Value::obj(vec![
            ("population", pop.clone()),
            (
                "population_digest",
                Value::str(&watch::crypto::d("population", &pop)),
            ),
            (
                "seed",
                Value::str(&watch::crypto::d("seed", &Value::str("smoke1"))),
            ),
            ("k", Value::num(3)),
        ])),
    )
    .unwrap();
    println!("smoke env written to /tmp/watch-smoke; pub={}", pub_key());
}

/// (Re)write observation.json / oref.json / check.json at the live clock.
/// freshness_ms=2000 means the smoke must regenerate these right before
/// `observe`, never minutes earlier.
fn write_obs(dir: &std::path::Path, seq: u64, prev: &str) {
    let now_ms = watch::clock::boottime_ms();
    let boot =
        watch::clock::boot_id().unwrap_or_else(|_| "00000000-0000-4000-8000-000000000000".into());
    let mut ob = observation_body_o();
    ob.cut_ms = now_ms;
    ob.boot = boot.clone();
    ob.run = "wtr_smoke1".into();
    ob.seq = seq;
    ob.prev = prev.to_string();
    let obs = sign_fixture("observation", &observation_body_value(&ob));
    std::fs::write(dir.join("observation.json"), jcs(&obs)).unwrap();
    let oref = Value::obj(vec![
        ("source", Value::str("source1")),
        ("epoch", Value::ustr("1")),
        ("seq", Value::ustr(&seq.to_string())),
        (
            "hash",
            Value::str(obs.get("digest").unwrap().as_str().unwrap()),
        ),
    ]);
    std::fs::write(dir.join("oref.json"), jcs(&oref)).unwrap();
    std::fs::write(
        dir.join("check.json"),
        jcs(&Value::obj(vec![
            ("id", Value::str("wtc_smoke1")),
            ("run", Value::str("wtr_smoke1")),
            ("intent", intent_value(&intent_i())),
            ("observation", oref.clone()),
            ("review", Value::Null),
        ])),
    )
    .unwrap();
}
