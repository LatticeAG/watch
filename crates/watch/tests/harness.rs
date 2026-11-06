use std::process::Command;

#[test]
fn self_test_runs_vectors_and_unknown_filter_fails() {
    let harness = env!("CARGO_BIN_EXE_watch-harness");
    let result = Command::new(harness).arg("--self-test").output().unwrap();
    assert!(result.status.success());
    assert_eq!(
        String::from_utf8(result.stdout).unwrap().trim(),
        "{\"pass\":72,\"fail\":0}"
    );

    let result = Command::new(harness)
        .arg("no-such-vector")
        .output()
        .unwrap();
    assert!(!result.status.success());
}
