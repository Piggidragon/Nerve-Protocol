//! The program itself with `--json` (docs/user/commands.md): a program that
//! drives it reads every answer from stdout, an error too, since stderr
//! also carries the log's events.

use std::process::Command;

fn node(dir: &std::path::Path, args: &[&str]) -> (bool, serde_json::Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_nerve-node"))
        .arg("--config-dir")
        .arg(dir.join("config"))
        .arg("--state-dir")
        .arg(dir.join("state"))
        .arg("--json")
        .args(args)
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let v = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{e}: {text:?}"));
    (out.status.success(), v)
}

#[test]
fn every_answer_is_json_on_stdout() {
    let d = tempfile::tempdir().unwrap();
    let (ok, v) = node(d.path(), &["status"]);
    assert!(ok, "{v}");
    assert_eq!(v["daemon"], "not running", "{v}");
    let (ok, v) = node(d.path(), &["mode", "set", "user"]);
    assert!(!ok, "{v}");
    let e = v["error"].as_str().unwrap();
    assert!(e.contains("center"), "{e}");
}

/// A passphrase comes on stdin when that is no terminal, unasked, so the
/// answer on stdout stays JSON.
#[test]
fn a_passphrase_on_stdin_is_taken_without_a_question() {
    use std::io::Write;
    let d = tempfile::tempdir().unwrap();
    let file = d.path().join("node.backup");
    let mut child = Command::new(env!("CARGO_BIN_EXE_nerve-node"))
        .arg("--config-dir")
        .arg(d.path().join("config"))
        .arg("--state-dir")
        .arg(d.path().join("state"))
        .args(["--json", "backup"])
        .arg(&file)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"correct horse battery\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(out.status.success(), "{text}");
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert!(!v["messages"].as_array().unwrap().is_empty(), "{v}");
    assert!(!text.contains("Passphrase"), "{text}");
    assert!(file.is_file());
}
