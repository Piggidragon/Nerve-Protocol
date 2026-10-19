//! The owners of the installed node change it without root (crate::owner):
//! the node runs their command as itself, with every check of the CLI, and
//! refuses what stays root's, someone who is no owner, and a confined
//! program.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::time::Duration;

use nerve_node::owner::{Endpoint, Owners};
use nerve_node::{Daemon, NodeOptions, NodePaths};
use nerve_policy::audit::AuditLog;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

fn program() -> PathBuf {
    std::env::var_os("NERVE_NODE_BIN")
        .map(Into::into)
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_nerve-node").into())
}

fn uid() -> u32 {
    // SAFETY: a plain getter.
    unsafe { libc::getuid() }
}

/// A node in `root` whose owner endpoint is `root/owner.sock`, for `owners`.
async fn node(root: &Path, owners: Vec<u32>) -> (Daemon, PathBuf) {
    let home = std::fs::canonicalize(root).unwrap();
    let paths = NodePaths::new(home.join("config"), home.join("state"));
    let mut o = NodeOptions::new(paths);
    o.home = home.clone();
    o.exe = Some(program());
    o.cgroups = Some(Err("no cgroup for this test".into()));
    let at = home.join("owner.sock");
    o.owners = Some(Endpoint {
        at: at.clone(),
        owners: Owners::Uids(owners),
        program: program(),
    });
    (Daemon::start(o).await.unwrap(), at)
}

/// What a `cli` request on `at` gave: the refusal, or the output, the
/// error output and the exit code. `input` is sent first, then its end.
async fn run(at: &Path, args: &[&str], input: &str) -> Result<(String, String, i64), String> {
    let s = UnixStream::connect(at).await.unwrap();
    let (r, mut w) = s.into_split();
    let req = json!({"method": "cli", "params": {"args": args, "cwd": "/"}});
    w.write_all(format!("{req}\n").as_bytes()).await.unwrap();
    let mut lines = BufReader::new(r).lines();
    let first: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    if let Some(e) = first["error"].as_str() {
        return Err(e.to_string());
    }
    if !input.is_empty() {
        w.write_all(format!("{}\n", json!({ "in": input })).as_bytes())
            .await
            .unwrap();
    }
    w.write_all(b"{\"eof\": true}\n").await.unwrap();
    let (mut out, mut err) = (String::new(), String::new());
    let wait = tokio::time::timeout(Duration::from_secs(60), async {
        while let Some(l) = lines.next_line().await.unwrap() {
            let v: Value = serde_json::from_str(&l).unwrap();
            if let Some(s) = v["out"].as_str() {
                out.push_str(s);
            } else if let Some(s) = v["err"].as_str() {
                err.push_str(s);
            } else if let Some(c) = v["exit"].as_i64() {
                return c;
            }
        }
        panic!("the session ended without an exit code: {out} {err}");
    });
    let code = wait.await.expect("the command ends");
    Ok((out, err, code))
}

#[tokio::test(flavor = "multi_thread")]
async fn an_owner_changes_the_node_through_it_and_is_audited() {
    let d = tempfile::tempdir().unwrap();
    let (daemon, at) = node(d.path(), vec![uid()]).await;
    let paths = daemon.paths().clone();
    // The socket is open to every account; the node decides who.
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&at).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o666);

    let (out, err, code) = run(&at, &["config", "set", "log.level", "debug"], "")
        .await
        .unwrap();
    assert_eq!(code, 0, "{out} {err}");
    assert_eq!(daemon.config().log.level.to_string(), "debug");
    // Who made it is in the audit, beside `local`.
    let me = nerve_node::account::name_of(uid()).unwrap();
    let entries = AuditLog::new(paths.audit_log()).read().unwrap();
    let last = entries
        .iter()
        .rev()
        .find(|e| e["kind"] == "settings")
        .unwrap();
    assert_eq!(last["by"], "local");
    assert_eq!(last["user"], me.as_str());

    // The input reaches a command that asks, and its question comes before
    // its line ends.
    let (out, err, code) = run(
        &at,
        &[
            "center",
            "add",
            "nerve://pair?center=https%3A%2F%2F127.0.0.1%3A9&code=abc123",
        ],
        "n\n",
    )
    .await
    .unwrap();
    assert_eq!(code, 1);
    assert!(out.contains("Pair with this center? [y/N] "), "{out} {err}");

    // What decides the account commands run as stays root's.
    let (out, err, code) = run(&at, &["config", "set", "machine.allow_root", "true"], "")
        .await
        .unwrap();
    assert_eq!(code, 1, "{out}");
    assert!(err.contains("machine.allow_root decides"), "{err}");
    assert!(!daemon.config().machine.allow_root);
    for args in [
        &["sudo", "on"][..],
        &["setup"],
        &["install"],
        &["backup", "/tmp/x"],
        &["--config-dir", "/tmp", "status"],
    ] {
        let e = run(&at, args, "").await.unwrap_err();
        assert!(
            e.contains("needs root") || e.contains("own folders"),
            "{args:?}: {e}"
        );
    }
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn someone_who_is_no_owner_and_a_confined_program_are_refused() {
    let d = tempfile::tempdir().unwrap();
    let (daemon, at) = node(d.path(), Vec::new()).await;
    let e = run(&at, &["status"], "").await.unwrap_err();
    assert!(e.contains("not in the group nerve-admin"), "{e}");
    // Anyone learns that the node runs, nothing more.
    let s = UnixStream::connect(&at).await.unwrap();
    let r = nerve_transport::ctl::call_on(s, "status", json!({})).await;
    assert_eq!(r, Ok(json!({"running": true})));
    daemon.stop().await;

    // An owner's process with no_new_privs, as every confined command of
    // the node keeps it, is refused.
    let d = tempfile::tempdir().unwrap();
    let (daemon, at) = node(d.path(), vec![uid()]).await;
    let request = json!({"method": "cli", "params": {"args": ["status"]}}).to_string();
    let mut c = std::process::Command::new("python3");
    c.args([
        "-c",
        "import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.sendall(sys.argv[2].encode()+b'\\n'); print(s.makefile().readline())",
    ])
    .arg(&at)
    .arg(&request);
    use std::os::unix::process::CommandExt;
    // SAFETY: one plain system call between fork and exec.
    unsafe {
        c.pre_exec(|| {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = tokio::task::spawn_blocking(move || c.output())
        .await
        .unwrap();
    match out {
        Ok(o) => {
            let said = String::from_utf8_lossy(&o.stdout);
            assert!(
                said.contains("comes from a command the node runs"),
                "{said}"
            );
        }
        Err(e) => eprintln!("skipped the confined caller: no python3 ({e})"),
    }
    daemon.stop().await;
}
