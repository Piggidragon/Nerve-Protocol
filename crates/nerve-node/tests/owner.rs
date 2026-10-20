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
    // its line ends. (It asks only when the link can pair: a center that
    // answers, with its code open.)
    let center = nerve_conformance::fake_center::FakeCenter::start(false)
        .await
        .unwrap();
    let (out, err, code) = run(&at, &["center", "add", &center.link().render()], "n\n")
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
        &["--config-dir", "/tmp", "status"],
    ] {
        let e = run(&at, args, "").await.unwrap_err();
        assert!(
            e.contains("needs root") || e.contains("own folders"),
            "{args:?}: {e}"
        );
    }
    // A backup or restore only with the file the owner's program opened: the
    // node never opens the path itself.
    for args in [&["backup", "/tmp/x"][..], &["restore", "/tmp/x"]] {
        let e = run(&at, args, "").await.unwrap_err();
        assert!(e.contains("comes with the request"), "{args:?}: {e}");
    }
    daemon.stop().await;
}

const PASS: &str = "correct horse battery";

/// What a backup or restore through the owner socket at `at` did: its exit
/// code and output. The node is told `path` (the file the command names),
/// while `file` is the one this process opens and hands over.
async fn with_file(
    at: &Path,
    args: &[&str],
    file: nerve_node::owner::FileJob,
) -> Result<(i32, String), String> {
    let conn = UnixStream::connect(at).await.unwrap();
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut io = nerve_node::owner::Io {
        out: &mut out,
        err: &mut err,
    };
    let code =
        nerve_node::owner::send_file(conn, &args, Some("/".into()), &file, PASS, &mut io).await?;
    Ok((
        code,
        String::from_utf8_lossy(&out).into_owned() + &String::from_utf8_lossy(&err),
    ))
}

fn job(path: &Path, backup: Option<bool>) -> nerve_node::owner::FileJob {
    nerve_node::owner::FileJob {
        path: path.to_path_buf(),
        backup,
        passphrase_file: None,
    }
}

/// An owner backs up and restores without root: the file is opened by the
/// owner's own program and handed to the node, which writes and reads only
/// that (the path it is told leads nowhere). A restore stops the node,
/// which starts again after it; one that would change a setting that stays
/// root's is refused (owner's decision of 2026-10-20, item 14).
#[tokio::test(flavor = "multi_thread")]
async fn an_owner_backs_up_and_restores_with_a_file_of_their_own() {
    let d = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(d.path()).unwrap();
    let paths = NodePaths::new(home.join("config"), home.join("state"));
    let mut o = NodeOptions::new(paths.clone());
    o.home = home.clone();
    o.exe = Some(program());
    o.cgroups = Some(Err("no cgroup for this test".into()));
    let at = home.join("owner.sock");
    o.owners = Some(Endpoint {
        at: at.clone(),
        owners: Owners::Uids(vec![uid()]),
        program: program(),
    });
    let (stop, events) = tokio::sync::mpsc::unbounded_channel();
    let node = tokio::spawn(Daemon::run_until(o, events));
    let up = || async {
        for _ in 0..200 {
            if UnixStream::connect(&at).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the node did not come up");
    };
    up().await;
    let (_, _, code) = run(&at, &["config", "set", "log.level", "debug"], "")
        .await
        .unwrap();
    assert_eq!(code, 0);

    let mine = home.join("mine");
    std::fs::create_dir(&mine).unwrap();
    let file = mine.join("node.backup");
    let nowhere = "/nonexistent-nerve-test/node.backup";
    let (code, said) = with_file(&at, &["backup", nowhere], job(&file, Some(false)))
        .await
        .unwrap();
    assert_eq!(code, 0, "{said}");
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(&file).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    let first = std::fs::read(&file).unwrap();
    assert_eq!(
        nerve_transport::backup::kind_of(&first).unwrap(),
        nerve_transport::backup::Kind::Node
    );
    // Not over a file that is there, unless asked; then through a new file
    // and a rename, which leaves nothing beside it.
    let e = with_file(&at, &["backup", nowhere], job(&file, Some(false)))
        .await
        .unwrap_err();
    assert!(e.contains("exists already"), "{e}");
    let (code, said) = with_file(
        &at,
        &["backup", nowhere, "--overwrite"],
        job(&file, Some(true)),
    )
    .await
    .unwrap();
    assert_eq!(code, 0, "{said}");
    assert_ne!(std::fs::read(&file).unwrap(), first);
    assert_eq!(std::fs::read_dir(&mine).unwrap().count(), 1);

    // The restore: the node stops for it and comes back with what it put
    // back.
    let (_, _, code) = run(&at, &["config", "set", "log.level", "warn"], "")
        .await
        .unwrap();
    assert_eq!(code, 0);
    let (code, said) = with_file(&at, &["restore", nowhere], job(&file, None))
        .await
        .unwrap();
    assert_eq!(code, 0, "{said}");
    assert!(
        said.contains("The node starts again with it now."),
        "{said}"
    );
    up().await;
    let (out, _, _) = run(&at, &["config", "get", "log.level"], "").await.unwrap();
    assert!(out.contains("debug"), "{out}");

    // A backup that picks another shell for the commands is root's to
    // restore; the node runs on.
    let other = home.join("other");
    let other_paths = NodePaths::new(other.join("config"), other.join("state"));
    let opts = |a: &[&str]| {
        let mut v = vec![
            "nerve-node".to_string(),
            "--config-dir".into(),
            other_paths.config_dir.display().to_string(),
            "--state-dir".into(),
            other_paths.state_dir.display().to_string(),
        ];
        v.extend(a.iter().map(|s| s.to_string()));
        <nerve_node::cli::Cli as clap::Parser>::try_parse_from(v).unwrap()
    };
    let pass_file = home.join("pass");
    nerve_transport::files::write_private(&pass_file, format!("{PASS}\n").as_bytes()).unwrap();
    let mut said = Vec::new();
    nerve_node::cli::execute(
        opts(&["config", "set", "machine.shell", "/bin/bash"]),
        &mut said,
    )
    .await
    .unwrap();
    let shell_backup = mine.join("shell.backup");
    nerve_node::cli::execute(
        opts(&[
            "backup",
            shell_backup.to_str().unwrap(),
            "--passphrase-file",
            pass_file.to_str().unwrap(),
        ]),
        &mut said,
    )
    .await
    .unwrap();
    let (code, said) = with_file(
        &at,
        &["restore", nowhere, "--replace"],
        job(&shell_backup, None),
    )
    .await
    .unwrap();
    assert_eq!(code, 1, "{said}");
    assert!(
        said.contains(nerve_node::owner::RESTORE_BY_ADMIN) && said.contains("machine.shell"),
        "{said}"
    );
    up().await;
    let (out, _, _) = run(&at, &["config", "get", "machine.shell"], "")
        .await
        .unwrap();
    assert!(!out.contains("/bin/bash"), "{out}");

    stop.send(nerve_node::Event::Stop).unwrap();
    node.await.unwrap().unwrap();
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
