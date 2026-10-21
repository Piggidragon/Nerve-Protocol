//! The installed node on a real machine: `install` makes `nerve-run` and
//! names the owner, a folder-mode command of a center runs as `nerve-run`
//! with the folder the owner gives it (a POSIX ACL), `/tmp` and its own home,
//! and nothing else of the owner's; the owner socket refuses it; `folder rm`
//! takes the ACL off; `uninstall` removes the account, its home and every
//! entry (issue #142). For a test machine only, as root: it installs the
//! node as a service and removes it again.
//!
//! `NERVE_NODE_REAL=<the nerve-node to install> NERVE_REAL_OWNER=<an account
//! with a home, the owner> cargo test -p nerve-node --test real_account --
//! --ignored --nocapture`

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use nerve_conformance::fake_center::{self, FakeCenter};
use nerve_conformance::wire::Conn;
use serde_json::{Value, json};
use tokio::net::TcpStream;

const WAIT: Duration = Duration::from_secs(20);
const BIN: &str = "/usr/local/bin/nerve-node";

fn sh(cmd: &mut Command) -> (bool, String) {
    let o = cmd.output().expect("starts");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    (o.status.success(), text)
}

/// The installed program, run as `owner` (through the owner socket).
fn as_owner(owner: &str, args: &[&str]) -> (bool, String) {
    sh(Command::new("runuser")
        .args(["-u", owner, "--", BIN])
        .args(args)
        .current_dir("/"))
}

fn getfacl(p: &Path) -> String {
    sh(Command::new("getfacl").args(["-p", "-n"]).arg(p)).1
}

/// The `exec.run` of `command` in `cwd`, as a center sends it: its result,
/// or the refusal.
async fn run(conn: &mut Conn<TcpStream>, cwd: &Path, command: &str) -> Result<Value, String> {
    conn.call(
        "invoke",
        json!({"cap": "exec", "action": "run", "args": {
            "command": command, "cwd": cwd.display().to_string()}}),
        WAIT,
    )
    .await
    .expect("an answer")
    .map_err(|e| e.message)
}

fn out(v: &Value) -> String {
    format!(
        "{}{}",
        v["stdout"].as_str().unwrap_or_default(),
        v["stderr"].as_str().unwrap_or_default()
    )
}

/// Waits until `f` holds, for up to 15 s.
fn until(what: &str, f: impl Fn() -> bool) {
    for _ in 0..150 {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("{what} did not happen");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "installs the node on this machine; NERVE_NODE_REAL and NERVE_REAL_OWNER name it"]
async fn folder_mode_runs_as_nerve_run_on_this_machine() {
    let (Some(exe), Some(owner)) = (
        std::env::var_os("NERVE_NODE_REAL").map(PathBuf::from),
        std::env::var("NERVE_REAL_OWNER").ok(),
    ) else {
        eprintln!("NERVE_NODE_REAL or NERVE_REAL_OWNER is not set");
        return;
    };
    assert_eq!(nerve_transport::net::euid(), 0, "run it as root");
    let home =
        sh(Command::new("sh").args(["-c", &format!("getent passwd {owner} | cut -d: -f6")])).1;
    let home = PathBuf::from(home.trim());
    assert!(home.is_dir(), "{home:?}");

    // Install, as the owner's sudo would: the owner is named, nerve-run is
    // made with its home.
    let (ok, said) = sh(Command::new(&exe).arg("install").env("SUDO_USER", &owner));
    assert!(ok, "{said}");
    assert!(
        said.contains(&format!("{owner} is the owner of the node")),
        "{said}"
    );
    let (ok, id) = sh(Command::new("id").arg("nerve-run"));
    assert!(ok, "{id}");
    assert!(!id.contains("sudo") && !id.contains("docker"), "{id}");
    let unit = std::fs::read_to_string("/etc/systemd/system/nerve-node.service").unwrap();
    assert!(
        unit.contains(&format!("Environment=NERVE_NODE_OWNER={owner}")),
        "{unit}"
    );
    let run_home = Path::new("/var/lib/nerve-run");
    let (_, st) = sh(Command::new("stat").args(["-c", "%U %a"]).arg(run_home));
    assert_eq!(st.trim(), "nerve-run 700");
    // An update keeps the account.
    let (_, said) = sh(Command::new(BIN).args(["update", "--from"]).arg(&exe));
    assert!(
        said.contains("nothing to update") || said.contains("replaced"),
        "{said}"
    );
    assert!(sh(Command::new("id").arg("nerve-run")).0);

    // The owner's files: a folder to give, a file of each kind it does not
    // give, and a socket in a folder of its own.
    let base = home.join("nerve-real");
    let _ = std::fs::remove_dir_all(&base);
    let proj = base.join("proj");
    let private = base.join("private");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::create_dir_all(&private).unwrap();
    std::fs::write(proj.join("given.txt"), "given\n").unwrap();
    std::fs::write(base.join("open.txt"), "open-secret\n").unwrap();
    std::fs::write(base.join("closed.txt"), "closed-secret\n").unwrap();
    let sock = private.join("session.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let chown = |p: &Path| {
        assert!(
            sh(Command::new("chown")
                .args(["-R", &format!("{owner}:{owner}")])
                .arg(p))
            .0
        );
    };
    chown(&base);
    let chmod = |p: &Path, m: &str| assert!(sh(Command::new("chmod").arg(m).arg(p)).0);
    chmod(&home, "750");
    chmod(&base, "755");
    chmod(&base.join("open.txt"), "644");
    chmod(&base.join("closed.txt"), "600");
    chmod(&private, "700");
    // What a command reaches the owner socket with, by a path the guard
    // does not see.
    std::fs::write(
        proj.join("ask.py"),
        r#"import json, socket
s = socket.socket(socket.AF_UNIX)
s.connect("/run/" + "nerve-node/owner.sock")
s.sendall((json.dumps({"method": "cli", "params": {"args": ["mode", "set", "user"], "cwd": "/"}}) + "\n").encode())
print(s.makefile().readline())
"#,
    )
    .unwrap();
    std::fs::write(
        proj.join("dial.py"),
        format!(
            r#"import socket
s = socket.socket(socket.AF_UNIX)
try:
    s.connect("{}")
    print("connected")
except OSError as e:
    print("refused:", e.strerror)
"#,
            sock.display()
        ),
    )
    .unwrap();
    // One program per call: allowlist mode, where Landlock is missing,
    // runs no chained command line.
    std::fs::write(proj.join("who.sh"), "#!/bin/sh\nid -un\necho \"$HOME\"\n").unwrap();
    std::fs::write(
        proj.join("rw.sh"),
        "#!/bin/sh\nset -e\ncat given.txt\necho made > made.txt\ncat made.txt\necho t > /tmp/nerve-real-t\ncat /tmp/nerve-real-t\nrm /tmp/nerve-real-t\necho h > \"$HOME/h\"\ncat \"$HOME/h\"\n",
    )
    .unwrap();
    chown(&proj);
    for script in ["who.sh", "rw.sh"] {
        chmod(&proj.join(script), "755");
    }

    // The owner pairs and gives the folder, without sudo.
    let mut center = FakeCenter::start(false).await.unwrap();
    let link = center.link().render();
    let (ok, said) = as_owner(&owner, &["center", "add", &link, "--yes"]);
    assert!(ok, "{said}");
    let (ok, said) = as_owner(&owner, &["folder", "add", proj.to_str().unwrap(), "+rwx"]);
    assert!(ok, "{said}");
    let (_, ls) = as_owner(&owner, &["--json", "center", "ls"]);
    let ls: Value = serde_json::from_str(ls.trim()).unwrap();
    assert_eq!(ls["centers"][0]["mode"], "folder", "{ls}");
    let name = ls["centers"][0]["name"].as_str().unwrap().to_string();
    // Without Landlock folder mode runs no command; allowlist mode runs them
    // as nerve-run all the same, held by its account alone.
    let landlock = nerve_sandbox::Confinement::detect().landlock_abi.is_some();
    if !landlock {
        eprintln!("no Landlock here: allowlist mode, every command allowed");
        let key = format!("center.{name}.policy.allow");
        let (ok, said) = as_owner(&owner, &["mode", "set", "allowlist"]);
        assert!(ok, "{said}");
        let (ok, said) = as_owner(&owner, &["config", "add", &key, "exec.run:*"]);
        assert!(ok, "{said}");
    }
    let paired = center.paired().expect("paired");
    let mut inc = center.next_link(WAIT).await.expect("the node dials");
    fake_center::handshake(&mut inc.conn, &center.center_id, &paired)
        .await
        .expect("handshake");
    let mut conn = inc.conn;

    // As nerve-run, with its own home.
    let r = run(&mut conn, &proj, "./who.sh").await.unwrap();
    assert_eq!(out(&r), "nerve-run\n/var/lib/nerve-run\n", "{r}");
    // Its folder, /tmp and its home: read and write.
    let r = run(&mut conn, &proj, "./rw.sh").await.unwrap();
    assert_eq!(r["exit_code"], 0, "{r}");
    assert_eq!(out(&r), "given\nmade\nt\nh\n", "{r}");
    // What it made is the owner's to use: the default entry.
    assert_eq!(
        std::fs::read_to_string(proj.join("made.txt")).unwrap(),
        "made\n"
    );
    let acl = getfacl(&proj.join("made.txt"));
    assert!(acl.contains("user::rw-"), "{acl}");
    let (ok, said) = sh(Command::new("runuser")
        .args(["-u", &owner, "--", "sh", "-c"])
        .arg(format!("echo more >> {}", proj.join("made.txt").display())));
    assert!(ok, "the owner writes what nerve-run made: {said}");
    // No other file of the owner's: one closed to others by its mode, and
    // with Landlock one open to them as well.
    let others: &[&str] = if landlock {
        &["open.txt", "closed.txt"]
    } else {
        &["closed.txt"]
    };
    for f in others {
        let r = run(&mut conn, &proj, &format!("cat ../{f}")).await;
        let shown = r.as_ref().map(out).unwrap_or_else(|e| e.clone());
        assert!(!shown.contains("secret"), "{f}: {shown}");
    }
    // No socket in a folder of the owner's own.
    let r = run(&mut conn, &proj, "python3 dial.py").await.unwrap();
    assert!(out(&r).contains("refused"), "{r}");
    // The owner socket refuses it: it is not the owner.
    let r = run(&mut conn, &proj, "python3 ask.py").await.unwrap();
    assert!(out(&r).contains("not the owner"), "{r}");
    let (_, ls) = as_owner(&owner, &["--json", "center", "ls"]);
    let ls: Value = serde_json::from_str(ls.trim()).unwrap();
    let mode = if landlock { "folder" } else { "allowlist" };
    assert_eq!(ls["centers"][0]["mode"], mode, "{ls}");

    // The ACLs: on the folder and below, default ones for nerve-run and the
    // owner, a pass-through one on the closed home above it.
    let run_uid = sh(Command::new("id").args(["-u", "nerve-run"]))
        .1
        .trim()
        .to_string();
    let owner_uid = sh(Command::new("id").args(["-u", &owner]))
        .1
        .trim()
        .to_string();
    let acl = getfacl(&proj);
    assert!(acl.contains(&format!("\nuser:{run_uid}:rwx")), "{acl}");
    assert!(
        acl.contains(&format!("default:user:{run_uid}:rwx")),
        "{acl}"
    );
    assert!(
        acl.contains(&format!("default:user:{owner_uid}:rwx")),
        "{acl}"
    );
    let acl = getfacl(&home);
    assert!(acl.contains(&format!("\nuser:{run_uid}:--x")), "{acl}");
    // Revoked: the entries come off.
    let (ok, said) = as_owner(&owner, &["folder", "rm", proj.to_str().unwrap()]);
    assert!(ok, "{said}");
    until("the ACL comes off", || {
        !getfacl(&proj.join("given.txt")).contains(&format!("user:{run_uid}:"))
    });
    assert!(!getfacl(&proj).contains(&format!("user:{run_uid}:")));
    assert!(!getfacl(&home).contains(&format!("user:{run_uid}:")));
    let r = run(&mut conn, &proj, "cat given.txt").await;
    let shown = r.as_ref().map(out).unwrap_or_else(|e| e.clone());
    assert!(
        !shown.contains("given\n") || shown.contains("No such"),
        "{shown}"
    );
    // Given again, for uninstall to take off.
    let (ok, said) = as_owner(&owner, &["folder", "add", proj.to_str().unwrap(), "+r"]);
    assert!(ok, "{said}");
    let r = run(&mut conn, &proj, "cat given.txt").await.unwrap();
    assert_eq!(out(&r), "given\n", "{r}");
    drop(conn);

    // Uninstall: the account, its home and every entry go.
    let (ok, said) = sh(Command::new(BIN).args(["uninstall", "--purge"]));
    assert!(ok, "{said}");
    assert!(said.contains("removed the account nerve-run"), "{said}");
    assert!(!sh(Command::new("id").arg("nerve-run")).0);
    assert!(!run_home.exists());
    for p in [&proj, &proj.join("given.txt"), &home] {
        assert!(!getfacl(p).contains(&format!("user:{run_uid}:")), "{p:?}");
    }
    std::fs::remove_dir_all(&base).unwrap();
}
