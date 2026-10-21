//! Root as the owner on a real machine (issue #151): `install` run by root
//! itself makes root the owner only after a yes at a terminal or with
//! `--owner=root --accept-root-owner`; piped input and a no leave the node
//! without one, so `user` mode runs nothing. With root as the owner a
//! `user` mode command, and one of `allowlist` mode as the owner, runs as
//! root; `folder` mode still runs as `nerve-run`. For a test machine only,
//! as root and without sudo: it installs the node as a service and removes
//! it again.
//!
//! `NERVE_NODE_REAL=<the nerve-node to install> cargo test -p nerve-node
//! --test real_root_owner -- --ignored --nocapture`

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use nerve_conformance::fake_center::{self, FakeCenter};
use nerve_conformance::wire::Conn;
use serde_json::{Value, json};
use tokio::net::TcpStream;

const WAIT: Duration = Duration::from_secs(20);
const BIN: &str = "/usr/local/bin/nerve-node";
const UNIT: &str = "/etc/systemd/system/nerve-node.service";

/// `cmd` run as root with `input` on stdin (piped, no terminal), without
/// `SUDO_USER`: as root runs it itself.
fn typing(cmd: &mut Command, input: &str) -> (bool, String) {
    use std::io::Write;
    let mut child = cmd
        .env_remove("SUDO_USER")
        .env_remove("PKEXEC_UID")
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("starts");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let o = child.wait_with_output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    (o.status.success(), text)
}

fn sh(cmd: &mut Command) -> (bool, String) {
    typing(cmd, "")
}

/// `install` of `exe` with `args` at a terminal (`script` gives it one),
/// answering `answer`.
fn install_at_a_terminal(exe: &Path, args: &str, answer: &str) -> (bool, String) {
    typing(
        Command::new("script").args([
            "-qec",
            &format!("{} install {args}", exe.display()),
            "/dev/null",
        ]),
        answer,
    )
}

fn owner_in_unit() -> Option<String> {
    std::fs::read_to_string(UNIT)
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("Environment=NERVE_NODE_OWNER="))
        .map(String::from)
}

fn status() -> Value {
    let (_, st) = sh(Command::new(BIN).args(["--json", "status"]));
    serde_json::from_str(st.trim()).unwrap_or_else(|e| panic!("{e}: {st}"))
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

/// The node's next link to `center`, once the handshake is through.
async fn linked(center: &mut FakeCenter) -> Conn<TcpStream> {
    let paired = center.paired().expect("paired");
    let mut inc = center.next_link(WAIT).await.expect("the node dials");
    fake_center::handshake(&mut inc.conn, &center.center_id, &paired)
        .await
        .expect("handshake");
    inc.conn
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "installs the node on this machine as root; NERVE_NODE_REAL names it"]
async fn root_is_the_owner_only_when_it_says_so() {
    let Some(exe) = std::env::var_os("NERVE_NODE_REAL").map(PathBuf::from) else {
        eprintln!("NERVE_NODE_REAL is not set");
        return;
    };
    assert_eq!(nerve_transport::net::euid(), 0, "run it as root");
    assert!(!Path::new(UNIT).exists(), "the node is installed already");
    let question = "Make root the owner of this node? [y/N]";

    // Piped input is no terminal: nothing is asked, and there is no owner.
    let (ok, said) = typing(Command::new(&exe).arg("install"), "y\n");
    assert!(ok, "{said}");
    assert!(!said.contains(question), "{said}");
    assert!(said.contains("Warning: no owner"), "{said}");
    assert!(said.contains("--owner=root --accept-root-owner"), "{said}");
    assert_eq!(owner_in_unit(), None);
    // At a terminal, a no: no owner either, and user mode runs nothing.
    let (ok, said) = install_at_a_terminal(&exe, "", "n\n");
    assert!(ok, "{said}");
    assert!(said.contains(question), "{said}");
    assert!(
        said.contains("nothing in Nerve can hold them back"),
        "{said}"
    );
    assert!(said.contains("Warning: no owner"), "{said}");
    assert_eq!(owner_in_unit(), None);
    assert_eq!(status()["owner_is_root"], false);

    // A center paired by root, in user mode, and a folder of root's.
    let work = Path::new("/srv/nrv151");
    let _ = std::fs::remove_dir_all(work);
    std::fs::create_dir_all(work).unwrap();
    let secret = Path::new("/srv/nrv151-secret");
    std::fs::write(secret, "nobody's\n").unwrap();
    assert!(sh(Command::new("chown").args(["nobody:nogroup"]).arg(secret)).0);
    assert!(sh(Command::new("chmod").arg("600").arg(secret)).0);
    let mut center = FakeCenter::start(false).await.unwrap();
    let link = center.link().render();
    let (ok, said) = sh(Command::new(BIN).args(["center", "add", &link, "--yes"]));
    assert!(ok, "{said}");
    let (ok, said) = sh(Command::new(BIN).args(["mode", "set", "user"]));
    assert!(ok, "{said}");
    let mut conn = linked(&mut center).await;
    let e = run(&mut conn, work, "id -u").await.unwrap_err();
    assert!(e.contains("this node has no owner"), "{e}");
    drop(conn);

    // Either flag alone is refused before anything changes.
    let (ok, said) = sh(Command::new(&exe).args(["install", "--owner=root"]));
    assert!(!ok && said.contains("go together"), "{said}");
    assert_eq!(owner_in_unit(), None);

    // At a terminal, a yes: root is the owner, needs no polkit, and status
    // says so.
    let (ok, said) = install_at_a_terminal(&exe, "", "y\n");
    assert!(ok, "{said}");
    assert!(said.contains(question), "{said}");
    assert!(
        said.contains("Warning: root is the owner of the node, as you confirmed"),
        "{said}"
    );
    assert_eq!(owner_in_unit().as_deref(), Some("root"));
    assert!(!Path::new("/etc/polkit-1/rules.d/50-nerve-node.rules").exists());
    assert!(!Path::new("/usr/local/lib/nerve-node/service-control").exists());
    let st = status();
    assert_eq!(st["owner"], "root", "{st}");
    assert_eq!(st["owner_is_root"], true, "{st}");
    let (_, text) = sh(Command::new(BIN).arg("status"));
    assert!(
        text.contains("owner: root is the owner: commands of user mode"),
        "{text}"
    );
    assert!(text.contains("mode user, as root"), "{text}");

    // User mode runs as root, with root's home.
    let mut conn = linked(&mut center).await;
    let r = run(&mut conn, work, "id -u").await.unwrap();
    assert_eq!(out(&r), "0\n", "{r}");
    let r = run(&mut conn, work, "printenv HOME").await.unwrap();
    assert_eq!(out(&r), "/root\n", "{r}");
    // Root as the owner can do what root can, beyond what the node itself
    // may: read another account's private file.
    let r = run(&mut conn, work, &format!("cat {}", secret.display()))
        .await
        .unwrap();
    assert_eq!(out(&r), "nobody's\n", "{r}");

    // Allowlist mode as the owner runs as root too, as nerve-run without.
    assert!(sh(Command::new(BIN).args(["rule", "add", "allow", "id -u"])).0);
    assert!(sh(Command::new(BIN).args(["mode", "set", "allowlist", "--as-owner"])).0);
    let r = run(&mut conn, work, "id -u").await.unwrap();
    assert_eq!(out(&r), "0\n", "{r}");
    assert!(sh(Command::new(BIN).args(["mode", "set", "allowlist"])).0);
    let run_uid = sh(Command::new("id").args(["-u", "nerve-run"])).1;
    let r = run(&mut conn, Path::new("/tmp"), "id -u").await.unwrap();
    assert_eq!(out(&r), run_uid, "{r}");

    // Folder mode runs as nerve-run, in the folder root gives it.
    assert!(sh(Command::new(BIN).args(["mode", "set", "folder"])).0);
    let (ok, said) = sh(Command::new(BIN).args(["folder", "add", "/srv/nrv151", "+rwx"]));
    assert!(ok, "{said}");
    let r = run(&mut conn, work, "id -un").await.unwrap();
    assert_eq!(out(&r), "nerve-run\n", "{r}");
    let r = run(&mut conn, work, "touch made-by-run").await.unwrap();
    assert_eq!(r["exit_code"], 0, "{r}");
    let r = run(&mut conn, work, &format!("cat {}", secret.display())).await;
    let shown = r.as_ref().map(out).unwrap_or_else(|e| e.clone());
    assert!(!shown.contains("nobody's"), "{shown}");
    drop(conn);

    // Without a terminal, the flags keep root the owner; without them an
    // install drops it.
    let (ok, said) =
        sh(Command::new(&exe).args(["install", "--owner=root", "--accept-root-owner"]));
    assert!(ok, "{said}");
    assert!(!said.contains(question), "{said}");
    assert_eq!(owner_in_unit().as_deref(), Some("root"));
    let (ok, said) = sh(Command::new(&exe).arg("install"));
    assert!(ok, "{said}");
    assert!(said.contains("root is no longer the owner"), "{said}");
    assert_eq!(owner_in_unit(), None);

    // Removed again, with everything it made.
    let (ok, said) = sh(Command::new(BIN).args(["uninstall", "--purge"]));
    assert!(ok, "{said}");
    assert!(!sh(Command::new("id").arg("nerve-run")).0);
    assert!(!sh(Command::new("id").arg("nerve")).0);
    assert!(!Path::new("/etc/nerve").exists());
    assert!(!Path::new("/var/lib/nerve").exists());
    assert!(!Path::new(UNIT).exists());
    let _ = std::fs::remove_dir_all(work);
    let _ = std::fs::remove_file(secret);
}
