//! A real node daemon against the conformance fake center, in process:
//! pairing, handshake, describe, an `fs.read` that an allow rule lets through
//! and one that no rule allows, folder mode where allow rules do not count,
//! the 401 stop, and the conformance node checks.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nerve_conformance::fake_center::{self, FakeCenter};
use nerve_conformance::wire::{Conn, Recv};
use nerve_node::{Daemon, NodeOptions, NodePaths};
use nerve_policy::NodeConfig;
use nerve_proto::rpc::Message;
use serde_json::{Value, json};
use tokio::net::TcpStream;

const WAIT: Duration = Duration::from_secs(15);

fn tempdir() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

fn options(root: &Path) -> NodeOptions {
    let mut o = NodeOptions::new(NodePaths::new(root.join("config"), root.join("state")));
    o.home = root.join("home");
    std::fs::create_dir_all(&o.home).unwrap();
    // NERVE_NODE_BIN lets the built tests run on another machine.
    o.exe = Some(
        std::env::var_os("NERVE_NODE_BIN")
            .map(Into::into)
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_nerve-node").into()),
    );
    o
}

/// Pairs with `center` and starts the daemon.
async fn paired_node(root: &Path, center: &FakeCenter) -> Daemon {
    paired_node_with(root, center, |_| {}).await
}

/// Like [`paired_node`], with `policy` changed before the daemon starts.
async fn paired_node_with(
    root: &Path,
    center: &FakeCenter,
    policy: impl Fn(&mut nerve_policy::CenterPolicy),
) -> Daemon {
    let o = options(root);
    nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
        .await
        .expect("pair");
    owner_edit(&o.paths, |c| policy(&mut c.centers[0].policy)).await;
    Daemon::start(o).await.expect("start")
}

/// Changes the config the way the owner does while no daemon runs: through
/// the CLI's settings store, which signs the file. The node refuses a file it
/// did not sign.
async fn owner_edit(paths: &NodePaths, f: impl Fn(&mut NodeConfig)) {
    nerve_node::cli::edit(paths, |c| {
        f(c);
        Ok(())
    })
    .await
    .expect("the owner's edit");
}

/// Accepts the node's link and runs the handshake.
async fn linked(center: &mut FakeCenter) -> Conn<TcpStream> {
    let paired = center.paired().expect("paired");
    let mut inc = center.next_link(WAIT).await.expect("the node dials");
    assert_eq!(inc.node_header, paired.node_id);
    let hello = fake_center::handshake(&mut inc.conn, &center.center_id, &paired)
        .await
        .expect("handshake");
    assert_eq!(hello.node_id, paired.node_id);
    assert!(hello.versions.iter().any(|v| v == "0"));
    inc.conn
}

#[tokio::test(flavor = "multi_thread")]
async fn handshake_describe_and_an_allowed_read() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let home = std::fs::canonicalize(&home).unwrap();
    // A new center is in default deny: an allow rule lets the read through.
    let node = paired_node_with(dir.path(), &center, |p| {
        assert_eq!(p.mode, nerve_policy::Mode::Allowlist);
        p.allow
            .push(format!("fs.read:{}/*", nerve_policy::paths::to_wire(&home)));
    })
    .await;
    let mut conn = linked(&mut center).await;

    let d = conn
        .call("describe", json!({"detail": "full"}), WAIT)
        .await
        .unwrap()
        .expect("describe");
    let caps = d["capabilities"].as_array().expect("caps");
    let cap = |id: &str| caps.iter().find(|c| c["id"] == id);
    // Only what a rule can allow is offered: a rule for reads shows no exec.
    for c in ["node", "fs", "audit"] {
        assert!(cap(c).is_some(), "missing {c}: {d}");
    }
    assert!(cap("exec").is_none(), "no rule covers exec: {d}");
    let fs_actions = cap("fs").unwrap()["actions"].as_object().unwrap();
    assert_eq!(fs_actions.keys().collect::<Vec<_>>(), ["read"]);
    assert!(cap("settings").is_none(), "settings needs the write grant");
    assert_eq!(cap("fs").unwrap()["exposure"], "on");

    let file = home.join("note.txt");
    std::fs::write(&file, "hello center").unwrap();
    let read = conn
        .call(
            "invoke",
            json!({"cap": "fs", "action": "read", "args": {"path": nerve_policy::paths::to_wire(&file)}}),
            WAIT,
        )
        .await
        .unwrap()
        .expect("the folder allows the read");
    assert_eq!(read["content"], "hello center");
    assert_eq!(read["encoding"], "utf8");
    // The rule is for reads; the write is a call no rule allows.
    let e = conn
        .call(
            "invoke",
            json!({"cap": "fs", "action": "write",
                   "args": {"path": nerve_policy::paths::to_wire(&file), "content": "x"}}),
            WAIT,
        )
        .await
        .unwrap()
        .expect_err("no rule allows the write");
    assert_eq!(nerve_conformance::wire::code_of(&e), "forbidden");

    // The local audit log names the center and the decision.
    let log = std::fs::read_to_string(node.paths().audit_log()).unwrap();
    assert!(log.contains("\"allowed\""), "{log}");
    assert!(log.contains("lab"), "{log}");

    node.stop().await;
    assert!(
        conn.ends_within(WAIT).await.is_some(),
        "stop ends the link with bye"
    );
}

/// The next `node.descriptor_changed` on `conn`: its rev.
async fn changed_rev(conn: &mut Conn<TcpStream>) -> u64 {
    loop {
        match conn.recv(WAIT).await {
            Recv::Msg(Message::Notification { method: m, params }) if m == "event" => {
                if params["cap"] == "node" && params["name"] == "descriptor_changed" {
                    return params["data"]["rev"].as_u64().expect("a rev");
                }
            }
            Recv::Msg(_) => {}
            other => panic!("no descriptor_changed: {other:?}"),
        }
    }
}

/// The tools a center can build: `cap.action` of the full descriptor.
async fn offered(conn: &mut Conn<TcpStream>) -> (u64, Vec<String>) {
    let d = conn
        .call("describe", json!({"detail": "full"}), WAIT)
        .await
        .unwrap()
        .expect("describe");
    let mut out = Vec::new();
    for c in d["capabilities"].as_array().unwrap() {
        if matches!(c["id"].as_str(), Some("fs" | "exec")) {
            for a in c["actions"].as_object().unwrap().keys() {
                out.push(format!("{}.{a}", c["id"].as_str().unwrap()));
            }
        }
    }
    (d["rev"].as_u64().expect("a rev"), out)
}

/// Under default deny the center is shown only the actions a rule covers;
/// an added or removed rule moves the rev and the node tells the center.
#[tokio::test(flavor = "multi_thread")]
async fn a_rule_edit_changes_what_the_center_is_offered() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let node = paired_node(dir.path(), &center).await;
    let mut conn = linked(&mut center).await;
    let (rev0, tools) = offered(&mut conn).await;
    assert!(tools.is_empty(), "{tools:?}");

    owner_edit(node.paths(), |c| {
        c.centers[0].policy.allow = vec!["exec.run:git *".into()];
    })
    .await;
    let rev1 = changed_rev(&mut conn).await;
    assert_ne!(rev1, rev0);
    assert_eq!(offered(&mut conn).await, (rev1, vec!["exec.run".into()]));

    owner_edit(node.paths(), |c| {
        c.centers[0].policy.allow.clear();
    })
    .await;
    assert_eq!(changed_rev(&mut conn).await, rev0);
    assert_eq!(offered(&mut conn).await, (rev0, vec![]));
    node.stop().await;
}

/// No folder and no rule allows the read, so the node refuses it at once: it
/// does not wait for anyone, and nothing is asked.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_no_rule_allows_is_refused_immediately() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let node = paired_node(dir.path(), &center).await;
    let mut conn = linked(&mut center).await;
    let file = dir.path().join("home").join("x.txt");
    std::fs::write(&file, "x").unwrap();
    // Well inside the 15 s a held call would take to time out the wait.
    let e = conn
        .call(
            "invoke",
            json!({"cap": "fs", "action": "read", "args": {"path": nerve_policy::paths::to_wire(&file)}}),
            Duration::from_secs(5),
        )
        .await
        .unwrap()
        .expect_err("no rule allows the read");
    assert_eq!(nerve_conformance::wire::code_of(&e), "forbidden");

    let log = std::fs::read_to_string(node.paths().audit_log()).unwrap();
    assert!(log.contains("\"forbidden\""), "{log}");
    assert!(!log.contains("\"asked\""), "{log}");
    node.stop().await;
}

/// In folder mode the folders give full access and allow rules change
/// nothing; a deny rule still refuses.
#[tokio::test(flavor = "multi_thread")]
async fn allow_rules_do_not_count_in_folder_mode_and_deny_rules_do() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let home = std::fs::canonicalize(&home).unwrap();
    let inside = home.join("in");
    let elsewhere = dir.path().join("elsewhere");
    std::fs::create_dir_all(&inside).unwrap();
    std::fs::create_dir_all(&elsewhere).unwrap();
    let elsewhere = std::fs::canonicalize(&elsewhere).unwrap();
    for (d, name) in [
        (&inside, "a.txt"),
        (&inside, "secret.txt"),
        (&elsewhere, "b.txt"),
    ] {
        std::fs::write(d.join(name), "x").unwrap();
    }
    let wire = |p: &Path| nerve_policy::paths::to_wire(p);
    let node = paired_node_with(dir.path(), &center, |p| {
        p.mode = nerve_policy::Mode::Folder;
        p.folders.push(nerve_policy::config::Folder {
            path: inside.display().to_string(),
            access: nerve_policy::config::Access::parse("r").unwrap(),
        });
        p.allow.push(format!("fs:{}/*", wire(&elsewhere)));
        p.deny
            .push(format!("fs:{}", wire(&inside.join("secret.txt"))));
    })
    .await;
    let mut conn = linked(&mut center).await;
    let mut read = async |p: &Path| {
        conn.call(
            "invoke",
            json!({"cap": "fs", "action": "read", "args": {"path": wire(p)}}),
            WAIT,
        )
        .await
        .unwrap()
    };
    assert!(read(&inside.join("a.txt")).await.is_ok(), "the folder");
    let e = read(&elsewhere.join("b.txt")).await.unwrap_err();
    assert_eq!(nerve_conformance::wire::code_of(&e), "forbidden");
    let e = read(&inside.join("secret.txt")).await.unwrap_err();
    assert_eq!(nerve_conformance::wire::code_of(&e), "forbidden");
    node.stop().await;
}

/// Starts `sleep 2` under `policy`, sends `exec.signal kill` for it and
/// returns the signal's answer, the run's answer and the audit log.
#[cfg(unix)]
async fn signal_a_sleep(
    policy: impl Fn(&mut nerve_policy::CenterPolicy),
) -> (Result<Value, String>, Value, String) {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let node = paired_node_with(dir.path(), &center, policy).await;
    let mut conn = linked(&mut center).await;
    let run = conn
        .request(
            "invoke",
            json!({"cap": "exec", "action": "run", "args": {"command": "sleep 2"}}),
        )
        .await
        .unwrap();
    // Long enough for the command to start and be known by its call id.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let signal = conn
        .call(
            "invoke",
            json!({"cap": "exec", "action": "signal", "args": {"call": run, "signal": "kill"}}),
            WAIT,
        )
        .await
        .unwrap()
        .map_err(|e| nerve_conformance::wire::code_of(&e));
    let mut others = Vec::new();
    let ran = conn
        .answer(run, WAIT, &mut others)
        .await
        .unwrap()
        .expect("the command ran");
    let log = std::fs::read_to_string(node.paths().audit_log()).unwrap();
    node.stop().await;
    (signal, ran, log)
}

/// `exec.signal` goes through the policy like every other action: a deny
/// rule refuses it and the refusal is audited.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_deny_rule_refuses_exec_signal_and_the_audit_says_so() {
    let (signal, ran, log) = signal_a_sleep(|p| {
        p.allow.push("exec.run:sleep *".into());
        p.deny.push("exec.signal".into());
    })
    .await;
    assert_eq!(signal, Err("forbidden".into()), "{log}");
    assert_eq!(ran["exit_code"], 0, "the command was not killed: {ran}");
    let line = log
        .lines()
        .find(|l| l.contains("\"signal\""))
        .unwrap_or_else(|| panic!("no audit line for the signal: {log}"));
    assert!(line.contains("\"forbidden\""), "{line}");

    // An allow rule lets it through, and that is audited too.
    let (signal, ran, log) = signal_a_sleep(|p| {
        p.allow.push("exec.run:sleep *".into());
        p.allow.push("exec.signal".into());
    })
    .await;
    assert_eq!(signal, Ok(json!({})), "{log}");
    assert_eq!(ran["signal"], "kill", "{ran}");
    let line = log
        .lines()
        .find(|l| l.contains("\"signal\""))
        .unwrap_or_else(|| panic!("no audit line for the signal: {log}"));
    assert!(line.contains("\"allowed\""), "{line}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_node_answer_stops_dialling() {
    let dir = tempdir();
    let center = FakeCenter::start(false).await.unwrap();
    let o = options(dir.path());
    nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
        .await
        .unwrap();
    // A second center that never paired this node answers 401.
    let stranger = FakeCenter::start(false).await.unwrap();
    let url = format!("http://{}", stranger.url.authority());
    owner_edit(&o.paths, |c| c.centers[0].url = url.clone()).await;

    let node = Daemon::start(o).await.unwrap();
    let mut marked = false;
    for _ in 0..100 {
        if node.config().centers[0].unknown {
            marked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        marked,
        "the node marks the center and stops: {}",
        node.status()
    );
    let status = node.status();
    let c: &Value = &status["centers"][0];
    assert_eq!(c["unknown"], true);
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn passes_the_conformance_node_checks() {
    let dir = tempdir();
    let root = dir.path().to_path_buf();
    let running: Arc<Mutex<Option<Daemon>>> = Arc::default();
    let keep = running.clone();
    let report = nerve_conformance::node_part::run(move |link| async move {
        let o = options(&root);
        nerve_node::pair::pair(&o.paths, &link, None).await?;
        let d = Daemon::start(o).await?;
        *keep.lock().unwrap() = Some(d);
        Ok(nerve_conformance::node_part::Setup::default())
    })
    .await;
    let d = running.lock().unwrap().take();
    if let Some(d) = d {
        d.stop().await;
    }
    assert!(report.ok(), "{report}");
}

#[tokio::test(flavor = "multi_thread")]
async fn folder_mode_confines_commands_to_their_folders() {
    if !nerve_sandbox::Confinement::detect().available() {
        eprintln!("skipped: Landlock is not available here");
        return;
    }
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let o = options(dir.path());
    nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
        .await
        .unwrap();
    let work = dir.path().join("home").join("work");
    std::fs::create_dir_all(&work).unwrap();
    let work = std::fs::canonicalize(&work).unwrap();
    let outside = dir.path().join("outside.txt");
    owner_edit(&o.paths, |c| {
        let p = &mut c.centers[0].policy;
        p.mode = nerve_policy::Mode::Folder;
        p.folders.push(nerve_policy::config::Folder {
            path: work.display().to_string(),
            access: nerve_policy::config::Access::ALL,
        });
    })
    .await;
    let node = Daemon::start(o).await.unwrap();
    let mut conn = linked(&mut center).await;

    let state = conn
        .call("get", json!({"cap": "exec", "keys": ["confinement"]}), WAIT)
        .await
        .unwrap()
        .expect("get");
    assert!(
        state["confinement"]
            .as_str()
            .unwrap()
            .starts_with("landlock"),
        "{state}"
    );
    let command = format!(
        "sh -c 'echo in > inside.txt; echo out > {}'",
        outside.display()
    );
    let r = conn
        .call(
            "invoke",
            json!({"cap": "exec", "action": "run",
                   "args": {"command": command, "cwd": work.display().to_string()}}),
            WAIT,
        )
        .await
        .unwrap()
        .expect("the command runs");
    assert_ne!(r["exit_code"], 0, "{r}");
    assert_eq!(
        std::fs::read_to_string(work.join("inside.txt")).unwrap(),
        "in\n"
    );
    assert!(
        !outside.exists(),
        "the write outside the folder was blocked"
    );
    node.stop().await;
}

/// Whether process `pid` still runs (a zombie does not count).
#[cfg(target_os = "linux")]
fn running(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| {
        s.rsplit_once(')')
            .is_some_and(|(_, rest)| !rest.trim_start().starts_with('Z'))
    })
}

/// The pid a command wrote to `file`, once it is there.
#[cfg(target_os = "linux")]
async fn pid_in(file: &Path) -> u32 {
    for _ in 0..200 {
        if let Ok(t) = std::fs::read_to_string(file)
            && let Ok(pid) = t.trim().parse()
        {
            return pid;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("no pid in {}", file.display())
}

/// `session.end` stops the commands of that session the way a timeout does:
/// the call fails `cancelled` and its processes are gone within seconds. A
/// command of another session keeps running until its own cancel.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_session_end_stops_the_commands_of_that_session() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let node = paired_node_with(dir.path(), &center, |p| {
        p.mode = nerve_policy::Mode::User;
    })
    .await;
    let mut conn = linked(&mut center).await;
    let home = dir.path().join("home");
    let run = |session: &str, file: &str| {
        json!({"cap": "exec", "action": "run",
               "args": {"command": format!("sleep 30 & echo $! > {file}; wait")},
               "ctx": {"session": session}})
    };
    let ended = conn
        .request("invoke", run("s-ended", "ended.pid"))
        .await
        .unwrap();
    let other = conn
        .request("invoke", run("s-other", "other.pid"))
        .await
        .unwrap();
    let ended_pid = pid_in(&home.join("ended.pid")).await;
    let other_pid = pid_in(&home.join("other.pid")).await;

    conn.notify("session.end", json!({"session": "s-ended"}))
        .await
        .unwrap();
    let mut others = Vec::new();
    let e = conn
        .answer(ended, WAIT, &mut others)
        .await
        .unwrap()
        .expect_err("the session's call ends");
    assert_eq!(nerve_conformance::wire::code_of(&e), "cancelled");
    let gone = |pid| async move {
        for _ in 0..100 {
            if !running(pid) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    };
    assert!(gone(ended_pid).await, "the session's command outlived it");
    assert!(running(other_pid), "another session's command was stopped");

    conn.notify("cancel", json!({"id": other})).await.unwrap();
    let e = conn
        .answer(other, WAIT, &mut others)
        .await
        .unwrap()
        .expect_err("cancelled");
    assert_eq!(nerve_conformance::wire::code_of(&e), "cancelled");
    assert!(
        gone(other_pid).await,
        "a cancelled command outlived its call"
    );
    node.stop().await;
}
