//! A real node daemon against the conformance fake center, in process:
//! pairing, handshake, describe, an `fs.read` that an allow rule lets through
//! and one that no rule allows, folder mode where allow rules do not count,
//! the 401 stop, and the conformance node checks.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nerve_conformance::fake_center::{self, FakeCenter};
use nerve_conformance::wire::Conn;
use nerve_node::{Daemon, NodeOptions, NodePaths};
use nerve_policy::NodeConfig;
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
    // Not the rights of whoever runs the tests: an elevated run must pass.
    o.full_rights = Some(false);
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
#[cfg(unix)]
async fn changed_rev(conn: &mut Conn<TcpStream>) -> u64 {
    use nerve_conformance::wire::Recv;
    use nerve_proto::rpc::Message;
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
#[cfg(unix)]
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
/// Unix only: the rule reaches the running daemon through its control
/// socket, and Windows has none (the CLI writes the file and the
/// node takes it at its next start, docs/dev/spec/node-local.md §1).
#[cfg(unix)]
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

/// A command line longer than the node checks is refused, also with no
/// grant at all, and the audit log says why.
#[tokio::test(flavor = "multi_thread")]
async fn an_overlong_command_line_is_refused_and_audited_with_the_reason() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let node = paired_node(dir.path(), &center).await;
    let mut conn = linked(&mut center).await;
    let command = "a:".repeat(nerve_policy::COMMAND_MAX_BYTES / 2 + 1);
    let e = conn
        .call(
            "invoke",
            json!({"cap": "exec", "action": "run", "args": {"command": command}}),
            Duration::from_secs(5),
        )
        .await
        .unwrap()
        .expect_err("the command line is too long");
    assert_eq!(nerve_conformance::wire::code_of(&e), "forbidden");
    let log = std::fs::read_to_string(node.paths().audit_log()).unwrap();
    let line: Value = log
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .find(|v: &Value| v["action"] == "run")
        .unwrap_or_else(|| panic!("no audit line for the run: {log}"));
    assert_eq!(line["decision"], "forbidden", "{line}");
    let reason = line["reason"].as_str().unwrap_or_default();
    assert!(reason.contains("longer than"), "{line}");
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

/// Runs `command` in `cwd` as an `exec.run` and answers its result.
async fn run_in(conn: &mut Conn<TcpStream>, cwd: &Path, command: &str) -> Value {
    conn.call(
        "invoke",
        json!({"cap": "exec", "action": "run",
               "args": {"command": command, "cwd": cwd.display().to_string()}}),
        WAIT,
    )
    .await
    .unwrap()
    .expect("the command runs")
}

/// A command with `w` on a folder replaces a folder inside it, one with
/// rights of its own, by a link to a place no folder names (issue #74). The
/// next command's rules must not grant the nested folder's rights there:
/// Landlock follows a link in a rule's path, so the command would read and
/// write the place the link leads to.
#[tokio::test(flavor = "multi_thread")]
async fn folder_mode_gives_no_rule_where_a_command_linked_a_nested_folder() {
    if !nerve_sandbox::Confinement::detect().available() {
        eprintln!("skipped: Landlock is not available here");
        return;
    }
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let home = dir.path().join("home");
    let (work, docs) = (home.join("work"), home.join("docs"));
    std::fs::create_dir_all(work.join("bin")).unwrap();
    std::fs::create_dir_all(&docs).unwrap();
    let (work, docs) = (
        std::fs::canonicalize(&work).unwrap(),
        std::fs::canonicalize(&docs).unwrap(),
    );
    let bin = work.join("bin");
    std::fs::write(bin.join("in-bin.txt"), "bin\n").unwrap();
    std::fs::write(docs.join("secret.txt"), "secret\n").unwrap();
    let node = paired_node_with(dir.path(), &center, |p| {
        p.mode = nerve_policy::Mode::Folder;
        for (path, access) in [(&work, "rwx"), (&bin, "rwx")] {
            p.folders.push(nerve_policy::config::Folder {
                path: path.display().to_string(),
                access: nerve_policy::config::Access::parse(access).unwrap(),
            });
        }
    })
    .await;
    let mut conn = linked(&mut center).await;

    // The folders as they were: `bin` is a folder like the rest.
    let r = run_in(&mut conn, &work, "cat bin/in-bin.txt").await;
    assert_eq!(r["exit_code"], 0, "{r}");
    assert_eq!(r["stdout"], "bin\n", "{r}");

    // The command swaps `bin` for a link to `docs`, which `work` allows.
    let swap = format!("rm -rf bin && ln -s {} bin", docs.display());
    let r = run_in(&mut conn, &work, &swap).await;
    assert_eq!(r["exit_code"], 0, "{r}");
    assert!(std::fs::symlink_metadata(&bin).unwrap().is_symlink());

    // The next command gets nothing for `docs` from the rights of `bin`.
    let r = run_in(&mut conn, &work, "cat bin/secret.txt").await;
    assert_ne!(r["exit_code"], 0, "{r}");
    assert!(!r["stdout"].as_str().unwrap().contains("secret"), "{r}");
    let r = run_in(&mut conn, &work, "echo planted > bin/planted.txt").await;
    assert_ne!(r["exit_code"], 0, "{r}");
    assert!(!docs.join("planted.txt").exists());
    // `work` keeps its own rights.
    let r = run_in(&mut conn, &work, "echo fine > fresh.txt").await;
    assert_eq!(r["exit_code"], 0, "{r}");
    assert_eq!(
        std::fs::read_to_string(work.join("fresh.txt")).unwrap(),
        "fine\n"
    );
    node.stop().await;
}

/// A folder mode command that started with the keys in files is counted for as
/// long as its `exec.run` runs: a move of the keys into the keyring is refused
/// meanwhile and nothing moves, and the count is 0 again once the call
/// answered. The count is checked before the move is asked for, so a node that
/// does not count the command fails here without writing to the machine's
/// keyring. The test, not a timer, ends the command, once the refusal was
/// checked: a command that ended on its own before the move was asked for (a
/// slow machine) would let the move go into the real keyring.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn the_keys_do_not_move_into_the_keyring_past_a_running_folder_command() {
    let Some(abi) = nerve_sandbox::Confinement::detect().landlock_abi else {
        eprintln!("skipped: Landlock is not available here");
        return;
    };
    // Below ABI 9 the keys never go into the keyring, whatever runs.
    if abi < 9 {
        eprintln!("skipped: Landlock ABI {abi} here, below 9, keeps the keys in files");
        return;
    }
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let work = dir.path().join("home").join("work");
    std::fs::create_dir_all(&work).unwrap();
    let work = std::fs::canonicalize(&work).unwrap();
    let node = paired_node_with(dir.path(), &center, |p| {
        p.mode = nerve_policy::Mode::Folder;
        p.folders.push(nerve_policy::config::Folder {
            path: work.display().to_string(),
            access: nerve_policy::config::Access::ALL,
        });
    })
    .await;
    let mut conn = linked(&mut center).await;
    let paths = node.paths().clone();
    // Waits for `release`, bounded to about 30 s so a broken test does not
    // hang for good; it fails if it was not released.
    let command = "sh -c 'echo > started; i=0; \
                   while [ ! -e release ] && [ $i -lt 600 ]; do sleep 0.05; i=$((i+1)); done; \
                   [ -e release ]'";
    let run = conn
        .request(
            "invoke",
            json!({"cap": "exec", "action": "run",
                   "args": {"command": command, "cwd": work.display().to_string()}}),
        )
        .await
        .unwrap();
    let started = work.join("started");
    for _ in 0..200 {
        if started.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(started.exists(), "the command did not start");
    assert_eq!(node.open_to_bus(), 1, "the running command is not counted");

    let files = || {
        [
            paths.config_file(),
            paths.config_key(),
            paths.key_file("lab"),
        ]
        .map(|f| std::fs::read(f).unwrap())
    };
    let before = files();
    let e = nerve_node::cli::edit(&paths, |c| {
        c.machine.secret_storage = nerve_policy::config::SecretStorage::Keyring;
        Ok(())
    })
    .await
    .expect_err("the keys moved past a running command");
    assert!(e.contains("1 folder mode command runs"), "{e}");
    assert!(e.contains("nothing was changed"), "{e}");
    assert_eq!(files(), before);
    assert!(!paths.keys_moving().exists());
    assert_eq!(
        node.config().machine.secret_storage,
        nerve_policy::config::SecretStorage::File
    );

    assert_eq!(
        node.open_to_bus(),
        1,
        "the command ended before its release"
    );

    std::fs::write(work.join("release"), b"").unwrap();
    let mut others = Vec::new();
    let ran = conn
        .answer(run, WAIT, &mut others)
        .await
        .unwrap()
        .expect("the command ran");
    assert_eq!(ran["exit_code"], 0, "{ran}");
    assert_eq!(
        node.open_to_bus(),
        0,
        "the command is counted after it ended"
    );
    node.stop().await;
}

/// A walk (`grep`, `find`, `list`) leaves out what a direct read would refuse:
/// a folder inside a readable one that has no `r` stays sealed, while the
/// readable files beside it are still found.
#[tokio::test(flavor = "multi_thread")]
async fn walks_skip_a_nested_folder_without_the_read_flag() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let data = dir.path().join("home").join("data");
    let private = data.join("private");
    std::fs::create_dir_all(private.join("deep")).unwrap();
    let data = std::fs::canonicalize(&data).unwrap();
    let private = data.join("private");
    std::fs::write(data.join("open.txt"), "token: public\n").unwrap();
    std::fs::write(private.join("creds.txt"), "token: classified\n").unwrap();
    std::fs::write(private.join("deep/more.txt"), "token: classified too\n").unwrap();
    let wire = |p: &Path| nerve_policy::paths::to_wire(p);
    let node = paired_node_with(dir.path(), &center, |p| {
        p.mode = nerve_policy::Mode::Folder;
        for (path, access) in [(&data, "r"), (&private, "")] {
            p.folders.push(nerve_policy::config::Folder {
                path: path.display().to_string(),
                access: nerve_policy::config::Access::parse(access).unwrap(),
            });
        }
    })
    .await;
    let mut conn = linked(&mut center).await;
    let mut call = async |action: &str, args: Value| {
        conn.call(
            "invoke",
            json!({"cap": "fs", "action": action, "args": args}),
            WAIT,
        )
        .await
        .unwrap()
    };

    // The direct read is refused, which is the decision the walks must follow.
    let e = call("read", json!({"path": wire(&private.join("creds.txt"))}))
        .await
        .unwrap_err();
    assert_eq!(nerve_conformance::wire::code_of(&e), "forbidden");

    let g = call("grep", json!({"path": wire(&data), "pattern": "token"}))
        .await
        .expect("grep");
    let text = g.to_string();
    assert!(text.contains("open.txt") && text.contains("public"), "{g}");
    assert!(
        !text.contains("classified") && !text.contains("private"),
        "grep reached the sealed folder: {g}"
    );

    let f = call("find", json!({"path": wire(&data), "glob": "**/*.txt"}))
        .await
        .expect("find");
    let text = f.to_string();
    assert!(text.contains("open.txt"), "{f}");
    assert!(
        !text.contains("creds") && !text.contains("more.txt") && !text.contains("private"),
        "find reached the sealed folder: {f}"
    );

    let l = call("list", json!({"path": wire(&data)}))
        .await
        .expect("list");
    let names: Vec<_> = l["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["open.txt"], "{l}");
    node.stop().await;
}

/// A walk passes through a sealed folder to a folder with `r` inside it and
/// finds the files there, but nothing of the sealed folder's own.
#[tokio::test(flavor = "multi_thread")]
async fn walks_reach_a_readable_folder_inside_a_sealed_one() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let data = dir.path().join("home").join("data");
    std::fs::create_dir_all(data.join("private/pub")).unwrap();
    let data = std::fs::canonicalize(&data).unwrap();
    let private = data.join("private");
    let public = private.join("pub");
    std::fs::write(private.join("creds.txt"), "token: classified\n").unwrap();
    std::fs::write(public.join("note.txt"), "token: shared\n").unwrap();
    let wire = |p: &Path| nerve_policy::paths::to_wire(p);
    let node = paired_node_with(dir.path(), &center, |p| {
        p.mode = nerve_policy::Mode::Folder;
        for (path, access) in [(&data, "r"), (&private, ""), (&public, "r")] {
            p.folders.push(nerve_policy::config::Folder {
                path: path.display().to_string(),
                access: nerve_policy::config::Access::parse(access).unwrap(),
            });
        }
    })
    .await;
    let mut conn = linked(&mut center).await;
    let mut call = async |action: &str, args: Value| {
        conn.call(
            "invoke",
            json!({"cap": "fs", "action": action, "args": args}),
            WAIT,
        )
        .await
        .unwrap()
    };

    let g = call("grep", json!({"path": wire(&data), "pattern": "token"}))
        .await
        .expect("grep");
    let paths: Vec<_> = g["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["path"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(paths, [wire(&public.join("note.txt"))], "{g}");

    let f = call("find", json!({"path": wire(&data), "glob": "**/*.txt"}))
        .await
        .expect("find");
    assert_eq!(f["paths"], json!([wire(&public.join("note.txt"))]), "{f}");

    // A listing names its folders, so the sealed one stays out of it.
    let l = call("list", json!({"path": wire(&data)}))
        .await
        .expect("list");
    assert_eq!(l["entries"], json!([]), "{l}");
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
