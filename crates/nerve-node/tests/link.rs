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
