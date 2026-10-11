//! A real node daemon against the conformance fake center, in process:
//! pairing, handshake, describe, an `fs.read` that the center approves, the
//! 401 stop, and the conformance node checks.

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
    o.exe = Some(env!("CARGO_BIN_EXE_nerve-node").into());
    o
}

/// Pairs with `center` and starts the daemon.
async fn paired_node(root: &Path, center: &FakeCenter) -> Daemon {
    let o = options(root);
    nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
        .await
        .expect("pair");
    Daemon::start(o).await.expect("start")
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
async fn handshake_describe_and_an_approved_read() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let node = paired_node(dir.path(), &center).await;
    let mut conn = linked(&mut center).await;

    // The descriptor in this center's view: ask mode, so fs asks.
    let d = conn
        .call("describe", json!({"detail": "full"}), WAIT)
        .await
        .unwrap()
        .expect("describe");
    let caps = d["capabilities"].as_array().expect("caps");
    let cap = |id: &str| caps.iter().find(|c| c["id"] == id);
    for c in ["node", "fs", "exec", "approvals", "audit"] {
        assert!(cap(c).is_some(), "missing {c}: {d}");
    }
    assert!(cap("settings").is_none(), "settings needs the write grant");
    assert_eq!(cap("fs").unwrap()["exposure"], "ask");

    let file = dir.path().join("home").join("note.txt");
    std::fs::write(&file, "hello center").unwrap();
    let id = conn
        .request(
            "invoke",
            json!({"cap": "fs", "action": "read", "args": {"path": file.display().to_string()}}),
        )
        .await
        .unwrap();

    // The node asks; the center answers through the approvals capability.
    let requested = loop {
        match conn.recv(WAIT).await {
            Recv::Msg(Message::Notification { method, params })
                if method == "event"
                    && params["cap"] == "approvals"
                    && params["name"] == "requested" =>
            {
                break params["data"].clone();
            }
            Recv::Msg(_) => {}
            other => panic!("no approval request: {other:?}"),
        }
    };
    assert_eq!(requested["cap"], "fs");
    assert_eq!(requested["action"], "read");
    let answer = conn
        .request(
            "invoke",
            json!({"cap": "approvals", "action": "answer",
                   "args": {"id": requested["id"], "answer": "once"}}),
        )
        .await
        .unwrap();
    let mut others = Vec::new();
    conn.answer(answer, WAIT, &mut others)
        .await
        .unwrap()
        .expect("answer accepted");
    let read = conn
        .answer(id, WAIT, &mut others)
        .await
        .unwrap()
        .expect("read allowed");
    assert_eq!(read["content"], "hello center");
    assert_eq!(read["encoding"], "utf8");

    // A second answer to the same approval is refused: first answer wins.
    let again = conn
        .call(
            "invoke",
            json!({"cap": "approvals", "action": "answer",
                   "args": {"id": requested["id"], "answer": "deny"}}),
            WAIT,
        )
        .await
        .unwrap();
    assert!(again.is_err());

    // The local audit log names the center and the approval.
    let log = std::fs::read_to_string(node.paths().audit_log()).unwrap();
    assert!(
        log.contains("\"asked\"") && log.contains("\"allowed\""),
        "{log}"
    );
    assert!(log.contains("lab"), "{log}");

    node.stop().await;
    assert!(
        conn.ends_within(WAIT).await.is_some(),
        "stop ends the link with bye"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_denied_read_fails_with_denied() {
    let dir = tempdir();
    let mut center = FakeCenter::start(false).await.unwrap();
    let node = paired_node(dir.path(), &center).await;
    let mut conn = linked(&mut center).await;
    let file = dir.path().join("home").join("x.txt");
    std::fs::write(&file, "x").unwrap();
    let id = conn
        .request(
            "invoke",
            json!({"cap": "fs", "action": "read", "args": {"path": file.display().to_string()}}),
        )
        .await
        .unwrap();
    let req_id = loop {
        match conn.recv(WAIT).await {
            Recv::Msg(Message::Notification { params, .. }) if params["name"] == "requested" => {
                break params["data"]["id"].clone();
            }
            Recv::Msg(_) => {}
            other => panic!("no approval request: {other:?}"),
        }
    };
    // The owner denies it locally over the control socket.
    let r = nerve_transport::ctl::call(
        &node.paths().ctl_socket(),
        "approvals.answer",
        json!({"id": req_id, "answer": "deny"}),
    )
    .await;
    assert!(r.is_ok(), "{r:?}");
    let mut others = Vec::new();
    let e = conn
        .answer(id, WAIT, &mut others)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(nerve_conformance::wire::code_of(&e), "denied");
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
    let file = o.paths.config_file();
    let mut cfg = NodeConfig::load(&file).unwrap();
    cfg.centers[0].url = format!("http://{}", stranger.url.authority());
    cfg.save(&file).unwrap();

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
        Ok(())
    })
    .await;
    let d = running.lock().unwrap().take();
    if let Some(d) = d {
        d.stop().await;
    }
    assert!(report.ok(), "{report}");
}

#[tokio::test(flavor = "multi_thread")]
async fn folders_mode_confines_commands_to_their_folders() {
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
    let file = o.paths.config_file();
    let mut cfg = NodeConfig::load(&file).unwrap();
    let p = &mut cfg.centers[0].policy;
    p.mode = nerve_policy::Mode::Folders;
    p.folders.push(nerve_policy::config::Folder {
        path: work.display().to_string(),
        access: nerve_policy::config::Access::Rw,
        execute: true,
    });
    p.commands.never_ask.push("sh *".into());
    cfg.save(&file).unwrap();
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
