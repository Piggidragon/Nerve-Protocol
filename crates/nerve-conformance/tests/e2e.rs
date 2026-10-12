//! End-to-end tests: the real `nerve-center` and `nerve-node` binaries, against
//! the conformance parts and against each other.

#![cfg(unix)]

mod common;

use std::future::Future;
use std::time::{Duration, Instant};

use common::{Mcp, Node, text_of};
use nerve_conformance::{center_part, node_part};
use nerve_proto::link::PairLink;
use nerve_transport::sudo::{Offer, seal};
use serde_json::{Value, json};

fn block_on<F: Future>(f: F) -> F::Output {
    nerve_transport::init_crypto();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

fn center_part_against(tls: bool) {
    let state = tempfile::tempdir().unwrap();
    let mcp = Mcp::start(state.path(), tls, &[]);
    let link = PairLink::parse(&mcp.pair_link()).unwrap();
    assert_eq!(link.pin.is_some(), tls);
    let report = block_on(center_part::run(&link));
    assert!(report.ok(), "{report}");
    assert!(
        mcp.finish(),
        "nerve-center did not exit after its harness left"
    );
}

#[test]
fn center_part_passes_against_nerve_center_over_plain_loopback() {
    center_part_against(false);
}

#[test]
fn center_part_passes_against_nerve_center_over_pinned_tls() {
    center_part_against(true);
}

/// The name of the tool for `cap.action` and the arguments that pick `node`
/// when the tool covers several nodes.
fn tool(tools: &[Value], cap: &str, action: &str, node: &str) -> (String, Value) {
    let suffix = format!("{cap}_{action}");
    let t = tools
        .iter()
        .find(|t| t["name"].as_str().is_some_and(|n| n.ends_with(&suffix)))
        .unwrap_or_else(|| panic!("no tool for {suffix}: {tools:?}"));
    let mut args = json!({});
    if t["inputSchema"]["properties"].get("node").is_some() {
        args["node"] = json!(node);
    }
    (t["name"].as_str().unwrap().to_string(), args)
}

fn with(mut args: Value, more: Value) -> Value {
    for (k, v) in more.as_object().unwrap() {
        args[k] = v.clone();
    }
    args
}

const SUDO_PW: &str = "e2e-right-sudo-pw";

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Fails when a file below `dir` contains `secret`.
fn assert_no_file_holds(dir: &std::path::Path, secret: &str) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            assert_no_file_holds(&p, secret);
        } else if let Ok(bytes) = std::fs::read(&p) {
            let found = bytes.windows(secret.len()).any(|w| w == secret.as_bytes());
            // The fake sudo script names the right password, as /etc/shadow
            // would hold its hash.
            assert!(
                !found || p.ends_with("fake-sudo"),
                "{} holds it",
                p.display()
            );
        }
    }
}

/// The whole path through both binaries: pairing, the link, tools, the
/// the sudo switch relayed by the center, a folder and a rule on the node
/// deciding calls (allowed at once, or
/// refused at once), a rule from the audit view landing in the node's
/// settings, the node's audit log, and removing the node.
#[test]
fn nerve_center_and_nerve_node_work_together() {
    let root = tempfile::tempdir().unwrap();
    let mut mcp = Mcp::start(&root.path().join("center"), true, &[]);
    let mut node = Node::new(&root.path().join("node"));

    // Pairing from the web UI's link, confirmed on the node.
    let link = mcp.pair_link();
    let out = node.ok(&["center", "add", &link, "--yes"]);
    assert!(out.contains("e2e-center"), "{out}");
    assert!(node.ok(&["center", "ls"]).contains("e2e-center"));
    node.use_fake_sudo(SUDO_PW);
    node.start();
    let ov = mcp.wait_overview("the node comes online", |v| {
        v["nodes"][0]["online"] == json!(true)
            && v["nodes"][0]["capabilities"]
                .as_array()
                .is_some_and(|c| !c.is_empty())
    });
    let node_id = ov["nodes"][0]["id"].as_str().unwrap().to_string();
    let node_name = ov["nodes"][0]["name"].as_str().unwrap().to_string();
    assert_eq!(ov["nodes"][0]["settings_write"], json!(false), "{ov}");

    // Tools: none for files and commands while no allow rule could let a
    // call through, and never one for the node's settings.
    let tools = mcp.tools();
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert!(!names.iter().any(|n| n.ends_with("fs_read")), "{names:?}");
    assert!(!names.iter().any(|n| n.ends_with("exec_run")), "{names:?}");
    assert!(!names.iter().any(|n| n.contains("settings_")), "{names:?}");

    // The settings grant, given on the node, reaches the center.
    node.ok(&["center", "grant", "settings", "write"]);
    mcp.wait_overview("the settings grant reaches the center", |v| {
        v["nodes"][0]["settings_write"] == json!(true)
    });
    let (status, v) = mcp.api(
        "GET",
        &format!("/api/nodes/settings?id={node_id}"),
        Value::Null,
    );
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["sudo"], "off", "{v}");

    // The sudo switch from the web UI: the center checks that the node
    // signed the offer and relays a password sealed for it. The browser
    // seals; here the test does.
    let sealed_for = |mcp: &mut Mcp, password: &str| {
        let (status, v) = mcp.api("POST", "/api/nodes/sudo/offer", json!({"id": node_id}));
        assert_eq!(status, 200, "{v}");
        let offer: Offer = serde_json::from_value(v).unwrap();
        seal(&offer, password, now_ms()).unwrap()
    };
    let wrong = sealed_for(&mut mcp, "wrong");
    let (status, v) = mcp.api(
        "POST",
        "/api/nodes/sudo",
        json!({"id": node_id, "on": true, "sealed": wrong}),
    );
    assert_eq!(status, 409, "{v}");
    assert!(
        v["error"].as_str().unwrap().contains("password is wrong"),
        "{v}"
    );
    let right = sealed_for(&mut mcp, SUDO_PW);
    let (status, v) = mcp.api(
        "POST",
        "/api/nodes/sudo",
        json!({"id": node_id, "on": true, "sealed": right}),
    );
    assert_eq!((status, &v["sudo"]), (200, &json!("on")), "{v}");
    // The node says so too. Running sudo commands is the node part's and
    // nerve-node's own tests' job.
    let (_, v) = mcp.api(
        "GET",
        &format!("/api/nodes/settings?id={node_id}"),
        Value::Null,
    );
    assert_eq!(v["sudo"], "on", "{v}");
    assert!(node.ok(&["sudo", "status"]).contains("on"));
    let (status, v) = mcp.api(
        "POST",
        "/api/nodes/sudo",
        json!({"id": node_id, "on": false}),
    );
    assert_eq!((status, &v["sudo"]), (200, &json!("off")), "{v}");
    assert!(node.ok(&["sudo", "status"]).contains("off"));
    // Neither the center's files nor the node's hold the password.
    assert_no_file_holds(root.path(), SUDO_PW);

    // The four buttons of the audit view, for a command, a path and another
    // action: each one adds a rule to its list on the node and takes none off.
    let center_policy = format!("center.{}.policy", "e2e-center");
    let list =
        |name: &str| -> String { node.ok(&["config", "get", &format!("{center_policy}.{name}")]) };
    let button = |mcp: &Mcp, body: Value| mcp.api("POST", "/api/audit/rule", body);
    let click = |mcp: &Mcp, list: &str, cap: &str, action: &str, target: &str, wildcard: bool| {
        let (status, v) = button(
            mcp,
            json!({"node_id": node_id, "list": list, "cap": cap, "action": action,
                   "target": target, "wildcard": wildcard}),
        );
        assert_eq!(status, 200, "{v}");
        v["rule"].as_str().unwrap().to_string()
    };
    assert_eq!(
        click(&mcp, "allow", "exec", "run", "echo hi", false),
        "exec.run:echo hi"
    );
    assert_eq!(
        click(&mcp, "allow", "exec", "run", "echo hi", true),
        "exec.run:echo *"
    );
    assert_eq!(
        click(&mcp, "deny", "exec", "run", "rm -rf x", false),
        "exec.run:rm -rf x"
    );
    assert_eq!(
        click(&mcp, "deny", "exec", "run", "rm -rf x", true),
        "exec.run:rm *"
    );
    assert_eq!(
        click(&mcp, "allow", "fs", "read", "/nerve-e2e/a.txt", false),
        "fs.read:/nerve-e2e/a.txt"
    );
    assert_eq!(
        click(&mcp, "deny", "fs", "write", "/nerve-e2e/a.txt", true),
        "fs.write:/nerve-e2e/*"
    );
    assert_eq!(
        click(&mcp, "allow", "camera", "snap", "camera.snap", false),
        "camera.snap"
    );
    assert_eq!(
        click(&mcp, "deny", "camera", "snap", "camera.snap", true),
        "camera"
    );
    assert_eq!(
        click(&mcp, "sudo", "exec", "run", "sudo apt update", false),
        "sudo apt update"
    );
    assert_eq!(
        click(&mcp, "sudo", "exec", "run", "sudo apt update", true),
        "sudo apt *"
    );
    // A repeat adds nothing.
    click(&mcp, "allow", "exec", "run", "echo hi", false);
    let allow = list("allow");
    for want in [
        "exec.run:echo hi",
        "exec.run:echo *",
        "fs.read:/nerve-e2e/a.txt",
        "camera.snap",
    ] {
        assert!(allow.contains(want), "{allow}");
    }
    assert_eq!(allow.matches("exec.run:echo hi").count(), 1, "{allow}");
    assert!(!allow.contains("rm"), "{allow}");
    let deny = list("deny");
    for want in [
        "exec.run:rm -rf x",
        "exec.run:rm *",
        "fs.write:/nerve-e2e/*",
        "camera",
    ] {
        assert!(deny.contains(want), "{deny}");
    }
    assert!(!deny.contains("echo"), "{deny}");
    let sudo = list("sudo_allow");
    assert!(
        sudo.contains("sudo apt update") && sudo.contains("sudo apt *"),
        "{sudo}"
    );
    // A bad list, a missing target and a sudo list for a plain command are
    // refused before the node sees them.
    for body in [
        json!({"list": "permit", "cap": "exec", "action": "run", "target": "ls"}),
        json!({"list": "allow", "cap": "exec", "action": "run", "target": " "}),
        json!({"list": "allow", "cap": "exec", "action": "run"}),
        json!({"list": "allow", "cap": "fs", "action": "read", "target": "relative"}),
        json!({"list": "sudo", "cap": "exec", "action": "run", "target": "ls"}),
        json!({"list": "sudo", "cap": "fs", "action": "read", "target": "/a"}),
        json!({"list": "allow", "cap": "", "action": "run", "target": "ls"}),
    ] {
        let body = with(body, json!({"node_id": node_id}));
        let (status, v) = button(&mcp, body.clone());
        assert_eq!(status, 400, "{body} {v}");
    }
    assert_eq!(list("allow"), allow);

    // The allow rules above made the tools appear: the node announced a new
    // descriptor and the center built them.
    let deadline = Instant::now() + Duration::from_secs(15);
    let tools = loop {
        let tools = mcp.tools();
        let has = |suffix: &str| {
            tools
                .iter()
                .any(|t| t["name"].as_str().is_some_and(|n| n.ends_with(suffix)))
        };
        if has("fs_read") && has("exec_run") {
            break tools;
        }
        assert!(
            Instant::now() < deadline,
            "the tools did not appear: {tools:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    };

    // exec.run goes straight to the node: the center holds no call back, and
    // the node lets it run (the allow rule above).
    let (run, args) = tool(&tools, "exec", "run", &node_name);
    let r = mcp.call(&run, with(args, json!({"command": "echo hi"})));
    let text = text_of(&r);
    assert_eq!(r["isError"], json!(false), "{r}");
    assert!(
        text.contains("hi") && text.contains("device content"),
        "{text}"
    );

    // fs.read: nothing is allowed until a rule or a mode allows it, and a
    // call no rule allows is refused at once instead of waiting for anybody.
    std::fs::write(node.home.join("notes.txt"), "hello from the node").unwrap();
    let path = node.home.join("notes.txt").to_string_lossy().to_string();
    let (read, args) = tool(&tools, "fs", "read", &node_name);
    let started = Instant::now();
    let r = mcp.call(&read, with(args.clone(), json!({"path": path})));
    assert!(started.elapsed() < Duration::from_secs(10), "{r}");
    assert_eq!(r["isError"], json!(true), "{r}");
    assert!(text_of(&r).contains("forbidden"), "{r}");

    // A folder counts in folder mode only: in default deny it allows nothing.
    node.ok(&["folder", "add", &node.home.to_string_lossy(), "+r"]);
    let r = mcp.call(&read, with(args.clone(), json!({"path": path})));
    assert_eq!(r["isError"], json!(true), "{r}");
    node.ok(&["mode", "set", "folder"]);
    let r = mcp.call(&read, with(args.clone(), json!({"path": path})));
    assert_eq!(r["isError"], json!(false), "{r}");
    assert!(text_of(&r).contains("hello from the node"), "{r}");

    // A file outside every folder is refused at once.
    let outside = root.path().join("outside.txt");
    std::fs::write(&outside, "not for the model").unwrap();
    let r = mcp.call(
        &read,
        with(args, json!({"path": outside.to_string_lossy()})),
    );
    assert_eq!(r["isError"], json!(true), "{r}");
    assert!(text_of(&r).contains("forbidden"), "{r}");
    assert!(!text_of(&r).contains("not for the model"), "{r}");

    // The node's own audit log has the decisions.
    let audit = node.ok(&["audit"]);
    assert!(
        audit.contains("exec.run") && audit.contains("allowed"),
        "{audit}"
    );
    assert!(
        audit.contains("fs.read") && audit.contains("forbidden"),
        "{audit}"
    );
    let denied = node.ok(&["audit", "--denied"]);
    assert!(!denied.contains("exec.run"), "{denied}");

    // The center's statistics count the calls; nothing of their content.
    let (_, stats) = mcp.api("GET", "/api/stats", Value::Null);
    assert!(
        !stats.to_string().contains("hello from the node"),
        "{stats}"
    );

    // Removing the node from the web UI: its tools go, and the node stops.
    let (status, v) = mcp.api("POST", "/api/nodes/remove", json!({"id": node_id}));
    assert_eq!(status, 200, "{v}");
    mcp.wait_overview("the node is gone", |v| {
        v["nodes"].as_array().is_some_and(|n| n.is_empty())
    });
    let names: Vec<String> = mcp
        .tools()
        .iter()
        .filter_map(|t| t["name"].as_str().map(str::to_string))
        .collect();
    assert!(!names.iter().any(|n| n.ends_with("fs_read")), "{names:?}");
    let status = node.ok(&["status"]);
    assert!(
        status.contains("revoked") || status.contains("unknown") || status.contains("stopped"),
        "{status}"
    );
    assert!(!node.daemon_exited(), "the daemon itself keeps running");
    assert!(mcp.finish());
}

/// The node part of the conformance runner against the real binary.
#[test]
fn node_part_passes_against_nerve_node() {
    let root = tempfile::tempdir().unwrap();
    let node = std::sync::Arc::new(std::sync::Mutex::new(Node::new(root.path())));
    let n = node.clone();
    let report = block_on(node_part::run(move |link: PairLink| async move {
        let link = link.render();
        let node = n;
        tokio::task::spawn_blocking(move || {
            let mut node = node.lock().unwrap();
            let (ok, out, err) = node.cli(&["center", "add", &link, "--yes"]);
            if !ok {
                return Err(format!("pair failed: {out}{err}"));
            }
            // The profile checks write the policy through settings.set and
            // try one wrong sudo password: on a fake sudo, not this machine's.
            let (ok, out, err) = node.cli(&["center", "grant", "settings", "write"]);
            if !ok {
                return Err(format!("grant failed: {out}{err}"));
            }
            let password = "conformance-right-password";
            node.use_fake_sudo(password);
            let folder = node.home.join("work");
            std::fs::create_dir_all(&folder).unwrap();
            node.start();
            Ok(node_part::Setup {
                folder: Some(folder.display().to_string()),
                sudo_password: Some(password.into()),
            })
        })
        .await
        .map_err(|e| e.to_string())?
    }));
    assert!(report.ok(), "{report}");
    let profiles = report
        .outcomes
        .iter()
        .filter(|o| o.section.starts_with('7'));
    assert_eq!(profiles.count(), 19, "{report}");
    drop(node);
}
