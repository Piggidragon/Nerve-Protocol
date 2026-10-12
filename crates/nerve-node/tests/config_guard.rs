//! The node's config is the owner's (issue #20): a command cannot write it,
//! a file changed behind the node's back is refused and audited, and owner
//! changes through the local interface are applied and signed.

#![cfg(unix)]

use std::path::Path;
use std::time::Duration;

use clap::Parser;
use nerve_conformance::fake_center::{self, FakeCenter};
use nerve_conformance::wire::Conn;
use nerve_node::{Daemon, NodeOptions, NodePaths};
use nerve_policy::NodeConfig;
use nerve_policy::audit::AuditLog;
use serde_json::{Value, json};
use tokio::net::TcpStream;

const WAIT: Duration = Duration::from_secs(15);

/// A node whose config and state folders sit in its home, as they do by
/// default (`~/.config/nerve`, `~/.local/state/nerve`).
fn options(root: &Path) -> NodeOptions {
    let home = root.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let home = std::fs::canonicalize(&home).unwrap();
    let paths = NodePaths::new(home.join(".config/nerve"), home.join(".local/state/nerve"));
    let mut o = NodeOptions::new(paths);
    o.home = home;
    o.exe = Some(
        std::env::var_os("NERVE_NODE_BIN")
            .map(Into::into)
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_nerve-node").into()),
    );
    o
}

/// The owner's change while no daemon runs: through the CLI's store.
async fn owner_edit(paths: &NodePaths, f: impl Fn(&mut NodeConfig)) {
    nerve_node::cli::edit(paths, |c| {
        f(c);
        Ok(())
    })
    .await
    .expect("the owner's edit");
}

/// Runs one `nerve-node` command line as the owner would.
async fn cli(paths: &NodePaths, args: &[&str]) -> Result<String, String> {
    let mut argv: Vec<String> = vec![
        "nerve-node".into(),
        "--config-dir".into(),
        paths.config_dir.display().to_string(),
        "--state-dir".into(),
        paths.state_dir.display().to_string(),
    ];
    argv.extend(args.iter().map(|s| s.to_string()));
    let cli = nerve_node::cli::Cli::try_parse_from(argv).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    nerve_node::cli::execute(cli, &mut out).await?;
    Ok(String::from_utf8(out).unwrap())
}

async fn linked(center: &mut FakeCenter) -> Conn<TcpStream> {
    let paired = center.paired().expect("paired");
    let mut inc = center.next_link(WAIT).await.expect("the node dials");
    fake_center::handshake(&mut inc.conn, &center.center_id, &paired)
        .await
        .expect("handshake");
    inc.conn
}

fn wire(p: &Path) -> String {
    nerve_policy::paths::to_wire(p)
}

/// The audit lines about the config file itself.
fn config_events(o: &NodeOptions, event: &str) -> Vec<Value> {
    AuditLog::new(o.paths.audit_log())
        .read()
        .unwrap()
        .into_iter()
        .filter(|v| v["kind"] == "config" && v["event"] == event)
        .collect()
}

/// What a command, not the owner, would write: the config with `f` applied,
/// saved as plain TOML.
fn rewrite_behind_the_node(file: &Path, f: impl Fn(&mut NodeConfig)) {
    let mut cfg = NodeConfig::load(file).unwrap();
    f(&mut cfg);
    cfg.save(file).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_command_cannot_write_the_config_or_read_its_key() {
    if !nerve_sandbox::Confinement::detect().available() {
        eprintln!("skipped: Landlock is not available here");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let o = options(dir.path());
    nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
        .await
        .unwrap();
    let home = o.home.clone();
    let config_dir = std::fs::canonicalize(&o.paths.config_dir).unwrap();
    std::fs::create_dir_all(home.join("work")).unwrap();
    // The whole home is a read-write execute folder, so the config folder
    // lies inside it; one more folder names the config folder itself, which
    // would release a protected path.
    owner_edit(&o.paths, |c| {
        let p = &mut c.centers[0].policy;
        p.mode = nerve_policy::Mode::Folder;
        for path in [&home, &config_dir] {
            p.folders.push(nerve_policy::config::Folder {
                path: path.display().to_string(),
                access: nerve_policy::config::Access::Rw,
                execute: true,
            });
        }
    })
    .await;
    let file = o.paths.config_file();
    let paths = o.paths.clone();
    let node = Daemon::start(o).await.unwrap();
    let mut conn = linked(&mut center).await;
    let before = std::fs::read(&file).unwrap();
    let key_text = std::fs::read_to_string(paths.state_dir.join("config.key")).unwrap_or_default();

    // A command in the home: decide lets it run, Landlock keeps it out of
    // the node's folders while the rest of the home stays writable.
    let r = conn
        .call(
            "invoke",
            json!({"cap": "exec", "action": "run", "args": {
                "command": "echo in > work/inside.txt; echo pwned >> .config/nerve/node.toml; \
                            cat .local/state/nerve/config.key",
                "cwd": wire(&home)}}),
            WAIT,
        )
        .await
        .unwrap()
        .expect("the command runs");
    assert_eq!(
        std::fs::read_to_string(home.join("work/inside.txt")).unwrap(),
        "in\n",
        "{r}"
    );
    assert_eq!(std::fs::read(&file).unwrap(), before, "{r}");
    let stdout = r["stdout"].as_str().unwrap_or_default();
    assert!(
        key_text.trim().is_empty() || !stdout.contains(key_text.trim()),
        "{r}"
    );
    assert_ne!(r["exit_code"], 0, "{r}");

    // The fs capability and a command started in the config folder are
    // refused before any rule, though a folder names it.
    let e = conn
        .call(
            "invoke",
            json!({"cap": "fs", "action": "write",
                   "args": {"path": wire(&config_dir.join("node.toml")), "content": "x"}}),
            WAIT,
        )
        .await
        .unwrap()
        .expect_err("the config folder is refused");
    assert_eq!(nerve_conformance::wire::code_of(&e), "forbidden");
    let e = conn
        .call(
            "invoke",
            json!({"cap": "exec", "action": "run",
                   "args": {"command": "echo pwned > node.toml", "cwd": wire(&config_dir)}}),
            WAIT,
        )
        .await
        .unwrap()
        .expect_err("a command in the config folder is refused");
    assert_eq!(nerve_conformance::wire::code_of(&e), "forbidden");
    assert_eq!(std::fs::read(&file).unwrap(), before);
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_file_changed_behind_the_node_is_refused_and_audited() {
    let dir = tempfile::tempdir().unwrap();
    let center = FakeCenter::start(false).await.unwrap();
    let o = options(dir.path());
    nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
        .await
        .unwrap();
    let file = o.paths.config_file();
    let node = Daemon::start(o.clone()).await.unwrap();
    let before = node.config();
    let signed = std::fs::read_to_string(&file).unwrap();
    let widen = |c: &mut NodeConfig| {
        let p = &mut c.centers[0].policy;
        p.mode = nerve_policy::Mode::User;
        c.centers[0].settings = nerve_policy::config::SettingsGrant::Write;
    };

    // Rewritten as plain TOML: nothing picks it up by itself ...
    rewrite_behind_the_node(&file, widen);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(node.config(), before);
    // ... and the owner's reload refuses it.
    let e = node.reload().expect_err("an unsigned file is refused");
    assert!(e.contains("refused"), "{e}");
    assert_eq!(node.config(), before);

    // The node's own MAC line kept above a changed body is no way round it.
    assert!(signed.contains("settings = \"off\""), "{signed}");
    let changed = signed.replace("settings = \"off\"", "settings = \"write\"");
    std::fs::write(&file, changed).unwrap();
    assert!(node.reload().is_err());
    assert_eq!(node.config(), before);

    let refused = config_events(&o, "refused");
    assert_eq!(refused.len(), 2, "{refused:?}");
    assert_eq!(refused[0]["file"], file.display().to_string());
    assert!(
        refused[0]["reason"].as_str().unwrap().contains("MAC"),
        "{refused:?}"
    );
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_file_with_a_wrong_mac_is_refused_at_start_up() {
    let dir = tempfile::tempdir().unwrap();
    let center = FakeCenter::start(false).await.unwrap();
    let o = options(dir.path());
    nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
        .await
        .unwrap();
    // A first start signs what pairing wrote.
    Daemon::start(o.clone()).await.unwrap().stop().await;
    let file = o.paths.config_file();
    let signed = std::fs::read_to_string(&file).unwrap();
    assert!(signed.contains("settings = \"off\""), "{signed}");
    std::fs::write(
        &file,
        signed.replace("settings = \"off\"", "settings = \"write\""),
    )
    .unwrap();

    let e = match Daemon::start(o.clone()).await {
        Ok(d) => {
            d.stop().await;
            panic!("a node started on a file changed behind its back");
        }
        Err(e) => e,
    };
    assert!(e.contains("refused") && e.contains("config accept"), "{e}");
    let refused = config_events(&o, "refused");
    assert_eq!(refused.len(), 1, "{refused:?}");
    // The CLI refuses to work on it as well ...
    assert!(cli(&o.paths, &["centers"]).await.is_err());
    // ... until the owner looks at it and takes it.
    cli(&o.paths, &["config", "accept"]).await.unwrap();
    assert_eq!(config_events(&o, "accepted").len(), 1);
    let node = Daemon::start(o).await.unwrap();
    assert_eq!(
        node.config().centers[0].settings,
        nerve_policy::config::SettingsGrant::Write
    );
    node.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_owner_change_through_the_local_interface_is_applied_and_signed() {
    let dir = tempfile::tempdir().unwrap();
    let center = FakeCenter::start(false).await.unwrap();
    let o = options(dir.path());
    nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
        .await
        .unwrap();
    let node = Daemon::start(o.clone()).await.unwrap();
    let file = o.paths.config_file();
    let work = o.home.join("work");
    std::fs::create_dir_all(&work).unwrap();

    // The CLI reaches the running node over its control socket; the change
    // is in force at once, with no file watch and no tick.
    cli(&o.paths, &["folder", "add", work.to_str().unwrap(), "--rw"])
        .await
        .unwrap();
    cli(&o.paths, &["mode", "folder"]).await.unwrap();
    let cfg = node.config();
    assert_eq!(cfg.centers[0].policy.mode, nerve_policy::Mode::Folder);
    assert_eq!(cfg.centers[0].policy.folders.len(), 1);

    // Written signed: the first line is the node's MAC, and the file loads.
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.starts_with("# mac hmac-sha256 "), "{text}");
    assert_eq!(NodeConfig::load(&file).unwrap(), cfg);
    assert_eq!(node.reload(), Ok(false));
    // Audited with old and new value.
    let log = AuditLog::new(o.paths.audit_log()).read().unwrap();
    let mode = log
        .iter()
        .filter(|v| v["kind"] == "settings" && v["by"] == "local")
        .flat_map(|v| v["changes"].as_array().cloned().unwrap_or_default())
        .rfind(|c| c["key"] == "center")
        .expect("the change is audited");
    assert!(mode["old"].to_string().contains("allowlist"), "{mode}");
    assert!(mode["new"].to_string().contains("folder"), "{mode}");
    node.stop().await;

    // A restart takes the signed file.
    let node = Daemon::start(o).await.unwrap();
    assert_eq!(node.config(), cfg);
    node.stop().await;
}
