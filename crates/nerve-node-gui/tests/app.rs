//! The app against a node of its own, end to end: each action goes through
//! the window's callbacks, runs this crate's program as `nerve-node`, and
//! lands in the node's files and audit log as the CLI's command does.
//! One test: Slint takes one platform per process.

use std::path::Path;

use nerve_conformance::fake_center::FakeCenter;
use nerve_node::NodePaths;
use nerve_node_gui::app::{Ctl, Exec};
use nerve_node_gui::headless::Screen;
use nerve_node_gui::runner::Runner;
use nerve_node_gui::{AppWindow, Load, Page, Store};
use nerve_policy::NodeConfig;
use serde_json::Value;
use slint::{ComponentHandle, Model};

fn config(paths: &NodePaths) -> NodeConfig {
    NodeConfig::load(&paths.config_file()).unwrap()
}

fn audit(paths: &NodePaths) -> Vec<Value> {
    std::fs::read_to_string(paths.audit_log())
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn decided(paths: &NodePaths, ts: u64, center: &str, cap: &str, action: &str, target: &str) {
    nerve_policy::audit::AuditLog::new(paths.audit_log())
        .decision(&nerve_policy::audit::Entry {
            ts,
            center: center.into(),
            cap: cap.into(),
            action: action.into(),
            target: target.into(),
            decision: "forbidden".into(),
            code: None,
            session: None,
            reason: Some("no allow rule matches it (allowlist mode)".into()),
        })
        .unwrap();
}

#[test]
fn the_app_drives_the_cli_end_to_end() {
    let _screen = Screen::install(1180, 780, 1.0).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let root: &Path = dir.path();
    let paths = NodePaths::new(root.join("config"), root.join("state"));
    let runner = Runner::new(
        env!("CARGO_BIN_EXE_nerve-node-gui").into(),
        Some(paths.config_dir.clone()),
        Some(paths.state_dir.clone()),
    );
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let center = rt.block_on(FakeCenter::start(false)).unwrap();

    let window = AppWindow::new().unwrap();
    let ctl = Ctl::attach(&window, runner, Exec::Inline);
    let store = window.global::<Store>();
    ctl.refresh_status();
    assert_eq!(store.get_status_load(), Load::Ready);
    assert_eq!(store.get_status().state, "stopped");
    assert_eq!(store.get_centers().row_count(), 0);

    // A link that is none is refused by the CLI, and the dialog says why.
    store.invoke_pair_start();
    assert!(store.get_pair_open());
    store.invoke_pair_check("nerve://elsewhere".into(), "".into());
    assert!(
        store.get_pair_error().contains("nerve://pair?"),
        "{}",
        store.get_pair_error()
    );
    assert_eq!(store.get_pair_step(), 0);

    // The preview first, and nothing paired yet.
    let link = center.link().render();
    store.set_pair_link(link.clone().into());
    store.set_pair_name("home".into());
    store.invoke_pair_check(link.into(), "home".into());
    assert_eq!(store.get_pair_error(), "");
    assert_eq!(store.get_pair_step(), 1);
    assert_eq!(store.get_pair_preview().center, center.url.to_string());
    assert!(!store.get_pair_preview().tls);
    assert!(config(&paths).centers.is_empty());
    store.invoke_pair_confirm();
    assert!(!store.get_pair_open(), "{}", store.get_pair_error());
    assert!(
        store.get_toast().contains("Paired with home"),
        "{}",
        store.get_toast()
    );
    let cfg = config(&paths);
    assert_eq!(cfg.centers.len(), 1);
    assert_eq!(cfg.centers[0].name, "home");
    assert!(center.paired().is_some());
    assert_eq!(store.get_centers().row_count(), 1);
    assert_eq!(store.get_centers().row_data(0).unwrap().name, "home");

    // Pause, the settings grant, each as the CLI makes it, and audited.
    store.invoke_center_pause("home".into(), true);
    assert!(config(&paths).centers[0].paused);
    assert_eq!(store.get_centers().row_data(0).unwrap().link, "Paused");
    store.invoke_center_pause("home".into(), false);
    assert!(!config(&paths).centers[0].paused);
    store.invoke_center_grant("home".into(), true);
    assert_eq!(
        config(&paths).centers[0].settings,
        nerve_policy::config::SettingsGrant::Write
    );
    assert!(store.get_centers().row_data(0).unwrap().settings_write);
    let settings = audit(&paths)
        .iter()
        .filter(|e| e["kind"] == "settings" && e["by"] == "local")
        .count();
    assert!(
        settings >= 3,
        "every change is audited: {:?}",
        audit(&paths)
    );

    // The four buttons write the rules the CLI's `rule add --action` and
    // the center's buttons write.
    decided(&paths, 1, "home", "exec", "run", "git push origin main");
    decided(&paths, 2, "home", "fs", "write", "/srv/data/report.txt");
    decided(&paths, 3, "home", "exec", "run", "sudo apt update");
    store.invoke_show(Page::Audit);
    assert_eq!(store.get_page(), Page::Audit);
    assert_eq!(
        store.get_audit_load(),
        Load::Ready,
        "{}",
        store.get_audit_error()
    );
    let rows = store.get_audit();
    // Newest first: the sudo command, the file, the push.
    let row = |i: usize| rows.row_data(i).unwrap();
    assert_eq!(row(0).target, "sudo apt update");
    assert!(row(0).rules && row(1).rules && row(2).rules);
    // Each change is an entry too, so the list moves: a button is found by
    // its entry.
    let index_of = |target: &str| {
        let rows = store.get_audit();
        (0..rows.row_count())
            .find(|i| rows.row_data(*i).unwrap().target == target)
            .unwrap() as i32
    };
    store.invoke_audit_rule(index_of("git push origin main"), "allow".into(), true);
    store.invoke_audit_rule(index_of("/srv/data/report.txt"), "deny".into(), true);
    store.invoke_audit_rule(index_of("sudo apt update"), "allow".into(), false);
    store.invoke_audit_rule(index_of("git push origin main"), "deny".into(), false);
    let policy = config(&paths).centers[0].policy.clone();
    let rule = |cap, action, target, wildcard| {
        nerve_policy::rules::rule_for(cap, action, target, wildcard).unwrap()
    };
    assert_eq!(
        policy.allow,
        [rule("exec", "run", "git push origin main", true)]
    );
    assert_eq!(
        policy.deny,
        [
            rule("fs", "write", "/srv/data/report.txt", true),
            rule("exec", "run", "git push origin main", false)
        ]
    );
    assert_eq!(
        policy.sudo_allow,
        [nerve_policy::rules::sudo_rule_for("sudo apt update", false).unwrap()]
    );
    assert!(
        store.get_toast().contains("deny list of home"),
        "{}",
        store.get_toast()
    );

    // The refused only, as `audit --denied` gives them.
    store.invoke_audit_filter(true);
    let rows = store.get_audit();
    assert_eq!(rows.row_count(), 3);
    assert!((0..3).all(|i| rows.row_data(i).unwrap().badge == "Refused"));

    // Panic and unlock.
    store.invoke_panic();
    assert!(config(&paths).locked);
    assert_eq!(store.get_status().state, "locked");
    store.invoke_unlock();
    assert!(!config(&paths).locked);

    // Unpairing asks first.
    store.invoke_center_unpair("home".into());
    assert!(store.get_confirm_open());
    assert!(!config(&paths).centers.is_empty());
    store.set_confirm_open(false);
    store.invoke_confirm_accepted();
    assert!(config(&paths).centers.is_empty());
    assert!(!paths.key_file("home").exists());
    assert_eq!(store.get_centers().row_count(), 0);

    // An error of the CLI is said, and the window stays as it was.
    store.invoke_center_pause("nobody".into(), true);
    assert_eq!(store.get_toast_tone(), nerve_node_gui::Tone::Danger);
    assert!(
        store.get_toast().contains("center"),
        "{}",
        store.get_toast()
    );
    drop(rt);
}
