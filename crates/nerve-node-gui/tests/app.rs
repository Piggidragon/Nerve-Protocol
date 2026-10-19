//! The app against a node of its own, end to end: each action goes through
//! the window's callbacks, runs this crate's program as `nerve-node`, and
//! lands in the node's files and audit log as the CLI's command does.
//! One test: Slint takes one platform per process.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use nerve_conformance::fake_center::FakeCenter;
use nerve_node::NodePaths;
use nerve_node_gui::app::{Choose, Ctl, Exec};
use nerve_node_gui::broker::Launch;
use nerve_node_gui::headless::Screen;
use nerve_node_gui::runner::Runner;
use nerve_node_gui::{AppWindow, Load, Logs, Page, Perm, Prefs, Store};
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

/// Waits for a command that keeps answering (`audit --follow`) to bring
/// what `done` looks for into the window.
fn until(ctl: &Ctl, what: &str, done: impl Fn() -> bool) {
    for _ in 0..100 {
        ctl.pump();
        if done() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("{what} did not come");
}

fn logged(paths: &NodePaths, msg: &str) {
    use std::io::Write;
    std::fs::create_dir_all(&paths.state_dir).unwrap();
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(paths.log_file())
        .unwrap();
    writeln!(
        f,
        "{}",
        serde_json::json!({"ts": 1, "level": "warn", "msg": msg})
    )
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
    // `audit --follow` brings the entries in.
    until(&ctl, "the audit entries", || {
        store
            .get_audit()
            .row_data(0)
            .is_some_and(|r| r.target == "sudo apt update")
    });
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
    let settings_shown = || {
        let rows = store.get_audit();
        (0..rows.row_count())
            .filter(|i| rows.row_data(*i).unwrap().kind == "settings")
            .count()
    };
    let before = settings_shown();
    store.invoke_audit_rule(index_of("git push origin main"), "allow".into(), true);
    // The change comes in as an entry of its own, live.
    until(&ctl, "the rule's settings entry", || {
        settings_shown() == before + 1
    });
    store.invoke_audit_rule(index_of("/srv/data/report.txt"), "deny".into(), true);
    until(&ctl, "the second rule", || settings_shown() == before + 2);
    store.invoke_audit_rule(index_of("sudo apt update"), "allow".into(), false);
    until(&ctl, "the third rule", || settings_shown() == before + 3);
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
    until(&ctl, "the refused entries", || {
        store.get_audit().row_count() == 3
    });
    let rows = store.get_audit();
    assert!((0..3).all(|i| rows.row_data(i).unwrap().badge == "Refused"));

    // Permissions: the mode with a time, a folder from the system's
    // dialog (answered here), a rule, a capability switch.
    let work = root.join("work");
    std::fs::create_dir(&work).unwrap();
    let picked = work.clone();
    ctl.set_chooser(Arc::new(move |c| match c {
        Choose::Folder => Some(picked.clone()),
        _ => None,
    }));
    let perm = window.global::<Perm>();
    store.invoke_show(Page::Policy);
    assert_eq!(perm.get_center(), "home");
    assert_eq!(perm.get_load(), Load::Ready, "{}", perm.get_error());
    assert_eq!(perm.get_mode(), "allowlist");
    assert!(perm.get_caps().iter().any(|c| c.name == "exec.run"));
    perm.invoke_mode_pick("user".into());
    assert!(perm.get_mode_open());
    perm.set_mode_timed(true);
    perm.set_mode_hours("2".into());
    perm.invoke_mode_apply();
    assert!(!perm.get_mode_open(), "{}", perm.get_mode_error());
    let p = config(&paths).centers[0].policy.clone();
    assert_eq!(p.mode, nerve_policy::Mode::User);
    assert!(p.until.is_some());
    assert_eq!(perm.get_mode(), "user");
    assert!(
        perm.get_mode_until().contains("Back to allowlist"),
        "{}",
        perm.get_mode_until()
    );
    perm.invoke_mode_pick("allowlist".into());
    assert_eq!(
        config(&paths).centers[0].policy.mode,
        nerve_policy::Mode::Allowlist
    );

    perm.invoke_folder_choose();
    assert!(perm.get_folder_open());
    assert_eq!(perm.get_folder_path(), work.display().to_string());
    perm.set_folder_execute(true);
    perm.invoke_folder_add();
    assert!(!perm.get_folder_open(), "{}", perm.get_folder_error());
    let f = &config(&paths).centers[0].policy.folders[0];
    assert!(
        f.access.read && !f.access.write && f.access.execute,
        "{f:?}"
    );
    let path = perm.get_folders().row_data(0).unwrap().path;
    perm.invoke_folder_set(path.clone(), true, true, false);
    let f = &config(&paths).centers[0].policy.folders[0];
    assert!(
        f.access.read && f.access.write && !f.access.execute,
        "{f:?}"
    );
    perm.invoke_folder_remove(path);
    assert!(config(&paths).centers[0].policy.folders.is_empty());

    let allowed = |r: &str| {
        config(&paths).centers[0]
            .policy
            .allow
            .contains(&r.to_string())
    };
    perm.set_list(0);
    perm.set_rule_text("cargo build".into());
    perm.set_rule_wildcard(true);
    perm.invoke_rule_add();
    assert!(allowed("exec.run:cargo *"));
    assert_eq!(perm.get_rule_text(), "");
    perm.invoke_rule_remove(0, "exec.run:cargo *".into());
    assert!(!allowed("exec.run:cargo *"));
    perm.invoke_cap_set("exec.run".into(), 1);
    assert_eq!(
        config(&paths).centers[0].policy.caps.get("exec.run"),
        Some(&nerve_policy::config::CapSetting::Off)
    );
    assert!(
        perm.get_caps()
            .iter()
            .any(|c| c.name == "exec.run" && c.setting == 1 && c.set)
    );
    perm.invoke_cap_set("exec.run".into(), 0);

    // Sudo takes the password on stdin; without a running node it says so
    // and waits for nothing.
    perm.invoke_sudo_ask();
    perm.set_sudo_password("not a real password".into());
    perm.invoke_sudo_confirm();
    if cfg!(unix) {
        assert!(
            perm.get_sudo_error().contains("daemon"),
            "{}",
            perm.get_sudo_error()
        );
    }
    assert_eq!(perm.get_sudo_password(), "", "the password is not kept");
    perm.set_sudo_open(false);

    // The log, live.
    logged(&paths, "link dropped");
    store.invoke_show(Page::Log);
    let logs = window.global::<Logs>();
    until(&ctl, "the log line", || logs.get_rows().row_count() == 1);
    logged(&paths, "cannot connect");
    until(&ctl, "the new log line", || {
        logs.get_rows().row_count() == 2
    });
    assert_eq!(logs.get_rows().row_data(0).unwrap().msg, "cannot connect");

    // Settings: the name, any setting, a relay node's token, a backup and
    // its restore, the passphrase piped in.
    let prefs = window.global::<Prefs>();
    store.invoke_show(Page::Settings);
    assert_eq!(prefs.get_load(), Load::Ready, "{}", prefs.get_error());
    prefs.invoke_name_save("lab-box".into());
    assert_eq!(config(&paths).node.name.as_deref(), Some("lab-box"));
    prefs.set_raw_key("log.level".into());
    prefs.set_raw_value("debug".into());
    prefs.invoke_raw_set();
    assert_eq!(prefs.get_raw_error(), "");
    assert_eq!(prefs.get_raw_shown(), "debug");
    prefs.set_relay_new_node("laptop-2".into());
    prefs.invoke_relay_add();
    assert!(prefs.get_once_open());
    assert!(
        prefs.get_once_text().contains("laptop-2"),
        "{}",
        prefs.get_once_text()
    );
    assert_eq!(prefs.get_relay_nodes().row_count(), 1);
    prefs.set_once_open(false);
    let backup = root.join("node.backup");
    let file = backup.clone();
    ctl.set_chooser(Arc::new(move |_| Some(file.clone())));
    prefs.invoke_backup_choose();
    assert!(prefs.get_backup_open());
    prefs.set_backup_pass("correct horse battery".into());
    prefs.set_backup_pass2("correct horse battery".into());
    prefs.invoke_backup_confirm();
    assert!(!prefs.get_backup_open(), "{}", prefs.get_backup_error());
    assert!(backup.is_file());
    prefs.set_once_open(false);
    prefs.invoke_restore_choose();
    assert!(prefs.get_restore_open());
    prefs.set_restore_pass("wrong passphrase!".into());
    prefs.invoke_restore_confirm();
    assert!(
        prefs.get_restore_error().contains("passphrase"),
        "{}",
        prefs.get_restore_error()
    );
    prefs.set_restore_pass("correct horse battery".into());
    prefs.invoke_restore_confirm();
    assert!(!prefs.get_restore_open(), "{}", prefs.get_restore_error());
    prefs.set_once_open(false);

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

    // The first-run steps: a name, the keys, a new center, its mode, and
    // the node started by the app, which ends with it.
    let second = rt.block_on(FakeCenter::start(true)).unwrap();
    store.invoke_setup_start();
    assert!(store.get_setup_open());
    store.set_setup_name("studio".into());
    store.invoke_setup_next();
    assert_eq!(store.get_setup_step(), 1, "{}", store.get_setup_error());
    assert_eq!(config(&paths).node.name.as_deref(), Some("studio"));
    store.invoke_setup_next();
    assert_eq!(store.get_setup_step(), 2, "{}", store.get_setup_error());
    store.set_pair_link(second.link().render().into());
    store.set_pair_name("studio-center".into());
    store.invoke_setup_next();
    assert_eq!(store.get_pair_step(), 1, "{}", store.get_pair_error());
    store.invoke_setup_next();
    assert_eq!(store.get_setup_step(), 3, "{}", store.get_pair_error());
    assert_eq!(store.get_setup_center(), "studio-center");
    store.set_setup_mode("folder".into());
    store.invoke_setup_next();
    assert_eq!(store.get_setup_step(), 4, "{}", store.get_setup_error());
    assert_eq!(
        config(&paths).center("studio-center").unwrap().policy.mode,
        nerve_policy::Mode::Folder
    );
    store.invoke_setup_next();
    assert!(!store.get_setup_open());
    assert!(store.get_started_here());
    until(&ctl, "the node the app started", || {
        ctl.refresh_status();
        store.get_status().state == "running"
    });
    store.invoke_node_stop();
    assert!(!store.get_started_here());
    ctl.refresh_status();
    assert_eq!(store.get_status().state, "stopped");

    // A nerve:// link goes straight to the pairing's confirmation.
    let third = rt.block_on(FakeCenter::start(false)).unwrap();
    ctl.open_link(third.link().render());
    assert!(store.get_pair_open());
    assert_eq!(store.get_pair_step(), 1, "{}", store.get_pair_error());
    assert_eq!(store.get_pair_preview().center, third.url.to_string());
    store.set_pair_open(false);

    // An installed node: the app says why it needs the rights, then runs
    // every command through the broker (here as this user), the ones that
    // keep answering too.
    ctl.needs_rights(Launch::Plain);
    assert!(store.get_elevate_open() && store.get_elevate_needed());
    store.invoke_elevate_allow();
    assert!(!store.get_elevate_needed(), "{}", store.get_elevate_error());
    ctl.refresh_status();
    assert_eq!(
        store.get_status_load(),
        Load::Ready,
        "{}",
        store.get_status_error()
    );
    store.invoke_panic();
    assert!(config(&paths).locked);
    store.invoke_unlock();
    store.invoke_show(Page::Audit);
    until(&ctl, "the audit through the broker", || {
        // The refused ones, as the page still shows.
        store.get_audit().row_count() == 3
    });
    store.invoke_show(Page::Overview);
    ctl.end();
    drop((rt, second, third));
}
