//! A folder-mode command runs as the account the commands run as, confined
//! by Landlock to its folders like any folder-mode command, and the node's
//! own folders are out of that account's reach (issue #21). The test runs
//! as its own user, which stands in for the chosen account; the node's
//! folders are closed to it as `nerve`'s folders are closed to the account.

#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use nerve_node::exec::{self, RunCall, RunOptions};
use nerve_node::service::Account;
use nerve_policy::config::{Access, CenterPolicy, Folder, Mode};

fn set_mode(p: &Path, mode: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn me(home: &Path) -> Account {
    // SAFETY: plain getters.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    Account {
        name: "chosen".into(),
        uid,
        gid,
        comment: String::new(),
        home: home.to_path_buf(),
        groups: vec![gid],
    }
}

fn opts(policy: &CenterPolicy, account: &Account, own: &[PathBuf]) -> RunOptions {
    RunOptions {
        shell: None,
        landlock: Some(exec::landlock_spec(policy, &account.home, own, &[])),
        container: None,
        exe: env!("CARGO_BIN_EXE_nerve-node").into(),
        output_cap: 64 * 1024,
        timeouts: Default::default(),
        sudo: None,
        account: Some(account.clone()),
        own: own.to_vec(),
    }
}

#[tokio::test]
async fn a_folder_mode_command_of_the_account_stays_in_its_folders_and_off_the_keys() {
    if !nerve_sandbox::Confinement::detect().available() {
        eprintln!("skipped: Landlock is not available here");
        return;
    }
    if nerve_transport::net::euid() == 0 {
        eprintln!("skipped: root opens every folder");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(d.path()).unwrap();
    let home = root.join("home");
    let work = home.join("work");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(work.join("in.txt"), "inside\n").unwrap();
    std::fs::write(home.join("out.txt"), "outside\n").unwrap();
    // The node's folders, with a key, as install leaves them.
    let config = root.join("etc/nerve");
    let state = root.join("var/lib/nerve/state");
    nerve_transport::files::write_private(&config.join("keys/lab.key"), b"secret-key\n").unwrap();
    std::fs::create_dir_all(&state).unwrap();
    let own = vec![config.clone(), state.clone()];
    let policy = CenterPolicy {
        mode: Mode::Folder,
        folders: vec![Folder {
            path: work.display().to_string(),
            access: Access::ALL,
        }],
        ..CenterPolicy::default()
    };
    let account = me(&home);
    let call = |cmd: &str| RunCall {
        command: cmd.into(),
        cwd: work.clone(),
        timeout: Some(Duration::from_secs(20)),
    };
    let probe = format!(
        "id -u; echo HOME=$HOME; pwd; cat in.txt; cat {out}; cat {key}; echo end",
        out = home.join("out.txt").display(),
        key = config.join("keys/lab.key").display()
    );

    // While the account can open the node's folders, nothing runs.
    let e = exec::run(&call(&probe), &opts(&policy, &account, &own), |_| {})
        .await
        .unwrap_err();
    assert!(
        e.message.contains("can open the node's own folders"),
        "{}",
        e.message
    );

    // Closed to it, as nerve's folders are: the command runs as the
    // account, in its folder, and reaches nothing outside it.
    set_mode(&config, 0o000);
    set_mode(&root.join("var/lib/nerve"), 0o000);
    let r = exec::run(&call(&probe), &opts(&policy, &account, &own), |_| {}).await;
    set_mode(&config, 0o700);
    set_mode(&root.join("var/lib/nerve"), 0o700);
    let r = r.unwrap();
    let out = r["stdout"].as_str().unwrap();
    let err = r["stderr"].as_str().unwrap();
    assert_eq!(
        out,
        format!(
            "{}\nHOME={}\n{}\ninside\nend\n",
            account.uid,
            home.display(),
            work.display()
        ),
        "{err}"
    );
    assert!(
        !out.contains("outside") && !out.contains("secret-key"),
        "{out}"
    );
    assert!(err.contains("out.txt") && err.contains("lab.key"), "{err}");

    // The key is closed by Landlock too, not only by its folder's bits:
    // with the folders open to the check's eyes but Landlock in force, the
    // command still cannot read it. (The check refuses that case, so the
    // rules are run here without it.)
    let mut o = opts(&policy, &account, &own);
    o.own = Vec::new();
    let r = exec::run(
        &call(&format!("cat {}", config.join("keys/lab.key").display())),
        &o,
        |_| {},
    )
    .await
    .unwrap();
    assert_ne!(r["exit_code"], 0, "{r}");
    assert!(!r["stdout"].as_str().unwrap().contains("secret-key"), "{r}");
}
