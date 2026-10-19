//! Root's `backup` and `restore` on a node whose folders are another user's,
//! as the installed node's are `nerve`'s: the command runs as that user, but
//! the backup file is opened as the user who asked through sudo, in a folder
//! only that user may open, and the backup written there is that user's.
//! Runs as root only, for example in a user namespace (`unshare
//! --map-root-user --map-auto <the test program>`); it says it skipped
//! otherwise.

#![cfg(target_os = "linux")]

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

/// The node's user and the one who asks, ids nothing else uses.
const NODE: u32 = 4300;
const ASKER: u32 = 4301;

fn chown(path: &Path, id: u32) {
    let status = Command::new("chown")
        .args(["-R", &format!("{id}:{id}")])
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success());
}

fn mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn node(root: &Path, asker: Option<u32>, args: &[&str]) -> std::process::Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_nerve-node"));
    c.arg("--config-dir")
        .arg(root.join("config"))
        .arg("--state-dir")
        .arg(root.join("state"))
        .args(args)
        .env_remove("SUDO_UID")
        .env_remove("SUDO_GID")
        .env_remove("SUDO_USER")
        .env_remove("PKEXEC_UID");
    if let Some(id) = asker {
        c.env("SUDO_UID", id.to_string())
            .env("SUDO_GID", id.to_string());
    }
    c.output().unwrap()
}

fn ok(o: &std::process::Output) {
    assert!(
        o.status.success(),
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
}

#[test]
fn the_backup_file_is_opened_as_the_user_who_asked() {
    if nerve_transport::net::euid() != 0 {
        eprintln!("skipped: needs root (unshare --map-root-user --map-auto)");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let root = d.path();
    mode(root, 0o755);
    ok(&node(root, None, &["config", "set", "node.name", "boxy"]));
    let pass = root.join("state/pass");
    std::fs::write(&pass, "correct horse battery\n").unwrap();
    mode(&pass, 0o600);
    chown(&root.join("config"), NODE);
    chown(&root.join("state"), NODE);

    // The asker's home: nobody else may open it.
    let home = root.join("home");
    std::fs::create_dir(&home).unwrap();
    chown(&home, ASKER);
    mode(&home, 0o700);
    let file = home.join("nerve-node.backup");
    let file_arg = file.to_str().unwrap();
    let pass_arg = pass.to_str().unwrap();

    ok(&node(
        root,
        Some(ASKER),
        &["backup", file_arg, "--passphrase-file", pass_arg],
    ));
    let m = std::fs::metadata(&file).unwrap();
    assert_eq!(
        (m.uid(), m.gid()),
        (ASKER, ASKER),
        "the backup is the asker's"
    );
    assert_eq!(m.mode() & 0o777, 0o600);
    // An existing file stays without --overwrite, and is replaced with it.
    let again = node(
        root,
        Some(ASKER),
        &["backup", file_arg, "--passphrase-file", pass_arg],
    );
    assert!(
        String::from_utf8_lossy(&again.stderr).contains("exists already"),
        "{again:?}"
    );
    ok(&node(
        root,
        Some(ASKER),
        &[
            "backup",
            file_arg,
            "--overwrite",
            "--passphrase-file",
            pass_arg,
        ],
    ));
    ok(&node(
        root,
        Some(ASKER),
        &["restore", file_arg, "--passphrase-file", pass_arg],
    ));
    // What the restore wrote is the node's.
    let toml = std::fs::metadata(root.join("config/node.toml")).unwrap();
    assert_eq!(toml.uid(), NODE);

    // A file the asker may not open is not opened for them by root.
    let closed = root.join("closed");
    std::fs::create_dir(&closed).unwrap();
    mode(&closed, 0o700);
    let o = node(
        root,
        Some(ASKER),
        &[
            "backup",
            closed.join("x.backup").to_str().unwrap(),
            "--passphrase-file",
            pass_arg,
        ],
    );
    assert!(!o.status.success());
    assert!(!closed.join("x.backup").exists());
    // Root's own command opens it as root.
    ok(&node(
        root,
        None,
        &[
            "backup",
            closed.join("x.backup").to_str().unwrap(),
            "--passphrase-file",
            pass_arg,
        ],
    ));
    assert_eq!(std::fs::metadata(closed.join("x.backup")).unwrap().uid(), 0);
}
