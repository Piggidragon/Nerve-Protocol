//! The sudo switch on Windows (docs/user/sudo.md, docs/dev/spec/node-local.md
//! §4). Windows has no sudo program: a sudo command starts with the full
//! token of the account the commands run as. That is the account's logon
//! as a batch job, which UAC does not filter, as the task scheduler logs an
//! account on for a task that runs with highest privileges; an
//! administrator then has the Administrators group in effect. It takes the
//! account's password, and the installed service, which alone may start a
//! process with another account's token (crate::win_user).
//!
//! The switch keeps that password with DPAPI in the config folder
//! ([`SUDO_FILE`]), as `install` keeps the account's password
//! (crate::winsvc::SECRET_FILE). The running service has no control pipe:
//! `nerve-node sudo on` checks the password and writes the file, and
//! the service takes it at its next start; `nerve-node sudo off` removes it,
//! and the running service drops the password within a second ([`settle`]).
//! A center with the settings grant switches the running service directly.
//!
//! The steps go through [`WinSystem`], so they run on every platform in the
//! tests.

use std::io::Write;

use nerve_policy::config::Sudo;
use nerve_policy::settings::SettingsStore;

use crate::paths::NodePaths;
use crate::service::{Account, write_file};
use crate::winsvc::{SERVICE_NAME, WinSystem, parse_secret, secret};

/// The file in the config folder that holds the sudo password, encrypted
/// with DPAPI, while the switch is on.
pub const SUDO_FILE: &str = "sudo.dpapi";

/// Why a node that is not the installed service has no sudo switch.
pub const INSTALLED_ONLY: &str = "on Windows the sudo switch works on the node installed as a service (`nerve-node install`): only the service may start a command with the administrator token of the account commands run as";

/// Why `name`, not an administrator, cannot have the switch.
pub fn not_admin(name: &str) -> String {
    format!(
        "{name} is not an administrator: on Windows a sudo command runs with the administrator rights of the account commands run as, so that account must be in the Administrators group. Then every command of {name}, not only sudo commands, can get those rights back (UAC is no security boundary) and read the node's keys"
    )
}

/// What the owner is told when the switch turns on: the account is an
/// administrator, so its other commands can rise as well
/// (crate::winsvc::admin_warning says the same at install).
pub fn warning(name: &str) -> String {
    format!(
        "Warning: sudo commands run as {name} with its administrator rights. They can change anything on this machine and read the node's keys. {name} is an administrator, and UAC is no security boundary: every other command of {name} can get these rights back too, not only the commands on the sudo list. Allow commands only to centers you trust with this machine."
    )
}

/// Whether the switch may turn on for `account` (`None`: the node runs the
/// commands as its own user) with `password`: the installed node, and an
/// account whose batch logon with that password holds the Administrators
/// group. A wrong password is refused.
pub fn check(sys: &dyn WinSystem, account: Option<&Account>, password: &str) -> Result<(), String> {
    let a = account.ok_or(INSTALLED_ONLY)?;
    if sys.sudo_logon(&a.name, password)? {
        Ok(())
    } else {
        Err(not_admin(&a.name))
    }
}

/// Keeps `password`, `name`'s, with DPAPI in [`SUDO_FILE`].
pub fn keep(
    paths: &NodePaths,
    sys: &dyn WinSystem,
    name: &str,
    password: &str,
) -> Result<(), String> {
    let sealed = sys.protect(&secret(name, password))?;
    write_file(&paths.config_dir.join(SUDO_FILE), &sealed, 0o600)
}

/// Removes [`SUDO_FILE`]; one that is not there is fine.
pub fn forget(paths: &NodePaths) -> Result<(), String> {
    let file = paths.config_dir.join(SUDO_FILE);
    match std::fs::remove_file(&file) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("{}: {e}", file.display())),
    }
}

/// Whether [`SUDO_FILE`] is there.
pub fn kept(paths: &NodePaths) -> bool {
    paths.config_dir.join(SUDO_FILE).is_file()
}

/// The password [`keep`] kept, when it is `user`'s: the account the
/// commands run as now (`machine.user`).
pub fn stored(paths: &NodePaths, sys: &dyn WinSystem, user: Option<&str>) -> Option<String> {
    let user = user?;
    let blob = std::fs::read(paths.config_dir.join(SUDO_FILE)).ok()?;
    let (name, password) = parse_secret(&sys.unprotect(&blob).ok()?)?;
    name.eq_ignore_ascii_case(user).then_some(password)
}

/// What the running node does with the password it holds (crate::sudo).
#[derive(Debug, PartialEq, Eq)]
pub enum Settle {
    /// The switch is on, no password is held and one is kept: a start, or
    /// `sudo on` before it. The node holds the kept one.
    Load,
    /// A password is held but none is kept any more: `sudo off` removed
    /// it. The node drops it, and the switch goes off.
    Drop,
    Nothing,
}

/// [`Settle`] for the switch `on`, whether a password is `held`, and
/// whether one is `kept`.
pub fn settle(on: bool, held: bool, kept: bool) -> Settle {
    match (on, held, kept) {
        (true, false, true) => Settle::Load,
        (true, true, false) => Settle::Drop,
        _ => Settle::Nothing,
    }
}

/// `nerve-node sudo on`: asks for the password of the account the commands
/// run as, checks it ([`check`]) and keeps it ([`keep`]), and sets the
/// switch in the signed config. `installed` says whether `paths` are the
/// installed service's.
pub async fn on(
    paths: &NodePaths,
    sys: &dyn WinSystem,
    installed: bool,
    out: &mut dyn Write,
) -> Result<(), String> {
    if !sys.is_admin() {
        return Err(
            "sudo on needs an administrator: run `nerve-node sudo on` in a terminal opened with \"Run as administrator\"".into(),
        );
    }
    if !installed {
        return Err(INSTALLED_ONLY.into());
    }
    let cfg = SettingsStore::peek(&paths.config_file(), &paths.config_key())?;
    let name = cfg.machine.user.ok_or(
        "no account is chosen for commands; `nerve-node install`, run again as administrator, takes the one that runs it",
    )?;
    let a = sys
        .account(&name)?
        .ok_or_else(|| format!("there is no local account {name}"))?;
    let password = sys.read_password(
        &format!(
            "Password of {}, the account commands from centers run as: ",
            a.name
        ),
        out,
    )?;
    check(sys, Some(&a), &password)?;
    keep(paths, sys, &a.name, &password)?;
    let set = crate::cli::edit(paths, |c| {
        c.machine.sudo = Sudo::On;
        Ok(())
    })
    .await;
    if let Err(e) = set {
        let _ = forget(paths);
        return Err(e);
    }
    let _ = writeln!(
        out,
        "sudo: on (only commands the sudo allow list names run with sudo)\n{}\n`Restart-Service {SERVICE_NAME}` lets the running service take it.",
        warning(&a.name)
    );
    Ok(())
}

/// `nerve-node sudo off`: removes the kept password, which the running
/// service then drops, and sets the switch off in the signed config.
pub async fn off(
    paths: &NodePaths,
    sys: &dyn WinSystem,
    out: &mut dyn Write,
) -> Result<(), String> {
    if !sys.is_admin() {
        return Err(
            "sudo off needs an administrator: run `nerve-node sudo off` in a terminal opened with \"Run as administrator\"".into(),
        );
    }
    forget(paths)?;
    crate::cli::edit(paths, |c| {
        c.machine.sudo = Sudo::Off;
        Ok(())
    })
    .await?;
    let _ = writeln!(
        out,
        "sudo: off (a running service drops the password within a second)"
    );
    Ok(())
}

/// `nerve-node sudo status`: on when the signed config says so and the
/// password is kept.
pub fn status(paths: &NodePaths) -> Result<bool, String> {
    let cfg = SettingsStore::peek(&paths.config_file(), &paths.config_key())?;
    Ok(cfg.machine.sudo == Sudo::On && kept(paths))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::winsvc::tests::{Fake, account, installed};

    fn sudo_of(paths: &NodePaths) -> Sudo {
        SettingsStore::peek(&paths.config_file(), &paths.config_key())
            .unwrap()
            .machine
            .sudo
    }

    #[test]
    fn the_switch_needs_the_installed_node_an_administrator_and_the_right_password() {
        let sys = Fake::new();
        sys.passwords
            .borrow_mut()
            .push(("bob".into(), "bob's".into()));
        let (alice, bob) = (account("alice", 1001, ""), account("bob", 1002, ""));
        assert_eq!(check(&sys, None, "x").unwrap_err(), INSTALLED_ONLY);
        // Alice logs on, but her logon has no Administrators group.
        let e = check(&sys, Some(&alice), "alice's").unwrap_err();
        assert!(e.contains("alice is not an administrator"), "{e}");
        // What making her one means is said.
        assert!(
            e.contains("not only sudo commands") && e.contains("UAC is no security boundary"),
            "{e}"
        );
        let e = check(&sys, Some(&bob), "wrong").unwrap_err();
        assert!(e.contains("password of bob is wrong"), "{e}");
        check(&sys, Some(&bob), "bob's").unwrap();
        assert_eq!(
            sys.calls()
                .iter()
                .filter(|c| c.starts_with("batch logon"))
                .count(),
            3
        );
    }

    #[tokio::test]
    async fn sudo_on_keeps_the_password_with_dpapi_and_sudo_off_removes_it() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        let p = &l.paths;
        let file = p.config_dir.join(SUDO_FILE);
        // Alice, who installed the node, is no administrator.
        sys.types("alice's");
        let e = on(p, &sys, true, &mut Vec::new()).await.unwrap_err();
        assert!(e.contains("alice is not an administrator"), "{e}");
        assert!(!file.exists());
        crate::cli::edit(p, |c| {
            c.machine.user = Some("bob".into());
            Ok(())
        })
        .await
        .unwrap();
        sys.passwords
            .borrow_mut()
            .push(("bob".into(), "bob's".into()));
        // Neither a node that is not installed nor a terminal without the
        // administrators' rights asks for the password.
        let e = on(p, &sys, false, &mut Vec::new()).await.unwrap_err();
        assert_eq!(e, INSTALLED_ONLY);
        let mut user = Fake::new();
        user.admin = false;
        let e = on(p, &user, true, &mut Vec::new()).await.unwrap_err();
        assert!(e.contains("needs an administrator"), "{e}");
        let e = off(p, &user, &mut Vec::new()).await.unwrap_err();
        assert!(e.contains("needs an administrator"), "{e}");
        // A wrong password leaves the switch off and keeps nothing.
        sys.types("wrong");
        let e = on(p, &sys, true, &mut Vec::new()).await.unwrap_err();
        assert!(e.contains("password of bob is wrong"), "{e}");
        assert!(!file.exists());
        assert_eq!(sudo_of(p), Sudo::Off);
        assert!(!status(p).unwrap());
        // The right one: kept sealed, the switch on, the owner warned.
        sys.types("bob's");
        let mut out = Vec::new();
        on(p, &sys, true, &mut out).await.unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("Password of bob"), "{out}");
        assert!(out.contains("sudo: on"), "{out}");
        assert!(
            out.contains("run as bob with its administrator rights"),
            "{out}"
        );
        // Not only sudo commands: the account's others can rise too.
        assert!(
            out.contains("UAC is no security boundary")
                && out.contains("not only the commands on the sudo list"),
            "{out}"
        );
        assert!(out.contains("Restart-Service nerve-node"), "{out}");
        assert!(!out.contains("bob's"), "{out}");
        let blob = std::fs::read(&file).unwrap();
        assert!(!blob.windows(5).any(|w| w == b"bob's"));
        assert_eq!(stored(p, &sys, Some("BOB")).as_deref(), Some("bob's"));
        // A password is one account's.
        assert_eq!(stored(p, &sys, Some("alice")), None);
        assert_eq!(stored(p, &sys, None), None);
        assert_eq!(sudo_of(p), Sudo::On);
        assert!(status(p).unwrap());
        // Off removes it.
        let mut out = Vec::new();
        off(p, &sys, &mut out).await.unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.starts_with("sudo: off"), "{out}");
        assert!(!file.exists());
        assert_eq!(sudo_of(p), Sudo::Off);
        assert!(!status(p).unwrap());
        assert_eq!(stored(p, &sys, Some("bob")), None);
        // Off again is fine.
        off(p, &sys, &mut Vec::new()).await.unwrap();
    }

    /// The running node holds a kept password when the switch is on, and
    /// drops the one it holds when `sudo off` removed it.
    #[test]
    fn the_running_node_follows_the_kept_password() {
        assert_eq!(settle(true, false, true), Settle::Load);
        assert_eq!(settle(true, true, false), Settle::Drop);
        for (on, held, kept) in [
            (true, true, true),
            (true, false, false),
            (false, false, true),
            (false, true, true),
            (false, true, false),
            (false, false, false),
        ] {
            assert_eq!(
                settle(on, held, kept),
                Settle::Nothing,
                "{on} {held} {kept}"
            );
        }
    }
}
