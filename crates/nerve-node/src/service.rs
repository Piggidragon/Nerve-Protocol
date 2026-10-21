//! The node as a service (docs/user/service.md): `install`, `update` and
//! `uninstall`, on Linux with systemd. The service runs `nerve-node run`
//! under a user of its own, `nerve`, which owns the node's config and state
//! folders. The owner's commands reach that node with `sudo nerve-node …`:
//! a command root runs on folders that belong to another user runs as that
//! user ([`become_owner`]), so whatever it writes stays the node's.
//!
//! The node runs a center's commands, in every mode, as an ordinary account
//! (`machine.user`, [`crate::account`]), not as `nerve`, so they cannot read
//! the node's keys. `install` takes the account that ran it; `setup` can
//! choose or make another.
//!
//! What these commands do to the machine beyond the node's files (the user,
//! systemd, running a program) goes through [`System`], so the tests run
//! every step on temporary folders.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use nerve_policy::audit::AuditLog;
use nerve_policy::config::SecretStorage;
use nerve_policy::settings::SettingsStore;

use crate::paths::NodePaths;

/// The user the service runs as.
pub const USER: &str = "nerve";
/// The comment `install` gives that user. A `nerve` user without it was not
/// made by `install`: install does not take it over, uninstall leaves it.
pub const USER_MARK: &str = "Nerve node";
/// The systemd unit.
pub const UNIT_NAME: &str = "nerve-node.service";
/// The largest program `update` downloads.
const PROGRAM_MAX: usize = 256 * 1024 * 1024;
/// The largest `SHA256SUMS` `update` downloads.
const SUMS_MAX: usize = 64 * 1024;

/// Where an installed node lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// The systemd unit file.
    pub unit: PathBuf,
    /// The program the service runs.
    pub bin: PathBuf,
    /// The home of the service's user: a command's working folder when the
    /// call names none, and the `~` of the protected list. It holds the
    /// state folder.
    pub home: PathBuf,
    pub paths: NodePaths,
    /// Where `update` finds the programs of the latest release and their
    /// `SHA256SUMS`.
    pub release: String,
    /// The program installed: the node, or the desktop app with its parts.
    pub edition: &'static crate::edition::Edition,
}

impl Layout {
    /// The places on this machine. On Windows the program goes to
    /// `%ProgramFiles%\Nerve` and the folders to `%ProgramData%\Nerve`; the
    /// service is registered with the service control manager, so there is
    /// no unit file ([`crate::winsvc`]).
    pub fn system() -> Layout {
        Layout::of(crate::edition::get())
    }

    /// [`Layout::system`] for `edition`: the program is named after it,
    /// `/usr/local/bin/nerve-node-desktop` for the desktop app.
    pub fn of(edition: &'static crate::edition::Edition) -> Layout {
        let program = edition.program;
        let release = concat!(env!("CARGO_PKG_REPOSITORY"), "/releases/latest/download").into();
        if cfg!(windows) {
            let var = |k: &str, or: &str| {
                std::env::var_os(k)
                    .filter(|v| !v.is_empty())
                    .map_or_else(|| PathBuf::from(or), PathBuf::from)
            };
            let data = var("ProgramData", "C:\\ProgramData").join("Nerve");
            return Layout {
                unit: PathBuf::new(),
                bin: var("ProgramFiles", "C:\\Program Files")
                    .join("Nerve")
                    .join(format!("{program}.exe")),
                paths: NodePaths::new(data.join("config"), data.join("state")),
                home: data,
                release,
                edition,
            };
        }
        Layout {
            unit: PathBuf::from("/etc/systemd/system").join(UNIT_NAME),
            bin: PathBuf::from("/usr/local/bin").join(program),
            home: "/var/lib/nerve".into(),
            paths: NodePaths::new("/etc/nerve", "/var/lib/nerve/state"),
            release,
            edition,
        }
    }

    /// Whether `install` put the node here: its unit is in place, or on
    /// Windows its service is registered.
    /// Whether the unit file is in place: [`Layout::installed`] on Linux,
    /// for a layout of any folders (the tests').
    fn installed_at_unit(&self) -> bool {
        self.unit.is_file()
    }

    /// The polkit rule that lets the owners start and stop the service
    /// (crate::owner): `/etc/polkit-1/rules.d`, beside the unit's `/etc`.
    pub fn polkit_rule(&self) -> PathBuf {
        self.etc().join("polkit-1/rules.d").join(POLKIT_RULE)
    }

    /// The `/etc` the unit is in.
    fn etc(&self) -> &Path {
        self.unit.ancestors().nth(3).unwrap_or(Path::new("/etc"))
    }

    /// The helper that starts, stops and restarts the service and does
    /// nothing else, which the owners run through pkexec
    /// ([`service_helper_text`]): beside the program's `bin`, in
    /// `/usr/local/lib/nerve-node`.
    pub fn service_helper(&self) -> PathBuf {
        let local = self
            .bin
            .parent()
            .and_then(Path::parent)
            .unwrap_or(Path::new("/usr/local"));
        local.join("lib/nerve-node").join(SERVICE_HELPER)
    }

    /// The polkit action of [`Layout::service_helper`]: in
    /// `/usr/share/polkit-1/actions`, the one folder polkit reads them from.
    pub fn polkit_action(&self) -> PathBuf {
        self.etc()
            .parent()
            .unwrap_or(Path::new("/"))
            .join("usr/share/polkit-1/actions")
            .join(format!("{POLKIT_ACTION}.policy"))
    }

    /// The `.pkla` file that lets the owners run the helper on a polkit
    /// without rules (0.105).
    pub fn polkit_pkla(&self) -> PathBuf {
        self.etc()
            .join("polkit-1/localauthority/50-local.d")
            .join(POLKIT_PKLA)
    }

    pub fn installed(&self) -> bool {
        #[cfg(windows)]
        {
            crate::win_host::service_registered()
        }
        #[cfg(not(windows))]
        {
            cfg!(target_os = "linux") && self.unit.is_file()
        }
    }

    /// The service unit. The node runs as its own user with the folders
    /// given; stopping the service ends every command it runs, and a node
    /// that fails is started again. CAP_SETUID and CAP_SETGID are the one
    /// privilege it keeps: they let it start a command as the
    /// account `machine.user` names. Every command drops them before it
    /// runs; the bounding set stays as it is, since an allowed sudo command
    /// needs root's. The service's cgroup is the node's to divide
    /// (`Delegate=`): each command runs in one of its own below it, held to
    /// its limits (crate::cgroup). A command the kernel kills for its memory
    /// leaves the node running (`OOMPolicy=`, which `Delegate=` defaults to
    /// already). systemd makes the node's runtime folder, where its owners
    /// reach it (crate::owner); every account may enter it. The node holds
    /// the owners' group besides its own, so that it can give them its owner
    /// token to read, and nothing else: who is an owner is looked up in the
    /// account database, which does not name the node's user.
    pub fn unit_text(&self) -> String {
        format!(
            "# Written by `nerve-node install`; `nerve-node uninstall` removes it.
[Unit]
Description=Nerve node
Documentation={repo}
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User={USER}
Group={USER}
SupplementaryGroups={owners}
Environment=HOME={home}
AmbientCapabilities=CAP_SETUID CAP_SETGID
Delegate=cpu memory pids
OOMPolicy=continue
ExecStart={bin} --config-dir {config} --state-dir {state} run
ExecReload=kill -HUP $MAINPID
RuntimeDirectory={runtime}
RuntimeDirectoryMode=0755
Restart=on-failure
RestartSec=5
UMask=0077

[Install]
WantedBy=multi-user.target
",
            repo = env!("CARGO_PKG_REPOSITORY"),
            home = self.home.display(),
            bin = self.bin.display(),
            config = self.paths.config_dir.display(),
            state = self.paths.state_dir.display(),
            owners = crate::owner::GROUP,
            runtime = Path::new(crate::owner::RUNTIME_DIR)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy(),
        )
    }
}

/// The file name of the polkit rule ([`Layout::polkit_rule`]).
pub const POLKIT_RULE: &str = "50-nerve-node.rules";

/// The file name of the `.pkla` file ([`Layout::polkit_pkla`]).
pub const POLKIT_PKLA: &str = "50-nerve-node.pkla";

/// The polkit action of the service helper ([`Layout::service_helper`]).
pub const POLKIT_ACTION: &str = "org.nerve-protocol.node.service-control";

/// The file name of the service helper.
pub const SERVICE_HELPER: &str = "service-control";

/// The service helper: a script that starts, stops or restarts the
/// installed unit and does nothing else. pkexec runs it as root for the
/// owners without a password ([`polkit_action_text`]), also on polkit 0.105,
/// which takes no rule that could limit systemd's own action to one unit.
/// It takes one word and nothing from its environment: pkexec matches an
/// action by the program's path only, never by its arguments.
pub fn service_helper_text() -> String {
    format!(
        "#!/bin/sh
# Written by `nerve-node install`; `nerve-node uninstall` removes it.
# Starts, stops or restarts the Nerve node's service {UNIT_NAME}, and does
# nothing else. The node's owners (the group {group}) run it through pkexec
# without a password (polkit action {POLKIT_ACTION}).
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
if [ \"$#\" -ne 1 ]; then
    echo \"usage: $0 start|stop|restart\" >&2
    exit 2
fi
case \"$1\" in
start | stop | restart) exec systemctl \"$1\" {UNIT_NAME} ;;
*)
    echo \"usage: $0 start|stop|restart\" >&2
    exit 2
    ;;
esac
",
        group = crate::owner::GROUP
    )
}

/// The polkit action of the service helper at `helper`: an administrator by
/// default; the owners by the rule ([`polkit_rule_text`]) or the `.pkla`
/// file ([`polkit_pkla_text`]).
pub fn polkit_action_text(helper: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<!-- Written by `nerve-node install`; `nerve-node uninstall` removes it. -->
<policyconfig>
  <vendor>Nerve</vendor>
  <action id="{POLKIT_ACTION}">
    <description>Start, stop or restart the Nerve node</description>
    <message>Authentication is required to start, stop or restart the Nerve node</message>
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.exec.path">{helper}</annotate>
  </action>
</policyconfig>
"#,
        helper = helper.display()
    )
}

/// The `.pkla` file for polkit 0.105: the owners may run the service
/// helper without a password from their own session at this machine
/// (`ResultActive`); anyone else, and an owner elsewhere, keeps the
/// action's default. Never one for systemd's `manage-units`, which would
/// let them manage every unit.
pub fn polkit_pkla_text() -> String {
    format!(
        "# Written by `nerve-node install`; `nerve-node uninstall` removes it.
# The members of {group}, the owners of the Nerve node, may start, stop and
# restart its service through its helper from their own session at this
# machine, and nothing else.
[Nerve node: start, stop and restart]
Identity=unix-group:{group}
Action={POLKIT_ACTION}
ResultActive=yes
",
        group = crate::owner::GROUP
    )
}

/// The polkit rule: the owners may start, stop and restart the node's
/// service, and nothing else: through systemd, which names the unit and the
/// verb of each request (`org.freedesktop.systemd1.manage-units`), or
/// through the service helper ([`POLKIT_ACTION`]).
pub fn polkit_rule_text() -> String {
    format!(
        "// Written by `nerve-node install`; `nerve-node uninstall` removes it.
// The members of {group}, the owners of the Nerve node, may start, stop and
// restart its service {UNIT_NAME} from their own session at this machine,
// and nothing else. A program outside a session, such as a command the
// node runs, is asked for an administrator's password as before.
polkit.addRule(function(action, subject) {{
    if (!subject.isInGroup(\"{group}\") || !subject.local || !subject.active) {{
        return polkit.Result.NOT_HANDLED;
    }}
    if (action.id == \"{POLKIT_ACTION}\") {{
        return polkit.Result.YES;
    }}
    if (action.id == \"org.freedesktop.systemd1.manage-units\" &&
        action.lookup(\"unit\") == \"{UNIT_NAME}\") {{
        var verb = action.lookup(\"verb\");
        if (verb == \"start\" || verb == \"stop\" || verb == \"restart\") {{
            return polkit.Result.YES;
        }}
    }}
    return polkit.Result.NOT_HANDLED;
}});
",
        group = crate::owner::GROUP
    )
}

/// What polkit on this machine takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Polkit {
    /// Rules in JavaScript (polkit 0.106 and later).
    Rules,
    /// polkit without them (0.105, Ubuntu 22.04): `.pkla` files.
    Old,
    /// No polkit.
    Missing,
}

/// Which polkit `pkaction --version` names (`pkaction version 0.105`,
/// `pkaction version 124`); `None` when it names none. Rules came with
/// 0.106; from 0.120 on the versions have one number.
pub fn polkit_of_version(said: &str) -> Option<Polkit> {
    let v = said.split_whitespace().last()?;
    let mut parts = v.split('.').map(|p| p.parse::<u32>().ok());
    let major = parts.next()??;
    let minor = parts.next().flatten().unwrap_or(0);
    Some(if major == 0 && minor < 106 {
        Polkit::Old
    } else {
        Polkit::Rules
    })
}

/// Whether a node on `paths` is the installed service, however it was
/// started: on the installed folders, or as the user `install` made. Such a
/// node runs commands only as the account `machine.user` names, never as
/// itself ([`crate::account::for_commands`]), even without the two
/// capabilities the unit gives it.
pub fn is_service_node(paths: &NodePaths) -> bool {
    if *paths == Layout::system().paths {
        return true;
    }
    #[cfg(any(unix, windows))]
    {
        let me = crate::account::own_uid();
        me != 0
            && matches!(crate::account::lookup(USER), Ok(Some(a)) if a.uid == me && a.comment == USER_MARK)
    }
    #[cfg(not(any(unix, windows)))]
    false
}

/// A user account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    /// The comment field, where [`USER_MARK`] goes.
    pub comment: String,
    pub home: PathBuf,
    /// Every group the account is in, its own included.
    pub groups: Vec<u32>,
}

/// What install, update and uninstall do to the machine besides writing the
/// node's files.
pub trait System {
    fn is_root(&self) -> bool;
    /// Whether systemd runs this machine.
    fn has_systemd(&self) -> bool;
    fn account(&self, name: &str) -> Result<Option<Account>, String>;
    /// The groups of [`crate::account::ROOT_GROUPS`] the account is in.
    fn root_groups(&self, account: &Account) -> Vec<String>;
    /// Whether `account` gets root through sudo without a password
    /// (`sudo -n true`, run as it).
    fn sudo_without_password(&self, _account: &Account) -> bool {
        false
    }
    /// Makes a system user with a group of the same name, the home given
    /// (not created) and no login, marked with [`USER_MARK`].
    fn add_account(&self, name: &str, home: &Path) -> Result<(), String>;
    /// Makes an ordinary account for the commands, as `setup` offers: a
    /// group of its own, the home given (created), no login, marked with
    /// [`crate::account::MADE_MARK`].
    fn add_user(&self, name: &str, home: &Path) -> Result<(), String>;
    /// Removes the user and its group.
    fn remove_account(&self, name: &str) -> Result<(), String>;
    fn systemctl(&self, args: &[&str]) -> Result<(), String>;
    /// Gives `path` and everything below it to `uid`:`gid`.
    fn give(&self, path: &Path, uid: u32, gid: u32) -> Result<(), String>;
    /// Waits until the node the service started answers on its control
    /// socket.
    fn wait_running(&self, paths: &NodePaths) -> Result<(), String>;
    /// What `<program> --version` prints, run as `account`.
    fn version_of(&self, program: &Path, account: &Account) -> Result<String, String>;
    /// The state of the installed unit: running, stopped, starting,
    /// stopping or failed, and whether it starts with the machine.
    fn unit_state(&self) -> Result<ServiceState, String>;
    /// Ends the session a system keyring gave `name` (`loginctl
    /// enable-linger`, [`crate::keyring_setup`]), so that the user can go;
    /// `Ok(false)` when it had none.
    fn end_session(&self, _name: &str) -> Result<bool, String> {
        Ok(false)
    }
    /// Whether the group `name` is there.
    fn has_group(&self, _name: &str) -> Result<bool, String> {
        Ok(false)
    }
    /// Makes the system group `name`.
    fn add_group(&self, name: &str) -> Result<(), String> {
        Err(format!("cannot make the group {name} here"))
    }
    /// Puts the account `user` in the group `group`.
    fn add_to_group(&self, user: &str, group: &str) -> Result<(), String> {
        Err(format!("cannot put {user} in the group {group} here"))
    }
    /// Removes the group `name`.
    fn remove_group(&self, name: &str) -> Result<(), String> {
        Err(format!("cannot remove the group {name} here"))
    }
    /// What polkit takes here; the rules go to `rule`'s folder.
    fn polkit(&self, _rule: &Path) -> Polkit {
        Polkit::Missing
    }
    /// Whether `pkexec` is there.
    fn has_pkexec(&self) -> bool {
        false
    }
    /// Runs `program` with `args` as root through `pkexec`, which asks
    /// polkit; never through a text agent in a terminal.
    fn pkexec(&self, program: &Path, _args: &[&str]) -> Result<(), String> {
        Err(format!(
            "cannot run {} through pkexec here",
            program.display()
        ))
    }
}

/// The `pkexec` of this machine: on `PATH`, else in `/usr/bin`.
fn pkexec_program() -> Option<PathBuf> {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .chain([PathBuf::from("/usr/bin")])
        .map(|d| d.join("pkexec"))
        .find(|p| p.is_file())
}

/// This machine.
pub struct Host;

impl System for Host {
    fn is_root(&self) -> bool {
        nerve_transport::net::euid() == 0
    }

    fn has_systemd(&self) -> bool {
        Path::new("/run/systemd/system").is_dir()
    }

    fn account(&self, name: &str) -> Result<Option<Account>, String> {
        crate::account::lookup(name)
    }

    fn root_groups(&self, account: &Account) -> Vec<String> {
        crate::account::root_groups(account)
    }

    fn sudo_without_password(&self, account: &Account) -> bool {
        // Sudo run as root for the account, so no password is asked for
        // the switch. The rules come first: an account whose rules surely
        // grant no root command without a password is never run as,
        // because its sudo would log a failed login and mail root about it.
        // The rules are read to err towards running as the account.
        let mut list = std::process::Command::new("sudo");
        list.args(["-n", "-l", "-U", &account.name])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        regain_root(&mut list);
        let Ok(o) = list.output() else {
            return false;
        };
        let listing = String::from_utf8_lossy(&o.stdout);
        if !crate::account::lists_no_password(&listing) {
            return false;
        }
        // Where the account's sudo would call PAM even with `-n` (sudo-rs,
        // `noninteractive_auth`), a probe counts as a failed login that
        // can lock the account (pam_faillock): the rules say alone.
        let mut v = std::process::Command::new("sudo");
        v.arg("-V")
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        regain_root(&mut v);
        // Only a sudo that says so on stdout is known to stay out of PAM.
        let version = match v.output() {
            Ok(v) if v.status.success() => String::from_utf8_lossy(&v.stdout).into_owned(),
            _ => String::new(),
        };
        if !crate::account::probe_stays_out_of_pam(&version, &listing) {
            return true;
        }
        // The account's own sudo, which `-n` never lets ask, and `-k`
        // keeps from taking the ticket its owner has just made by typing
        // the password for this command. As root, whatever `runas_default`
        // says: that is what the rules were read for.
        let mut c = std::process::Command::new("sudo");
        c.args([
            "-n",
            "-u",
            &account.name,
            "--",
            "sudo",
            "-n",
            "-k",
            "-u",
            "root",
            "--",
            "true",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
        regain_root(&mut c);
        c.status().is_ok_and(|s| s.success())
    }

    fn add_user(&self, name: &str, home: &Path) -> Result<(), String> {
        let mut c = std::process::Command::new("useradd");
        c.args(["--user-group", "--create-home", "--home-dir"])
            .arg(home)
            .args([
                "--shell",
                no_login(),
                "--comment",
                crate::account::MADE_MARK,
                "--",
                name,
            ]);
        // setup runs as the node's user and keeps root only as its saved
        // id ([`become_owner`]); useradd gets it back.
        regain_root(&mut c);
        let o = c.output().map_err(|e| format!("useradd: {e}"))?;
        if o.status.success() {
            Ok(())
        } else {
            Err(format!("useradd {name}: {}", failure(&o)))
        }
    }

    fn add_account(&self, name: &str, home: &Path) -> Result<(), String> {
        let shell = no_login();
        run(
            "useradd",
            &[
                "--system",
                "--user-group",
                "--home-dir",
                &home.display().to_string(),
                "--no-create-home",
                "--shell",
                shell,
                "--comment",
                USER_MARK,
                name,
            ],
        )
    }

    fn remove_account(&self, name: &str) -> Result<(), String> {
        run("userdel", &[name])?;
        // userdel takes the group along where the system makes one group per
        // user; elsewhere it stays behind.
        let group = std::process::Command::new("getent")
            .args(["group", name])
            .output()
            .is_ok_and(|o| o.status.success());
        if group {
            run("groupdel", &[name])?;
        }
        Ok(())
    }

    fn systemctl(&self, args: &[&str]) -> Result<(), String> {
        let mut c = std::process::Command::new("systemctl");
        c.args(args);
        // setup restarts the node after it installed a keyring.
        regain_root(&mut c);
        let o = c.output().map_err(|e| format!("systemctl: {e}"))?;
        if o.status.success() {
            Ok(())
        } else {
            Err(format!("systemctl {}: {}", args.join(" "), failure(&o)))
        }
    }

    fn give(&self, path: &Path, uid: u32, gid: u32) -> Result<(), String> {
        chown_tree(path, uid, gid)
    }

    fn unit_state(&self) -> Result<ServiceState, String> {
        let o = std::process::Command::new("systemctl")
            .args(["show", "--property=ActiveState,UnitFileState", UNIT_NAME])
            .output()
            .map_err(|e| format!("systemctl: {e}"))?;
        if !o.status.success() {
            return Err(format!("systemctl show {UNIT_NAME}: {}", failure(&o)));
        }
        Ok(unit_state_of(&String::from_utf8_lossy(&o.stdout)))
    }

    fn wait_running(&self, paths: &NodePaths) -> Result<(), String> {
        #[cfg(unix)]
        {
            use std::io::{BufRead, BufReader};
            let ask = || -> std::io::Result<bool> {
                let mut s = match std::os::unix::net::UnixStream::connect(paths.ctl_socket()) {
                    // An owner without root, after `service start`: the
                    // owner socket says that the node runs too.
                    Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                        std::os::unix::net::UnixStream::connect(crate::owner::socket())?
                    }
                    r => r?,
                };
                s.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
                // The node answers a request with the token it wrote at
                // its start, which root can read.
                let request = nerve_transport::ctl::request_line(
                    &paths.ctl_socket(),
                    "status",
                    serde_json::json!({}),
                );
                s.write_all(format!("{request}\n").as_bytes())?;
                let mut line = String::new();
                BufReader::new(s).read_line(&mut line)?;
                Ok(line.contains("\"ok\""))
            };
            for _ in 0..60 {
                if ask().unwrap_or(false) {
                    return Ok(());
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
            Err(format!(
                "the service started, but the node does not answer on {}; `journalctl -u {UNIT_NAME}` says why",
                paths.ctl_socket().display()
            ))
        }
        #[cfg(not(unix))]
        {
            let _ = paths;
            Err(LINUX_ONLY.into())
        }
    }

    fn version_of(&self, program: &Path, account: &Account) -> Result<String, String> {
        let mut c = std::process::Command::new(program);
        c.arg("--version");
        // A downloaded program runs as the service's user, not as root.
        #[cfg(unix)]
        if self.is_root() {
            use std::os::unix::process::CommandExt;
            c.uid(account.uid).gid(account.gid);
        }
        #[cfg(not(unix))]
        let _ = account;
        let o = c
            .output()
            .map_err(|e| format!("{}: {e}", program.display()))?;
        if !o.status.success() {
            return Err(format!("{} --version: {}", program.display(), failure(&o)));
        }
        Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
    }

    fn end_session(&self, name: &str) -> Result<bool, String> {
        if !Path::new("/var/lib/systemd/linger").join(name).exists() {
            return Ok(false);
        }
        run("loginctl", &["disable-linger", name])?;
        // userdel refuses a user whose processes (the keyring) still run;
        // systemctl waits until the session's manager has stopped them.
        if let Ok(Some(a)) = self.account(name) {
            let _ = run("systemctl", &["stop", &format!("user@{}.service", a.uid)]);
        }
        let _ = run("loginctl", &["terminate-user", name]);
        Ok(true)
    }

    fn has_group(&self, name: &str) -> Result<bool, String> {
        #[cfg(unix)]
        return Ok(crate::owner::group_id(name).is_some());
        #[cfg(not(unix))]
        {
            let _ = name;
            Ok(false)
        }
    }

    fn add_group(&self, name: &str) -> Result<(), String> {
        run("groupadd", &["--system", name])
    }

    fn add_to_group(&self, user: &str, group: &str) -> Result<(), String> {
        run("usermod", &["--append", "--groups", group, "--", user])
    }

    fn remove_group(&self, name: &str) -> Result<(), String> {
        run("groupdel", &[name])
    }

    fn has_pkexec(&self) -> bool {
        pkexec_program().is_some()
    }

    fn pkexec(&self, program: &Path, args: &[&str]) -> Result<(), String> {
        let pkexec = pkexec_program().ok_or("pkexec is not installed")?;
        let o = std::process::Command::new(pkexec)
            .arg("--disable-internal-agent")
            .arg(program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| format!("pkexec: {e}"))?;
        match o.status.code() {
            Some(0) => Ok(()),
            // pkexec's own: not authorized (or no agent to ask), and
            // dismissed.
            Some(126 | 127) => Err(format!(
                "polkit did not let you {}: the owners do it without a password from their own session at this machine; elsewhere `sudo {} service {}` does ({})",
                args.join(" "),
                crate::edition::get().program,
                args.join(" "),
                failure(&o)
            )),
            _ => Err(format!(
                "{} {}: {}",
                program.display(),
                args.join(" "),
                failure(&o)
            )),
        }
    }

    fn polkit(&self, rule: &Path) -> Polkit {
        // By its version: a polkit 0.105 has the rules folders too where a
        // package put a rule there for newer ones (systemd's own does).
        let said = std::process::Command::new("pkaction")
            .arg("--version")
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output();
        if let Some(p) = said
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| polkit_of_version(&String::from_utf8_lossy(&o.stdout)))
        {
            return p;
        }
        let rules = rule.parent().unwrap_or(Path::new("/etc/polkit-1/rules.d"));
        // polkit 0.106 and later read rules from both folders; the one in
        // /usr is the package's, there whether or not /etc has one yet.
        if rules.is_dir() || Path::new("/usr/share/polkit-1/rules.d").is_dir() {
            Polkit::Rules
        } else if Path::new("/etc/polkit-1").is_dir() || Path::new("/usr/bin/pkexec").exists() {
            Polkit::Old
        } else {
            Polkit::Missing
        }
    }
}

/// The shell of an account that does not log in.
pub fn no_login() -> &'static str {
    ["/usr/sbin/nologin", "/sbin/nologin"]
        .into_iter()
        .find(|s| Path::new(s).exists())
        .unwrap_or("/bin/false")
}

const LINUX_ONLY: &str = "works on Linux with systemd only; elsewhere run `nerve-node run` under your own service manager";

/// Runs a system tool; its error output is the error.
/// Lets `c` run as root where this process keeps root only as its saved id
/// (setup on the installed node, [`become_owner`]); elsewhere it runs as
/// this process does.
fn regain_root(c: &mut std::process::Command) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        let (mut r, mut e, mut s) = (0, 0, 0);
        // SAFETY: getresuid writes the three ids it is given.
        unsafe { libc::getresuid(&mut r, &mut e, &mut s) };
        if e == 0 || s != 0 {
            return;
        }
        // SAFETY: plain system calls between fork and exec.
        unsafe {
            c.pre_exec(|| {
                if libc::setresuid(0, 0, 0) != 0
                    || libc::setresgid(0, 0, 0) != 0
                    || libc::setgroups(0, std::ptr::null()) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = c;
}

/// Runs a system tool; its error output is the error.
pub fn run(program: &str, args: &[&str]) -> Result<(), String> {
    let o = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    if o.status.success() {
        Ok(())
    } else {
        Err(format!("{program} {}: {}", args.join(" "), failure(&o)))
    }
}

fn failure(o: &std::process::Output) -> String {
    let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
    if err.is_empty() {
        o.status.to_string()
    } else {
        err
    }
}

/// The steps a command did, shown as they are done and audited at its end.
pub(crate) struct Steps<'a> {
    pub(crate) done: Vec<String>,
    pub(crate) out: &'a mut dyn Write,
}

impl Steps<'_> {
    pub(crate) fn did(&mut self, step: impl Into<String>) {
        let step = step.into();
        let _ = writeln!(self.out, "{step}");
        self.done.push(step);
    }
}

/// Whether `what` can run here: Linux, root and systemd.
fn supported(sys: &dyn System, what: &str) -> Result<(), String> {
    if !sys.is_root() && cfg!(target_os = "linux") {
        return Err(format!("{what} needs root: run `sudo nerve-node {what}`"));
    }
    supported_without_root(sys, what)
}

/// Whether `what` can run here: Linux and systemd.
fn supported_without_root(sys: &dyn System, what: &str) -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err(format!("{what} {LINUX_ONLY}"));
    }
    if !sys.has_systemd() {
        return Err(format!(
            "{what} needs systemd, which does not run this machine; run `nerve-node run` under your own service manager"
        ));
    }
    Ok(())
}

/// Writes the command's audit entry, when the state folder is there to hold
/// it. It is written as the folder's owner ([`as_owner_of`]): root does not
/// write through a link that the node's user put there. A folder given to
/// root (by `uninstall`, or one an earlier uninstall left) is written as
/// root, so the log must be a plain file of one name there: a link that was
/// given away with the folder would otherwise be followed with root's rights.
pub(crate) fn audit(
    paths: &NodePaths,
    event: &str,
    steps: &[String],
    r: &Result<(), String>,
    out: &mut dyn Write,
) {
    if !paths.state_dir.is_dir() {
        return;
    }
    let log = AuditLog::new(paths.audit_log());
    let written = as_owner_of(&paths.state_dir).and_then(|_owner| {
        plain_log(log.path())?;
        log.node(event, steps, r.as_ref().err().map(String::as_str))
            .map_err(|e| e.to_string())
    });
    if let Err(e) = written {
        let _ = writeln!(out, "the audit log cannot be written: {e}");
    }
}

/// Refuses an audit log that is not a plain file with one name (one that
/// is not there yet is fine). The check holds in a folder of root's, which
/// nobody else can change between it and the write; in one of `nerve`'s,
/// the write runs as `nerve` anyway.
fn plain_log(log: &Path) -> Result<(), String> {
    let m = match std::fs::symlink_metadata(log) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("{}: {e}", log.display())),
    };
    if !m.file_type().is_file() {
        return Err(format!(
            "{} is not a plain file (a link?); root does not write through it",
            log.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if m.nlink() > 1 {
            return Err(format!(
                "{} has more than one name, and another may be outside the node's folders",
                log.display()
            ));
        }
    }
    Ok(())
}

/// `install`: the user, the folders, the account of the commands, the
/// program, the unit, the running service, in that order. `invoker` is the
/// account that ran install (`SUDO_USER`, else root); it becomes the account
/// of the commands unless one is chosen already, and the account chosen is
/// warned about when it gets root. Running it again puts back
/// what is missing and restarts the service.
pub fn install(
    layout: &Layout,
    sys: &dyn System,
    exe: &Path,
    invoker: &str,
    out: &mut dyn Write,
) -> Result<(), String> {
    let keyring = crate::keyring_setup::HostKeyring {
        exe: layout.bin.clone(),
    };
    install_asking(layout, sys, &keyring, None, exe, invoker, out)
}

/// [`install`] in a terminal: `input` answers the question whether to
/// install a system keyring, asked when the node's keys are to be in one
/// and none answers for its user ([`crate::keyring_setup`]). `keyring` asks
/// through the installed program, which that user can run.
pub fn install_asking(
    layout: &Layout,
    sys: &dyn System,
    keyring: &dyn crate::keyring_setup::Keyring,
    input: Option<&mut dyn BufRead>,
    exe: &Path,
    invoker: &str,
    out: &mut dyn Write,
) -> Result<(), String> {
    supported(sys, "install")?;
    let mut steps = Steps {
        done: Vec::new(),
        out,
    };
    let r = install_steps(layout, sys, keyring, input, exe, invoker, &mut steps);
    audit(&layout.paths, "install", &steps.done, &r, steps.out);
    r?;
    let _ = writeln!(
        steps.out,
        "Next: `sudo nerve-node setup` names the node and pairs it with its first center."
    );
    Ok(())
}

fn install_steps(
    layout: &Layout,
    sys: &dyn System,
    keyring: &dyn crate::keyring_setup::Keyring,
    input: Option<&mut dyn BufRead>,
    exe: &Path,
    invoker: &str,
    steps: &mut Steps,
) -> Result<(), String> {
    // Keys in the keyring where they may not be there (an old Landlock):
    // the installed node would not start, so install changes nothing.
    if crate::secrets::stated_storage(&layout.paths) == SecretStorage::Keyring
        && let Some(n) = crate::secrets::no_keyring(&layout.paths)
    {
        return Err(crate::secrets::keyring_refused(
            &layout.paths,
            n,
            "install changed nothing",
            "run `sudo nerve-node install` again",
        ));
    }
    let account = match sys.account(USER)? {
        Some(a) if a.comment == USER_MARK => {
            steps.did(format!("the user {USER} is there already"));
            a
        }
        Some(_) => {
            return Err(format!(
                "a user {USER} exists already, and nerve-node install did not make it; the node needs a user of its own"
            ));
        }
        None => {
            sys.add_account(USER, &layout.home)?;
            let a = sys
                .account(USER)?
                .ok_or_else(|| format!("useradd made no user {USER}"))?;
            steps.did(format!("made the user {USER} (uid {})", a.uid));
            a
        }
    };
    let dirs = [
        &layout.home,
        &layout.paths.config_dir,
        &layout.paths.state_dir,
    ];
    for dir in dirs {
        nerve_transport::files::create_private_dir(dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?;
        // An earlier install's folder may hold what its user put there; it
        // is changed as that user, and a link in its place is refused.
        let _owner = as_owner_of(dir)?;
        set_mode(dir, 0o700)?;
    }
    // The folders may be left from an earlier install, whose user had
    // another uid: everything in them is given to this one.
    for dir in dirs {
        sys.give(dir, account.uid, account.gid)?;
    }
    steps.did(format!(
        "{} and {} belong to {USER}",
        layout.paths.config_dir.display(),
        layout.paths.state_dir.display()
    ));
    let in_keyring = crate::secrets::stated_storage(&layout.paths) == SecretStorage::Keyring;
    if in_keyring {
        // Root does not open the keyring of the node's user, so the account
        // is left to setup, which runs as that user.
        steps
            .did("the account of the commands stays as it is; `sudo nerve-node setup` chooses one");
    } else {
        default_account(layout, sys, invoker, steps);
    }
    let real = |p: &Path| std::fs::canonicalize(p).ok();
    if real(exe).is_some() && real(exe) == real(&layout.bin) {
        steps.did(format!(
            "the program is at {} already",
            layout.bin.display()
        ));
    } else {
        let program = std::fs::read(exe).map_err(|e| format!("{}: {e}", exe.display()))?;
        write_file(&layout.bin, &program, 0o755)?;
        steps.did(format!("put the program at {}", layout.bin.display()));
    }
    // The old program goes over at once: a running one keeps its file.
    install_parts(layout, steps)?;
    // A node whose keys are in the system keyring does not start without
    // one that answers for its user; the installed program asks it.
    if in_keyring {
        crate::keyring_setup::ensure(keyring, &account, input, steps.out)?;
        steps.did(format!(
            "the node's keys are in the system keyring of {USER}, and it answers"
        ));
    }
    put_owners(layout, sys, invoker, true, steps)?;
    write_file(&layout.unit, layout.unit_text().as_bytes(), 0o644)?;
    steps.did(format!("wrote the service unit {}", layout.unit.display()));
    sys.systemctl(&["daemon-reload"])?;
    sys.systemctl(&["enable", UNIT_NAME])?;
    sys.systemctl(&["restart", UNIT_NAME])?;
    sys.wait_running(&layout.paths)?;
    steps.did(format!(
        "the service {UNIT_NAME} runs as {USER} and starts with the machine"
    ));
    Ok(())
}

/// The owners' parts (crate::owner): the group, `invoker` in it, and the
/// polkit rule for the service. `invoker` joins at install
/// (`always`), and at an update only when the group is made then: an
/// install from before the owners had none.
fn put_owners(
    layout: &Layout,
    sys: &dyn System,
    invoker: &str,
    always: bool,
    steps: &mut Steps,
) -> Result<(), String> {
    let group = crate::owner::GROUP;
    let made = !sys.has_group(group)?;
    if made {
        sys.add_group(group)?;
        steps.did(format!("made the group {group} of the node's owners"));
    }
    let program = layout.edition.program;
    if always || made {
        match sys.account(invoker)? {
            Some(a) if a.uid != 0 => {
                sys.add_to_group(invoker, group)?;
                steps.did(format!(
                    "{invoker} is an owner of the node ({group}): `{program}` changes its settings and starts and stops it without sudo"
                ));
            }
            _ => steps.did(format!(
                "no owner besides root: `sudo usermod --append --groups {group} NAME` makes NAME one"
            )),
        }
    }
    let rule = layout.polkit_rule();
    let polkit = sys.polkit(&rule);
    if polkit == Polkit::Missing {
        steps.did("Warning: polkit is not installed: starting and stopping the service needs sudo");
        return Ok(());
    }
    // The helper and its action on every polkit; what lets the owners run
    // it is the rule, or on 0.105 the `.pkla` file, and only the one this
    // polkit reads is kept.
    let helper = layout.service_helper();
    let mut wrote = false;
    for (path, text, mode) in [
        (helper.clone(), service_helper_text(), 0o755),
        (layout.polkit_action(), polkit_action_text(&helper), 0o644),
        if polkit == Polkit::Rules {
            (rule.clone(), polkit_rule_text(), 0o644)
        } else {
            (layout.polkit_pkla(), polkit_pkla_text(), 0o644)
        },
    ] {
        if std::fs::read_to_string(&path).ok().as_deref() != Some(text.as_str()) {
            write_file(&path, text.as_bytes(), mode)?;
            wrote = true;
        }
    }
    let other = if polkit == Polkit::Rules {
        layout.polkit_pkla()
    } else {
        rule
    };
    remove_if_there(&other)?;
    if wrote {
        let by = match polkit {
            Polkit::Rules => format!("the rule {}", layout.polkit_rule().display()),
            _ => format!("{} (polkit 0.105)", layout.polkit_pkla().display()),
        };
        steps.did(format!(
            "polkit lets the owners start, stop and restart the service without a password, by {by} and the helper {}",
            helper.display()
        ));
    }
    Ok(())
}

/// Removes the file at `path` when it is there.
fn remove_if_there(path: &Path) -> Result<bool, String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Removes the owners' parts again: the polkit files, the service helper
/// and the group.
fn remove_owners(layout: &Layout, sys: &dyn System, steps: &mut Steps) -> Result<(), String> {
    let helper = layout.service_helper();
    for path in [
        layout.polkit_rule(),
        layout.polkit_pkla(),
        layout.polkit_action(),
        helper.clone(),
    ] {
        if remove_if_there(&path)? {
            steps.did(format!("removed {}", path.display()));
        }
    }
    // Its folder is the helper's alone.
    if let Some(dir) = helper.parent() {
        let _ = std::fs::remove_dir(dir);
    }
    let group = crate::owner::GROUP;
    if sys.has_group(group)? {
        sys.remove_group(group)?;
        steps.did(format!("removed the group {group} of the node's owners"));
    }
    Ok(())
}

/// The account of the commands at install: the one chosen before, else
/// `invoker`. What fails here is said and left to `setup`; the node then
/// runs no command until an account is chosen.
fn default_account(layout: &Layout, sys: &dyn System, invoker: &str, steps: &mut Steps) {
    let p = &layout.paths;
    let r = (|| {
        // Written as the folders' owner, so the files are the node's and
        // root follows no link in them.
        let _owner = as_owner_of(&p.state_dir)?;
        let mut store = SettingsStore::open(
            p.config_file(),
            p.config_key(),
            AuditLog::new(p.audit_log()),
        )?;
        if let Some(u) = &store.config().machine.user {
            // An earlier install or setup chose it; its warning holds
            // today as well.
            if let Ok(Some(a)) = sys.account(u) {
                warn_about(sys, &a, invoker, steps.out);
            }
            return Ok(format!("commands run as {u}, as chosen before"));
        }
        let a = usable_account(sys, p, invoker)?;
        store
            .update(|c| {
                c.machine.user = Some(invoker.to_string());
                Ok(())
            })
            .map_err(|e| e.to_string())?;
        warn_about(sys, &a, invoker, steps.out);
        Ok::<_, String>(format!("commands run as {invoker}, who ran install"))
    })();
    match r {
        Ok(step) => steps.did(step),
        Err(e) => steps.did(format!(
            "no account for commands: {e}; {}",
            crate::account::NO_ACCOUNT_SETUP
        )),
    }
}

/// `name` as the account of the commands, or why not: it must exist, and
/// must not be the node's own user nor reach the node's folders, where the
/// keys are. Root is allowed: the caller warns.
pub fn usable_account(sys: &dyn System, paths: &NodePaths, name: &str) -> Result<Account, String> {
    let a = sys
        .account(name)?
        .ok_or_else(|| format!("there is no account {name}"))?;
    if a.uid == 0 {
        return Ok(a);
    }
    #[cfg(unix)]
    let owner = {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(&paths.config_dir).ok().map(|m| m.uid())
    };
    #[cfg(not(unix))]
    let owner: Option<u32> = None;
    if name == USER || a.comment == USER_MARK || owner == Some(a.uid) {
        return Err(format!(
            "{name} is the node's own user, which owns its keys; choose another account"
        ));
    }
    for dir in [&paths.config_dir, &paths.state_dir] {
        if crate::account::reaches(dir, &a) {
            return Err(format!(
                "{name} could open {}, where the node keeps its keys; choose another account",
                dir.display()
            ));
        }
    }
    Ok(a)
}

/// Warns when `a` as the account of the commands lets them get root: root
/// itself, the account that ran sudo (`invoker`), an account in a group
/// that gets root without a password, or one with sudo that asks for none.
/// It never stops the command that calls it.
fn warn_about(sys: &dyn System, a: &Account, invoker: &str, out: &mut dyn Write) {
    let groups = if a.uid == 0 {
        Vec::new()
    } else {
        sys.root_groups(a)
    };
    for w in crate::account::root_warnings(a, invoker, &groups, || sys.sudo_without_password(a)) {
        let _ = writeln!(out, "{w}");
    }
}

/// The account `setup` chose for the commands, and whether it made it.
#[derive(Debug, PartialEq, Eq)]
pub struct Chosen {
    pub name: String,
    pub made: bool,
}

/// The account step of `setup` on the installed node: which account
/// the node runs commands as. Enter keeps `current`, else takes
/// `suggested` (the account that runs setup). An account that does not
/// exist is made when the owner says yes. `None`: nothing changes. The
/// account that stays is warned about as well as one chosen, with
/// `invoker` the account that ran sudo.
pub fn choose_account(
    sys: &dyn System,
    paths: &NodePaths,
    current: Option<&str>,
    suggested: Option<&str>,
    invoker: &str,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<Option<Chosen>, String> {
    let default = current.or(suggested);
    let answer = crate::cli::ask(
        input,
        out,
        &format!(
            "Account that commands from centers run as [{}]: ",
            default.unwrap_or("none")
        ),
    )?;
    let name = match (answer.as_str(), default) {
        ("", Some(d)) => d.to_string(),
        ("", None) => {
            let _ = writeln!(
                out,
                "No account: the node runs no command until one is chosen."
            );
            return Ok(None);
        }
        (a, _) => a.to_string(),
    };
    if current == Some(name.as_str()) {
        if let Ok(Some(a)) = sys.account(&name) {
            warn_about(sys, &a, invoker, out);
        }
        return Ok(None);
    }
    if !nerve_policy::config::valid_account_name(&name) {
        return Err(format!("{name:?} is not an account name"));
    }
    let mut made = false;
    if sys.account(&name)?.is_none() {
        if !crate::account::makeable_name(&name) {
            return Err(format!(
                "there is no account {name}, and setup makes accounts only with a name of a-z, 0-9, _ and -"
            ));
        }
        let yes = crate::cli::ask(
            input,
            out,
            &format!(
                "There is no account {name}. Make it, with a group and a home of its own and no login? [y/N] "
            ),
        )?;
        if !matches!(yes.as_str(), "y" | "Y" | "yes") {
            return Err(format!("there is no account {name}; nothing changed"));
        }
        sys.add_user(&name, &crate::account::made_home(&name))?;
        let _ = writeln!(out, "made the account {name}");
        made = true;
    }
    let a = usable_account(sys, paths, &name)?;
    warn_about(sys, &a, invoker, out);
    Ok(Some(Chosen { name, made }))
}

/// `setup --create-user`: `name` becomes the account of the commands
/// without a question, made as [`choose_account`] makes one when it is not
/// there. An account that is there is taken if the node can use it.
pub fn create_account(
    sys: &dyn System,
    paths: &NodePaths,
    name: &str,
    invoker: &str,
    out: &mut dyn Write,
) -> Result<Chosen, String> {
    if !nerve_policy::config::valid_account_name(name) || !crate::account::makeable_name(name) {
        return Err(format!(
            "{name:?} is not a name setup makes accounts with: a-z, 0-9, _ and -, starting with a letter or _"
        ));
    }
    if name == USER {
        return Err(format!(
            "{name} is the node's own user, which owns its keys; choose another account"
        ));
    }
    let made = sys.account(name)?.is_none();
    if made {
        sys.add_user(name, &crate::account::made_home(name))?;
        let _ = writeln!(out, "made the account {name}");
    }
    let a = usable_account(sys, paths, name)?;
    warn_about(sys, &a, invoker, out);
    Ok(Chosen {
        name: name.to_string(),
        made,
    })
}

/// `uninstall`: stops and removes the service, then the folders (deleted
/// with `purge`, else kept and given to root), the user and the program.
pub fn uninstall(
    layout: &Layout,
    sys: &dyn System,
    purge: bool,
    out: &mut dyn Write,
) -> Result<(), String> {
    supported(sys, "uninstall")?;
    let mut steps = Steps {
        done: Vec::new(),
        out,
    };
    let r = uninstall_steps(layout, sys, purge, &mut steps);
    // With --purge the log went with the state folder.
    audit(&layout.paths, "uninstall", &steps.done, &r, steps.out);
    if r.is_ok() && steps.done.is_empty() {
        let _ = writeln!(
            steps.out,
            "nothing to uninstall: no service, user {USER} or program of the node is here"
        );
    }
    r
}

fn uninstall_steps(
    layout: &Layout,
    sys: &dyn System,
    purge: bool,
    steps: &mut Steps,
) -> Result<(), String> {
    if layout.unit.exists() {
        sys.systemctl(&["disable", "--now", UNIT_NAME])?;
        steps.did(format!("stopped the service {UNIT_NAME}"));
        std::fs::remove_file(&layout.unit)
            .map_err(|e| format!("{}: {e}", layout.unit.display()))?;
        sys.systemctl(&["daemon-reload"])?;
        // Only clears a failed state systemd still shows.
        let _ = sys.systemctl(&["reset-failed", UNIT_NAME]);
        steps.did(format!(
            "removed the service unit {}",
            layout.unit.display()
        ));
    }
    let folders = [
        &layout.paths.config_dir,
        &layout.home,
        &layout.paths.state_dir,
    ];
    if purge {
        for dir in folders {
            if dir.exists() {
                std::fs::remove_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
                steps.did(format!("deleted {}", dir.display()));
            }
        }
    } else if folders.iter().any(|d| d.exists()) {
        // Their user goes; a uid nobody has must not own the keys, since
        // the next user to get it would.
        for dir in folders.iter().filter(|d| d.exists()) {
            sys.give(dir, 0, 0)?;
        }
        steps.did(format!(
            "kept {} and {} (they belong to root now; `uninstall --purge` deletes them)",
            layout.paths.config_dir.display(),
            layout.paths.state_dir.display()
        ));
    }
    remove_owners(layout, sys, steps)?;
    match sys.account(USER)? {
        Some(a) if a.comment == USER_MARK => {
            if sys.end_session(USER)? {
                steps.did(format!(
                    "ended the session of {USER} that its keyring needed"
                ));
            }
            sys.remove_account(USER)?;
            steps.did(format!("removed the user {USER}"));
        }
        Some(_) => {
            let _ = writeln!(
                steps.out,
                "left the user {USER} as it is: nerve-node install did not make it"
            );
        }
        None => {}
    }
    uninstall_parts(layout, steps)?;
    if layout.bin.exists() {
        std::fs::remove_file(&layout.bin).map_err(|e| format!("{}: {e}", layout.bin.display()))?;
        steps.did(format!("removed the program {}", layout.bin.display()));
    }
    Ok(())
}

/// A version as `nerve-node --version` prints it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(u64, u64, u64);

impl Version {
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn parse(said: &str) -> Option<Version> {
        Version::parse_of("nerve-node", said)
    }

    /// The version `layout`'s program says it has: the desktop app's line
    /// starts with its own name, so neither program takes the other's place
    /// in an update.
    pub(crate) fn of_program(layout: &Layout, said: &str) -> Option<Version> {
        Version::parse_of(layout.edition.program, said)
    }

    /// A version as `<program> --version` prints it, for another program of
    /// the release (the center's service).
    pub fn parse_of(program: &str, said: &str) -> Option<Version> {
        let v = said.trim().strip_prefix(program)?.strip_prefix(' ')?;
        let mut parts = v.split('.').map(|p| p.parse::<u64>().ok());
        let v = Version(parts.next()??, parts.next()??, parts.next()??);
        parts.next().is_none().then_some(v)
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// `update`: the new program (the latest release, checked against its
/// `SHA256SUMS`, or a file the owner gives) replaces the installed one, and
/// the service restarts. The config, the keys and the audit log are not
/// touched. A program that does not run here, or is older than the
/// installed one, is refused; one that does not start is replaced by the
/// old one again.
pub async fn update(
    layout: &Layout,
    sys: &dyn System,
    from: Option<&Path>,
    invoker: &str,
    out: &mut dyn Write,
) -> Result<(), String> {
    supported(sys, "update")?;
    if !layout.installed() || !layout.bin.is_file() {
        return Err(
            "the node is not installed as a service here; `sudo nerve-node install` installs it"
                .into(),
        );
    }
    let mut steps = Steps {
        done: Vec::new(),
        out,
    };
    let r = update_steps(layout, sys, from, invoker, &mut steps).await;
    audit(&layout.paths, "update", &steps.done, &r, steps.out);
    r
}

async fn update_steps(
    layout: &Layout,
    sys: &dyn System,
    from: Option<&Path>,
    invoker: &str,
    steps: &mut Steps<'_>,
) -> Result<(), String> {
    let program = layout.edition.program;
    let account = sys
        .account(USER)?
        .filter(|a| a.comment == USER_MARK)
        .ok_or_else(|| {
            format!("the user {USER} is missing; `sudo nerve-node install` makes it again")
        })?;
    let new = match from {
        Some(f) => {
            let b = std::fs::read(f).map_err(|e| format!("{}: {e}", f.display()))?;
            steps.did(format!("read the new program from {}", f.display()));
            b
        }
        None => {
            let asset = asset_name(layout.edition.program)?;
            let b = fetch_release(&layout.release, &asset).await?;
            steps.did(format!(
                "downloaded {asset} from {} and checked it against its SHA256SUMS",
                layout.release
            ));
            b
        }
    };
    let old = std::fs::read(&layout.bin).map_err(|e| format!("{}: {e}", layout.bin.display()))?;
    if new == old {
        steps.did("the installed program is that one already; nothing to update");
        return Ok(());
    }
    // Staged beside the program, so the rename that puts it in place does
    // not cross file systems.
    let staged = layout
        .bin
        .with_file_name(format!(".{}.new", layout.edition.program));
    write_file(&staged, &new, 0o755)?;
    let checked = (|| {
        let said = sys.version_of(&staged, &account)?;
        let new_v = Version::of_program(layout, &said)
            .ok_or_else(|| format!("the new program is not {program}: it says {said:?}"))?;
        let old_v = sys
            .version_of(&layout.bin, &account)
            .ok()
            .and_then(|s| Version::of_program(layout, &s));
        if let Some(o) = old_v
            && new_v < o
        {
            return Err(format!(
                "the new program is {program} {new_v}, older than the installed {o}; nothing changed"
            ));
        }
        Ok((old_v, new_v))
    })();
    let (old_v, new_v) = match checked {
        Ok(v) => v,
        Err(e) => {
            let _ = std::fs::remove_file(&staged);
            return Err(e);
        }
    };
    std::fs::rename(&staged, &layout.bin).map_err(|e| format!("{}: {e}", layout.bin.display()))?;
    let old_v = old_v.map_or_else(|| "?".to_string(), |v| v.to_string());
    steps.did(format!("replaced {program} {old_v} with {new_v}"));
    // The unit of this version (the owners' runtime folder) and the owners'
    // parts an earlier install did not make; what is there stays.
    let unit = layout.unit_text();
    if std::fs::read_to_string(&layout.unit).ok().as_deref() != Some(unit.as_str()) {
        write_file(&layout.unit, unit.as_bytes(), 0o644)?;
        sys.systemctl(&["daemon-reload"])?;
        steps.did(format!(
            "wrote the service unit {} of this version",
            layout.unit.display()
        ));
    }
    put_owners(layout, sys, invoker, false, steps)?;
    let started = sys
        .systemctl(&["restart", UNIT_NAME])
        .and_then(|()| sys.wait_running(&layout.paths));
    if let Err(e) = started {
        write_file(&layout.bin, &old, 0o755)?;
        let back = sys
            .systemctl(&["restart", UNIT_NAME])
            .and_then(|()| sys.wait_running(&layout.paths));
        steps.did(format!("put {program} {old_v} back"));
        return Err(match back {
            Ok(()) => format!("the new program did not start ({e}); the old one runs again"),
            Err(e2) => format!(
                "the new program did not start ({e}), and the old one does not either ({e2})"
            ),
        });
    }
    steps.did(format!("restarted the service {UNIT_NAME}"));
    install_parts(layout, steps)
}

/// The release file of `program` for this machine. The desktop app comes
/// for x86_64 only.
pub(crate) fn asset_name(program: &str) -> Result<String, String> {
    let node = program == crate::edition::NODE.program;
    match std::env::consts::ARCH {
        "x86_64" if cfg!(windows) => Ok(format!("{program}-x86_64-windows.exe")),
        "x86_64" if !cfg!(windows) => Ok(format!("{program}-x86_64-linux")),
        "aarch64" if !cfg!(windows) && node => Ok(format!("{program}-aarch64-linux")),
        other => Err(format!(
            "the releases have no {program} for {other}; build one (docs/dev/building.md) and give it with --from"
        )),
    }
}

/// Puts the parts of `layout`'s program beside it ([`crate::edition::Parts`]),
/// once the program is in place.
pub(crate) fn put_parts(layout: &Layout, steps: &mut Steps) -> Result<(), String> {
    if let Some(parts) = layout.edition.parts {
        for step in parts.install(&layout.bin)? {
            steps.did(step);
        }
    }
    Ok(())
}

/// [`put_parts`], and the node alone that was installed before the program
/// becomes a link to it ([`link_node`]); Linux. On Windows that program goes
/// instead (crate::winsvc).
pub(crate) fn install_parts(layout: &Layout, steps: &mut Steps) -> Result<(), String> {
    put_parts(layout, steps)?;
    link_node(layout, steps)
}

/// Removes them again, and that link, before the program goes.
pub(crate) fn uninstall_parts(layout: &Layout, steps: &mut Steps) -> Result<(), String> {
    unlink_node(layout, steps)?;
    if let Some(parts) = layout.edition.parts {
        for step in parts.uninstall(&layout.bin)? {
            steps.did(step);
        }
    }
    Ok(())
}

/// Where `install` of the node alone put its program, beside `layout`'s
/// when that is another edition's: `nerve-node` (`nerve-node.exe`).
pub fn node_beside(layout: &Layout) -> Option<PathBuf> {
    let node = crate::edition::NODE.program;
    if layout.edition.program == node {
        return None;
    }
    Some(beside(layout, node))
}

/// The program `program` in `layout`'s folder, with its extension.
fn beside(layout: &Layout, program: &str) -> PathBuf {
    let mut p = layout.bin.with_file_name(program);
    if let Some(ext) = layout.bin.extension() {
        p.set_extension(ext);
    }
    p
}

/// The desktop app's program beside `layout`'s, when the app is installed
/// there and `layout` is the node alone's: the app took the node over, so
/// the service, the parts and the program are the app's, and only its own
/// uninstall removes them all ([`hand_over_uninstall`]).
pub fn app_beside(layout: &Layout) -> Option<PathBuf> {
    if layout.edition.program != crate::edition::NODE.program {
        return None;
    }
    Some(beside(layout, crate::edition::DESKTOP_PROGRAM)).filter(|p| p.is_file())
}

/// `uninstall` of the node alone where the desktop app took the node over:
/// the app's program at `app` runs its own `uninstall`, which removes the
/// service, the app's parts and both programs, and what it says is passed
/// on. Its log and errors go to stderr as they come.
pub fn hand_over_uninstall(app: &Path, purge: bool, out: &mut dyn Write) -> Result<(), String> {
    use std::io::BufReader;
    use std::process::{Command, Stdio};
    let _ = writeln!(
        out,
        "the desktop app is installed ({}): its uninstall removes the node with the app",
        app.display()
    );
    let mut cmd = Command::new(app);
    cmd.arg("uninstall");
    if purge {
        cmd.arg("--purge");
    }
    // Pipes, not this console: on Windows the app is a GUI program, which
    // keeps what it is given (nerve-node-desktop's console.rs).
    let mut child = cmd
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{}: {e}", app.display()))?;
    let stderr = child.stderr.take().expect("piped");
    let said = std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            eprintln!("{line}");
        }
    });
    for line in BufReader::new(child.stdout.take().expect("piped"))
        .lines()
        .map_while(Result::ok)
    {
        let _ = writeln!(out, "{line}");
    }
    let status = child
        .wait()
        .map_err(|e| format!("{}: {e}", app.display()))?;
    let _ = said.join();
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "`{} uninstall` did not finish ({status}); what it said is above",
            app.display()
        ))
    }
}

/// A node installed with `nerve-node` and then taken over by the desktop
/// app keeps its terminal command on Linux: the old program becomes a link
/// to the app's, which runs the CLI as `nerve-node` does, so one program
/// stays and it is never an older one. The edition comes from the program
/// the link leads to (crate::edition), so `nerve-node update` through it
/// updates the app. Nothing is made where no node alone was installed.
fn link_node(layout: &Layout, steps: &mut Steps) -> Result<(), String> {
    let Some(node) = node_beside(layout) else {
        return Ok(());
    };
    // A link is there already (this one, or another's to leave alone).
    if !std::fs::symlink_metadata(&node).is_ok_and(|m| m.is_file()) {
        return Ok(());
    }
    let at = |e: std::io::Error| format!("{}: {e}", node.display());
    // Made beside it first and moved over it, so the command is never
    // missing.
    let name = node
        .file_name()
        .map_or_else(Default::default, |n| n.to_string_lossy());
    let tmp = node.with_file_name(format!(".{name}.link"));
    let _ = std::fs::remove_file(&tmp);
    symlink(&layout.bin, &tmp).map_err(at)?;
    let r = std::fs::rename(&tmp, &node).map_err(at);
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r?;
    steps.did(format!(
        "{} is a link to {} now, so the command {} runs it",
        node.display(),
        layout.bin.display(),
        crate::edition::NODE.program
    ));
    Ok(())
}

#[cfg(unix)]
fn symlink(target: &Path, at: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, at)
}

// Windows removes the node alone's program instead (crate::winsvc).
#[cfg(not(unix))]
fn symlink(_: &Path, _: &Path) -> std::io::Result<()> {
    Err(std::io::Error::other("the link is made on Linux only"))
}

/// Removes the link [`link_node`] made, and no other.
fn unlink_node(layout: &Layout, steps: &mut Steps) -> Result<(), String> {
    let Some(node) = node_beside(layout) else {
        return Ok(());
    };
    let ours = std::fs::symlink_metadata(&node).is_ok_and(|m| m.file_type().is_symlink())
        && std::fs::read_link(&node).is_ok_and(|t| t == layout.bin);
    if !ours {
        return Ok(());
    }
    std::fs::remove_file(&node).map_err(|e| format!("{}: {e}", node.display()))?;
    steps.did(format!("removed the link {}", node.display()));
    Ok(())
}

/// What `service` does to the installed service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAction {
    Start,
    Stop,
    Restart,
}

impl ServiceAction {
    pub fn word(self) -> &'static str {
        match self {
            ServiceAction::Start => "start",
            ServiceAction::Stop => "stop",
            ServiceAction::Restart => "restart",
        }
    }
}

/// The installed service, as `service status` says it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceState {
    /// running, stopped, starting, stopping or failed.
    pub state: String,
    /// Whether it starts with the machine, when the system says.
    pub enabled: Option<bool>,
}

/// systemd's words for a unit, from `systemctl show`, as [`ServiceState`].
fn unit_state_of(shown: &str) -> ServiceState {
    let field = |k: &str| {
        shown
            .lines()
            .find_map(|l| l.strip_prefix(k)?.strip_prefix('='))
            .unwrap_or_default()
            .trim()
            .to_string()
    };
    let state = match field("ActiveState").as_str() {
        "active" | "reloading" | "refreshing" => "running",
        "activating" => "starting",
        "deactivating" => "stopping",
        "failed" => "failed",
        _ => "stopped",
    };
    let enabled = match field("UnitFileState").as_str() {
        "" => None,
        s => Some(s == "enabled" || s == "enabled-runtime"),
    };
    ServiceState {
        state: state.into(),
        enabled,
    }
}

/// `service status`: whether the node is installed as a service here, its
/// state (`None`: not installed), and the program it runs with its version.
/// Anyone may ask; the program says its version as the one who asks.
pub fn service_status(layout: &Layout, state: Option<&ServiceState>) -> serde_json::Value {
    let version = layout
        .bin
        .is_file()
        .then(|| {
            std::process::Command::new(&layout.bin)
                .arg("--version")
                .stdin(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .output()
                .ok()
        })
        .flatten()
        .filter(|o| o.status.success())
        .and_then(|o| Version::of_program(layout, &String::from_utf8_lossy(&o.stdout)))
        .map(|v| v.to_string());
    serde_json::json!({
        "installed": state.is_some(),
        "state": state.map(|s| s.state.as_str()),
        "enabled": state.and_then(|s| s.enabled),
        "program": layout.bin.display().to_string(),
        "present": layout.bin.is_file(),
        "version": version,
    })
}

/// The state of the unit, `None` when the node is not installed here.
pub fn unit_status(layout: &Layout, sys: &dyn System) -> Result<Option<ServiceState>, String> {
    if !layout.installed_at_unit() {
        return Ok(None);
    }
    sys.unit_state().map(Some)
}

/// `service start`, `stop` and `restart`: the installed service, as
/// systemctl does it, waiting until a node that starts answers.
pub fn control(
    layout: &Layout,
    sys: &dyn System,
    action: ServiceAction,
    out: &mut dyn Write,
) -> Result<(), String> {
    // Without root, the helper or systemctl asks polkit, whose rule or
    // `.pkla` file lets the owners do it (crate::owner); it refuses everyone
    // else.
    supported_without_root(sys, &format!("service {}", action.word()))?;
    if !layout.installed_at_unit() {
        return Err(
            "the node is not installed as a service here; `sudo nerve-node install` installs it"
                .into(),
        );
    }
    let helper = layout.service_helper();
    if !sys.is_root() && helper.is_file() && sys.has_pkexec() {
        // Through the helper's own polkit action, which the owners have
        // without a password on every polkit, 0.105 too.
        sys.pkexec(&helper, &[action.word()])?;
    } else {
        sys.systemctl(&[action.word(), UNIT_NAME])?;
    }
    let said = match action {
        ServiceAction::Stop => {
            let again = if sys.unit_state()?.enabled == Some(true) {
                "; it starts again with the machine"
            } else {
                ""
            };
            format!("stopped the service {UNIT_NAME}: the node ended its links{again}")
        }
        ServiceAction::Start | ServiceAction::Restart => {
            sys.wait_running(&layout.paths)?;
            let did = if action == ServiceAction::Start {
                "started"
            } else {
                "restarted"
            };
            format!("{did} the service {UNIT_NAME}, and the node answers")
        }
    };
    let _ = writeln!(out, "{said}");
    Ok(())
}

/// Downloads `asset` from the release at `base` and checks it against the
/// release's `SHA256SUMS`.
pub async fn fetch_release(base: &str, asset: &str) -> Result<Vec<u8>, String> {
    nerve_transport::init_crypto();
    let sums = download(&format!("{base}/SHA256SUMS"), SUMS_MAX).await?;
    let want = String::from_utf8_lossy(&sums)
        .lines()
        .find_map(|l| {
            let (hash, name) = l.split_once(char::is_whitespace)?;
            let name = name.trim_start();
            let name = name.strip_prefix('*').unwrap_or(name);
            (name == asset).then(|| hash.to_ascii_lowercase())
        })
        .ok_or_else(|| format!("the release's SHA256SUMS lists no {asset}"))?;
    let program = download(&format!("{base}/{asset}"), PROGRAM_MAX).await?;
    let got: String = ring::digest::digest(&ring::digest::SHA256, &program)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if got != want {
        return Err(format!(
            "the downloaded {asset} does not match its line in SHA256SUMS; nothing changed"
        ));
    }
    Ok(program)
}

/// `GET url`, following redirects (never from https to http), through the
/// proxy `HTTPS_PROXY` names: the download the center's one-click model
/// install shares (`nerve_transport::download`). Errors name the host, not
/// the whole address, which may hold a signed query.
async fn download(url: &str, max: usize) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    let opts = nerve_transport::download::Options {
        max: max as u64,
        idle: nerve_transport::http::HEAD_TIMEOUT,
        // Five redirects, as the node's own loop followed before.
        hops: 5,
        cancel: None,
    };
    nerve_transport::download::fetch(url, &mut body, &opts, &mut |_, _| {}).await?;
    Ok(body)
}

/// The server and the request target (path and query) of an http(s) URL.
#[cfg(all(test, target_os = "linux"))]
fn split_url(url: &str) -> Result<(nerve_proto::link::CenterUrl, String), String> {
    nerve_transport::download::split_url(url)
}

/// Writes `data` to `path` through a temporary file beside it and a rename,
/// with `mode`.
pub fn write_file(path: &Path, data: &[u8], mode: u32) -> Result<(), String> {
    let at = |e: std::io::Error| format!("{}: {e}", path.display());
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir).map_err(at)?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = dir.join(format!(
        ".{name}.{}.tmp",
        nerve_transport::keys::random_token(8)
    ));
    let r = (|| {
        std::fs::write(&tmp, data)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
        }
        #[cfg(not(unix))]
        let _ = mode;
        std::fs::rename(&tmp, path)
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r.map_err(at)
}

pub fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| format!("{}: {e}", path.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

/// Root's file access as the owner of `dir`, on this thread, while the
/// result lives ([`crate::account::FsAs`]): what root writes into a folder
/// of the node's user then cannot reach through a link that user made more
/// than that user may. A link in place of `dir` is refused. Nothing changes
/// for another caller than root, or a folder of root's.
pub fn as_owner_of(dir: &Path) -> Result<Option<impl Drop>, String> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        if m.file_type().is_symlink() {
            return Err(format!(
                "{} is a link; the node's folders are folders, and root does not follow it",
                dir.display()
            ));
        }
        if nerve_transport::net::euid() != 0 || m.uid() == 0 {
            return Ok(None);
        }
        let owner = Account {
            name: format!("uid {}", m.uid()),
            uid: m.uid(),
            gid: m.gid(),
            comment: String::new(),
            home: dir.to_path_buf(),
            groups: vec![m.gid()],
        };
        crate::account::FsAs::new(&owner)
            .map(Some)
            .map_err(|e| format!("cannot write as the owner of {}: {e}", dir.display()))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = dir;
        Ok(None::<NoDrop>)
    }
}

#[cfg(not(target_os = "linux"))]
struct NoDrop;
#[cfg(not(target_os = "linux"))]
impl Drop for NoDrop {
    fn drop(&mut self) {}
}

#[cfg(not(target_os = "linux"))]
fn chown(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        std::os::unix::fs::lchown(path, Some(uid), Some(gid))
            .map_err(|e| format!("{}: {e}", path.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, uid, gid);
        Ok(())
    }
}

/// Gives `path` and everything below it to `uid`:`gid`. Links are changed
/// themselves and never followed. On Linux each folder is opened without
/// following a link and read through its descriptor, so a folder that the
/// node's user swaps for a link meanwhile is not walked.
fn chown_tree(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        chown_below(path, path, uid, gid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        chown_tree_by_path(path, uid, gid)
    }
}

/// [`chown_tree`] on Linux: `at` is the path to open (below a folder's
/// descriptor), `shown` the one errors name.
#[cfg(target_os = "linux")]
fn chown_below(at: &Path, shown: &Path, uid: u32, gid: u32) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let err = |e: std::io::Error| format!("{}: {e}", shown.display());
    let dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(at);
    let dir = match dir {
        Ok(d) => d,
        // A file or a link: changed itself, through a descriptor of the
        // entry (not followed), so the file checked is the one changed.
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTDIR | libc::ELOOP)) => {
            return chown_entry(at, uid, gid).map_err(|e| format!("{}: {e}", shown.display()));
        }
        Err(e) => return Err(err(e)),
    };
    std::os::unix::fs::fchown(&dir, Some(uid), Some(gid)).map_err(err)?;
    let fd = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()));
    for e in std::fs::read_dir(&fd).map_err(err)? {
        let name = e.map_err(err)?.file_name();
        chown_below(&fd.join(&name), &shown.join(&name), uid, gid)?;
    }
    Ok(())
}

/// Gives the file or link at `at` (not followed) to `uid`:`gid`. A file
/// with more than one name is refused: its other name can be anywhere on
/// the same file system, as a hard link the node's user made to a file of
/// root's.
#[cfg(target_os = "linux")]
fn chown_entry(at: &Path, uid: u32, gid: u32) -> Result<(), String> {
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    let path = std::ffi::CString::new(at.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    // Through libc, not `OpenOptions::custom_flags`: on musl, the C library
    // of the released programs, the standard library takes O_PATH out of
    // the flags (musl's O_ACCMODE holds it), and the entry would be opened
    // for reading, which a socket refuses, a link fails and a FIFO waits on.
    // SAFETY: a valid C string; the new descriptor is owned below.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: open returned a fresh descriptor nothing else owns.
    let f = std::fs::File::from(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) });
    let m = f.metadata().map_err(|e| e.to_string())?;
    if m.nlink() > 1 {
        return Err(
            "it has another name (a hard link), which may be outside the node's folders; remove it and run this again".into(),
        );
    }
    // SAFETY: an empty NUL-terminated path with AT_EMPTY_PATH on an open
    // descriptor: the call changes that inode.
    let r = unsafe {
        libc::fchownat(
            std::os::fd::AsRawFd::as_raw_fd(&f),
            c"".as_ptr(),
            uid,
            gid,
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if r != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn chown_tree_by_path(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    chown(path, uid, gid)?;
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.is_dir() {
        let entries = std::fs::read_dir(path).map_err(|e| format!("{}: {e}", path.display()))?;
        for e in entries {
            let e = e.map_err(|e| format!("{}: {e}", path.display()))?;
            chown_tree_by_path(&e.path(), uid, gid)?;
        }
    }
    Ok(())
}

/// A command root runs on a node whose folders belong to another user (the
/// installed node's `nerve`) runs as that user, so that what it writes stays
/// readable to the node. Called before anything else runs in the process:
/// it changes the user of the calling thread only where the C library does
/// not change every thread's. With `keep_root` (setup) root stays the saved
/// id, so the process can get it back for one thing, making an account
/// ([`System::add_user`]); a process of the node's user cannot trace or
/// read it, since its ids are not all that user's.
pub fn become_owner(paths: &NodePaths, keep_root: bool) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Some(m) = owner_to_become(paths) else {
            return Ok(());
        };
        #[cfg(target_os = "linux")]
        let (setgid, setuid) = {
            let saved = |id: u32| if keep_root { 0 } else { id };
            (
                // SAFETY: plain calls without pointers.
                move |g: u32| unsafe { libc::setresgid(g, g, saved(g)) },
                move |u: u32| unsafe { libc::setresuid(u, u, saved(u)) },
            )
        };
        #[cfg(not(target_os = "linux"))]
        let (setgid, setuid) = {
            let _ = keep_root;
            // SAFETY: plain calls without pointers.
            (
                |g: u32| unsafe { libc::setgid(g) },
                |u: u32| unsafe { libc::setuid(u) },
            )
        };
        // SAFETY: the empty group list; groups first, the user last, while
        // root may still change both.
        let failed = unsafe { libc::setgroups(0, std::ptr::null()) != 0 }
            || setgid(m.gid()) != 0
            || setuid(m.uid()) != 0;
        if failed {
            return Err(format!(
                "cannot run as the owner (uid {}) of {}: {}",
                m.uid(),
                paths.config_dir.display(),
                std::io::Error::last_os_error()
            ));
        }
        // The session bus these name is the caller's, not the owner's: the
        // system keyring is found in the owner's session (/run/user/<uid>).
        // SAFETY: `main` calls this while the process has one thread.
        unsafe {
            std::env::remove_var("DBUS_SESSION_BUS_ADDRESS");
            std::env::remove_var("XDG_RUNTIME_DIR");
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (paths, keep_root);
        Ok(())
    }
}

/// The folders whose owner root's command becomes ([`become_owner`]): the
/// first of them that is there, when this process is root and they are not
/// root's.
#[cfg(unix)]
fn owner_to_become(paths: &NodePaths) -> Option<std::fs::Metadata> {
    use std::os::unix::fs::MetadataExt;
    if nerve_transport::net::euid() != 0 {
        return None;
    }
    [&paths.config_dir, &paths.state_dir]
        .iter()
        .find_map(|d| std::fs::metadata(d).ok())
        .filter(|m| m.uid() != 0)
}

/// Whether [`become_owner`] makes this process another user.
pub fn becomes_owner(paths: &NodePaths) -> bool {
    #[cfg(unix)]
    return owner_to_become(paths).is_some();
    #[cfg(not(unix))]
    {
        let _ = paths;
        false
    }
}

/// A command on the installed node from a user who is neither root nor the
/// node's own stops here and says how to run it, instead of failing on a
/// folder it may not open.
pub fn check_access(paths: &NodePaths) -> Result<(), String> {
    let layout = Layout::system();
    if *paths != layout.paths || !layout.installed() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let me = nerve_transport::net::euid();
        let owner = std::fs::metadata(&paths.config_dir).map(|m| m.uid());
        if me != 0 && owner.is_ok_and(|o| o != me) {
            return Err(format!(
                "the node is installed as a service, and its files belong to the user {USER}: run `sudo nerve-node …`"
            ));
        }
    }
    // Only `nerve` and the administrators may open the folders.
    #[cfg(windows)]
    if !crate::win_host::is_admin() && crate::win_user::current_user().as_deref() != Ok(USER) {
        return Err(format!(
            "the node is installed as a service, and its files are open to the user {USER} and the administrators only: run `nerve-node …` in a terminal opened with \"Run as administrator\""
        ));
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A machine in a temporary folder: the user is the test's own, and
    /// systemctl and the node's start are recorded.
    pub(crate) struct Fake {
        user: RefCell<Option<Account>>,
        /// The other accounts of the machine.
        others: RefCell<Vec<Account>>,
        calls: RefCell<Vec<String>>,
        /// The folders given to another user, and to whom.
        given: RefCell<Vec<(PathBuf, u32)>>,
        /// Whether a node started by the service answers.
        starts: std::cell::Cell<bool>,
        /// The accounts in a group that gets root, and that group.
        root_groups: RefCell<Vec<(String, String)>>,
        /// The accounts whose sudo asks for no password.
        sudo_without_password: RefCell<Vec<String>>,
        /// Whether the node's user keeps a session (a keyring's linger).
        lingers: std::cell::Cell<bool>,
        /// The groups and their members.
        pub(crate) groups: RefCell<Vec<(String, Vec<String>)>>,
        /// What polkit takes here.
        pub(crate) polkit: std::cell::Cell<Polkit>,
        /// Whether the command runs as root, and whether pkexec is there.
        pub(crate) root: std::cell::Cell<bool>,
        pub(crate) pkexec_here: std::cell::Cell<bool>,
    }

    impl Fake {
        pub(crate) fn new() -> Fake {
            Fake {
                user: RefCell::new(None),
                others: RefCell::new(vec![other("alice", 4242), other("root", 0)]),
                calls: RefCell::new(Vec::new()),
                given: RefCell::new(Vec::new()),
                starts: std::cell::Cell::new(true),
                root_groups: RefCell::new(Vec::new()),
                sudo_without_password: RefCell::new(Vec::new()),
                lingers: std::cell::Cell::new(false),
                groups: RefCell::new(Vec::new()),
                polkit: std::cell::Cell::new(Polkit::Rules),
                root: std::cell::Cell::new(true),
                pkexec_here: std::cell::Cell::new(true),
            }
        }

        /// The members of `group`, `None` when it is not there.
        pub(crate) fn members(&self, group: &str) -> Option<Vec<String>> {
            self.groups
                .borrow()
                .iter()
                .find(|(g, _)| g == group)
                .map(|(_, m)| m.clone())
        }

        pub(crate) fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    fn me() -> Account {
        // SAFETY: plain getters.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        Account {
            name: USER.into(),
            uid,
            gid,
            comment: USER_MARK.into(),
            home: "/var/lib/nerve".into(),
            groups: vec![gid],
        }
    }

    /// An account that is not the test's own.
    fn other(name: &str, uid: u32) -> Account {
        Account {
            name: name.into(),
            uid,
            gid: uid,
            comment: String::new(),
            home: format!("/home/{name}").into(),
            groups: vec![uid],
        }
    }

    impl System for Fake {
        fn is_root(&self) -> bool {
            self.root.get()
        }
        fn has_pkexec(&self) -> bool {
            self.pkexec_here.get()
        }
        fn pkexec(&self, program: &Path, args: &[&str]) -> Result<(), String> {
            self.calls.borrow_mut().push(format!(
                "pkexec {} {}",
                program.display(),
                args.join(" ")
            ));
            Ok(())
        }
        fn has_systemd(&self) -> bool {
            true
        }
        fn account(&self, name: &str) -> Result<Option<Account>, String> {
            if name == USER {
                return Ok(self.user.borrow().clone());
            }
            Ok(self
                .others
                .borrow()
                .iter()
                .find(|a| a.name == name)
                .cloned())
        }
        fn root_groups(&self, account: &Account) -> Vec<String> {
            self.root_groups
                .borrow()
                .iter()
                .filter(|(a, _)| *a == account.name)
                .map(|(_, g)| g.clone())
                .collect()
        }
        fn sudo_without_password(&self, account: &Account) -> bool {
            self.sudo_without_password.borrow().contains(&account.name)
        }
        fn add_user(&self, name: &str, home: &Path) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(format!("useradd {name} {}", home.display()));
            let uid = 5000 + self.others.borrow().len() as u32;
            self.others.borrow_mut().push(Account {
                comment: crate::account::MADE_MARK.into(),
                home: home.into(),
                ..other(name, uid)
            });
            Ok(())
        }
        fn add_account(&self, name: &str, home: &Path) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(format!("useradd {name} {}", home.display()));
            *self.user.borrow_mut() = Some(me());
            Ok(())
        }
        fn remove_account(&self, name: &str) -> Result<(), String> {
            self.calls.borrow_mut().push(format!("userdel {name}"));
            *self.user.borrow_mut() = None;
            Ok(())
        }
        fn systemctl(&self, args: &[&str]) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(format!("systemctl {}", args.join(" ")));
            Ok(())
        }
        /// Running after the last start or restart, until a stop.
        fn unit_state(&self) -> Result<ServiceState, String> {
            let calls = self.calls.borrow();
            let last = calls.iter().rev().find_map(|c| {
                // The helper's word is the last of a pkexec call.
                let c = c
                    .strip_prefix("systemctl ")
                    .or_else(|| c.strip_prefix("pkexec ").and_then(|r| r.rsplit(' ').next()))?;
                if c.starts_with("start") || c.starts_with("restart") {
                    Some("running")
                } else if c.starts_with("stop") || c.starts_with("disable --now") {
                    Some("stopped")
                } else {
                    None
                }
            });
            Ok(ServiceState {
                state: last.unwrap_or("stopped").into(),
                enabled: Some(calls.iter().any(|c| c.starts_with("systemctl enable"))),
            })
        }
        /// The test may give files to itself only; giving them to anyone
        /// else is recorded.
        fn give(&self, path: &Path, uid: u32, gid: u32) -> Result<(), String> {
            if uid == me().uid {
                chown_tree(path, uid, gid)
            } else {
                self.given.borrow_mut().push((path.to_path_buf(), uid));
                Ok(())
            }
        }
        fn wait_running(&self, _paths: &NodePaths) -> Result<(), String> {
            if self.starts.get() {
                Ok(())
            } else {
                Err("the node does not answer".into())
            }
        }
        /// A program here is a text file whose first line is what it says.
        fn version_of(&self, program: &Path, account: &Account) -> Result<String, String> {
            assert_eq!(account.comment, USER_MARK);
            let text = std::fs::read_to_string(program).map_err(|e| e.to_string())?;
            Ok(text.lines().next().unwrap_or_default().to_string())
        }
        fn end_session(&self, name: &str) -> Result<bool, String> {
            if !self.lingers.replace(false) {
                return Ok(false);
            }
            self.calls
                .borrow_mut()
                .push(format!("loginctl disable-linger {name}"));
            Ok(true)
        }

        fn has_group(&self, name: &str) -> Result<bool, String> {
            Ok(self.members(name).is_some())
        }

        fn add_group(&self, name: &str) -> Result<(), String> {
            self.calls.borrow_mut().push(format!("groupadd {name}"));
            self.groups.borrow_mut().push((name.into(), Vec::new()));
            Ok(())
        }

        fn add_to_group(&self, user: &str, group: &str) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(format!("usermod {user} {group}"));
            for (g, m) in self.groups.borrow_mut().iter_mut() {
                if g == group && !m.iter().any(|u| u == user) {
                    m.push(user.into());
                }
            }
            Ok(())
        }

        fn remove_group(&self, name: &str) -> Result<(), String> {
            self.calls.borrow_mut().push(format!("groupdel {name}"));
            self.groups.borrow_mut().retain(|(g, _)| g != name);
            Ok(())
        }

        fn polkit(&self, _rule: &Path) -> Polkit {
            self.polkit.get()
        }
    }

    fn layout(root: &Path) -> Layout {
        Layout {
            unit: root.join("etc/systemd/system").join(UNIT_NAME),
            bin: root.join("usr/local/bin/nerve-node"),
            home: root.join("var/lib/nerve"),
            paths: NodePaths::new(root.join("etc/nerve"), root.join("var/lib/nerve/state")),
            release: "http://127.0.0.1:1/none".into(),
            edition: &crate::edition::NODE,
        }
    }

    /// Installs a "program" saying `version` from a file in `root`.
    fn installed(root: &Path, sys: &Fake, version: &str) -> Layout {
        let l = layout(root);
        let exe = root.join("download/nerve-node-x86_64-linux");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, format!("nerve-node {version}\n")).unwrap();
        let mut out = Vec::new();
        install(&l, sys, &exe, "alice", &mut out).unwrap();
        l
    }

    fn audit_events(l: &Layout) -> Vec<serde_json::Value> {
        AuditLog::new(l.paths.audit_log())
            .read()
            .unwrap()
            .into_iter()
            .filter(|v| v["kind"] == "node")
            .collect()
    }

    fn mode(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn install_puts_the_service_under_its_own_user() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = layout(d.path());
        // The program as the release names it lands as nerve-node.
        let exe = d.path().join("download/nerve-node-x86_64-linux");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, "nerve-node 1.0.0\n").unwrap();
        let mut out = Vec::new();
        install(&l, &sys, &exe, "alice", &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("made the user nerve"), "{out}");
        assert!(
            out.contains("commands run as alice, who ran install"),
            "{out}"
        );
        // The account that ran sudo is no boundary: the warning is there,
        // and install went on.
        assert!(out.contains("alice is the account that ran sudo"), "{out}");
        assert!(out.contains("setup --create-user nerve-work"), "{out}");
        let cfg = SettingsStore::peek(&l.paths.config_file(), &l.paths.config_key()).unwrap();
        assert_eq!(cfg.machine.user.as_deref(), Some("alice"));
        assert!(out.contains("sudo nerve-node setup"), "{out}");
        // The user, made once with the home the unit names.
        assert_eq!(
            sys.calls(),
            [
                format!("useradd nerve {}", l.home.display()),
                "groupadd nerve-admin".into(),
                "usermod alice nerve-admin".into(),
                "systemctl daemon-reload".into(),
                format!("systemctl enable {UNIT_NAME}"),
                format!("systemctl restart {UNIT_NAME}"),
            ]
        );
        // The one who installed is an owner, and polkit lets the owners
        // start and stop this unit only.
        assert_eq!(
            sys.members(crate::owner::GROUP),
            Some(vec!["alice".to_string()])
        );
        assert!(
            out.contains("alice is an owner of the node (nerve-admin)"),
            "{out}"
        );
        let rule = l.polkit_rule();
        assert_eq!(
            rule,
            d.path().join("etc/polkit-1/rules.d/50-nerve-node.rules")
        );
        assert_eq!(std::fs::read_to_string(&rule).unwrap(), polkit_rule_text());
        assert_eq!(mode(&rule), 0o644);
        // The program, the unit, and the folders, private to the user.
        assert_eq!(std::fs::read(&l.bin).unwrap(), b"nerve-node 1.0.0\n");
        assert_eq!(mode(&l.bin), 0o755);
        let unit = std::fs::read_to_string(&l.unit).unwrap();
        assert_eq!(unit, l.unit_text());
        assert!(unit.contains("\nUser=nerve\n"), "{unit}");
        // The one privilege: switching to the account of the commands. Nothing
        // narrows the bounding set or sets no_new_privs, which an allowed
        // sudo command needs.
        let caps: Vec<&str> = unit
            .lines()
            .filter(|l| l.contains("Capabilit") || l.contains("NoNewPrivileges"))
            .collect();
        assert_eq!(caps, ["AmbientCapabilities=CAP_SETUID CAP_SETGID"]);
        // The cgroup of the service is the node's, for one per command.
        assert!(unit.contains("\nDelegate=cpu memory pids\n"), "{unit}");
        assert!(unit.contains("\nOOMPolicy=continue\n"), "{unit}");
        // The owners' socket's folder, which every account may enter, and
        // their group, to give them the owner token.
        assert!(
            unit.contains("\nRuntimeDirectory=nerve-node\nRuntimeDirectoryMode=0755\n"),
            "{unit}"
        );
        assert!(
            unit.contains("\nGroup=nerve\nSupplementaryGroups=nerve-admin\n"),
            "{unit}"
        );
        assert!(
            unit.contains(&format!(
                "\nExecStart={} --config-dir {} --state-dir {} run\n",
                l.bin.display(),
                l.paths.config_dir.display(),
                l.paths.state_dir.display()
            )),
            "{unit}"
        );
        for dir in [&l.home, &l.paths.config_dir, &l.paths.state_dir] {
            assert_eq!(mode(dir), 0o700, "{dir:?}");
        }
        // Audited, with each step.
        let a = audit_events(&l);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0]["event"], "install");
        assert!(a[0].get("error").is_none());
        assert_eq!(a[0]["steps"].as_array().unwrap().len(), 9, "{}", a[0]);
        // Again: the user is reused, the program replaced, the service
        // restarted, the account kept.
        std::fs::write(&exe, "nerve-node 1.0.1\n").unwrap();
        let mut out = Vec::new();
        install(&l, &sys, &exe, "root", &mut out).unwrap();
        assert!(
            String::from_utf8(out.clone())
                .unwrap()
                .contains("commands run as alice, as chosen before")
        );
        assert_eq!(std::fs::read(&l.bin).unwrap(), b"nerve-node 1.0.1\n");
        assert_eq!(
            sys.calls()
                .iter()
                .filter(|c| c.starts_with("useradd"))
                .count(),
            1
        );
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("the user nerve is there already")
        );
        assert_eq!(audit_events(&l).len(), 2);
    }

    /// An earlier install's config keeps the keys in the system keyring:
    /// install checks that it answers for the node's user before it starts
    /// the service, and offers to install one only in a terminal.
    #[test]
    fn install_checks_the_keyring_the_keys_are_in() {
        use crate::keyring_setup::tests::FakeKeyring;
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = layout(d.path());
        let mut store = SettingsStore::open_with(
            l.paths.config_file(),
            Box::new(crate::secrets::NodeSecrets::new(&l.paths)),
            AuditLog::new(l.paths.audit_log()),
        )
        .unwrap();
        store
            .update(|c| {
                c.machine.secret_storage = SecretStorage::Keyring;
                Ok(())
            })
            .unwrap();
        drop(store);
        let exe = d.path().join("nerve-node");
        std::fs::write(&exe, "nerve-node 1.0.0\n").unwrap();
        let started = |sys: &Fake| sys.calls().iter().any(|c| c.contains("restart"));
        let k = FakeKeyring::new(false);
        let install = |sys: &Fake, typed: Option<&str>| {
            let mut out = Vec::new();
            let mut input = typed.map(|t| std::io::Cursor::new(t.as_bytes().to_vec()));
            let r = install_asking(
                &l,
                sys,
                &k,
                input.as_mut().map(|i| i as &mut dyn BufRead),
                &exe,
                "alice",
                &mut out,
            );
            (r, String::from_utf8(out).unwrap())
        };
        let (r, out) = install(&sys, None);
        let e = r.unwrap_err();
        assert!(e.contains("no system keyring answers for nerve"), "{e}");
        assert!(e.contains("run in a terminal"), "{e}");
        assert!(!out.contains("[y/N]"), "{out}");
        assert!(!started(&sys));
        let (r, out) = install(&sys, Some("\n"));
        assert!(r.is_err());
        assert!(out.contains("Install it now? [y/N]"), "{out}");
        assert!(k.installed.borrow().is_empty() && !started(&sys));
        let (r, out) = install(&sys, Some("y\n"));
        r.unwrap();
        assert_eq!(k.installed.borrow().len(), 1);
        assert!(started(&sys));
        assert!(out.contains("keyring of nerve, and it answers"), "{out}");
        // Root does not open the keyring, so the account is setup's.
        assert!(out.contains("`sudo nerve-node setup` chooses one"), "{out}");
        // Once it answers, nothing is asked.
        let (r, out) = install(&sys, None);
        r.unwrap();
        assert!(!out.contains("[y/N]"), "{out}");
    }

    /// On a kernel below Landlock ABI 9, an earlier install's config that
    /// keeps the keys in the keyring is refused before install changes
    /// anything, with the command that moves them into files on these
    /// folders.
    #[test]
    fn install_refuses_keys_in_the_keyring_below_landlock_9() {
        use crate::keyring_setup::tests::FakeKeyring;
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = layout(d.path());
        let mut store = SettingsStore::open_with(
            l.paths.config_file(),
            Box::new(crate::secrets::NodeSecrets::new(&l.paths)),
            AuditLog::new(l.paths.audit_log()),
        )
        .unwrap();
        store
            .update(|c| {
                c.machine.secret_storage = SecretStorage::Keyring;
                Ok(())
            })
            .unwrap();
        drop(store);
        crate::secrets::for_tests::pretend_landlock(&l.paths, crate::secrets::Landlock::Abi(6));
        let exe = d.path().join("nerve-node");
        std::fs::write(&exe, "nerve-node 1.0.0\n").unwrap();
        let k = FakeKeyring::new(true);
        let e = install_asking(&l, &sys, &k, None, &exe, "alice", &mut Vec::new()).unwrap_err();
        assert!(e.contains("install changed nothing"), "{e}");
        assert!(e.contains("Landlock ABI 6, below 9"), "{e}");
        assert!(e.contains("cannot run programs from its folders"), "{e}");
        let command = format!(
            "`nerve-node --config-dir \"{}\" --state-dir \"{}\" config set machine.secret_storage file`",
            l.paths.config_dir.display(),
            l.paths.state_dir.display()
        );
        assert!(e.contains(&command), "{e}");
        assert!(sys.calls().is_empty(), "{:?}", sys.calls());
        assert!(!l.bin.exists() && !l.unit.exists());
    }

    #[test]
    fn uninstall_ends_the_session_a_keyring_gave_the_user() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        sys.lingers.set(true);
        let mut out = Vec::new();
        uninstall(&l, &sys, true, &mut out).unwrap();
        assert!(
            sys.calls().ends_with(&[
                "loginctl disable-linger nerve".into(),
                "userdel nerve".into()
            ]),
            "{:?}",
            sys.calls()
        );
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("ended the session of nerve"), "{out}");
    }

    #[test]
    fn install_takes_root_with_a_warning_and_leaves_an_unusable_account_to_setup() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = layout(d.path());
        let mut out = Vec::new();
        install(&l, &sys, Path::new("/bin/true"), "root", &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("commands run as root"), "{out}");
        assert!(
            out.contains("Warning: commands from a center then run as root")
                && out.contains("You are responsible"),
            "{out}"
        );
        let user = |l: &Layout| {
            SettingsStore::peek(&l.paths.config_file(), &l.paths.config_key())
                .unwrap()
                .machine
                .user
        };
        assert_eq!(user(&l).as_deref(), Some("root"));
        // An account that is not there, or the node's own: no account, and
        // install still does the rest.
        for who in ["ghost", USER] {
            let l = layout(&d.path().join(who));
            let mut out = Vec::new();
            install(&l, &sys, Path::new("/bin/true"), who, &mut out).unwrap();
            let out = String::from_utf8(out).unwrap();
            assert!(out.contains("no account for commands"), "{out}");
            assert!(out.contains("sudo nerve-node setup"), "{out}");
            assert_eq!(user(&l), None);
            assert!(l.unit.is_file());
        }
    }

    /// Setup's account step, with what the owner types.
    fn choose(
        sys: &Fake,
        l: &Layout,
        current: Option<&str>,
        typed: &str,
    ) -> (Result<Option<Chosen>, String>, String) {
        let mut out = Vec::new();
        let mut input = std::io::Cursor::new(typed.as_bytes().to_vec());
        let r = choose_account(
            sys,
            &l.paths,
            current,
            Some("alice"),
            "alice",
            &mut input,
            &mut out,
        );
        (r, String::from_utf8(out).unwrap())
    }

    #[test]
    fn setup_chooses_or_makes_the_account_of_the_commands() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        let chosen = |name: &str, made| {
            Some(Chosen {
                name: name.into(),
                made,
            })
        };
        // Default: Enter takes the account that runs setup, or keeps the
        // one chosen.
        let (r, out) = choose(&sys, &l, None, "\n");
        assert_eq!(r.unwrap(), chosen("alice", false));
        assert!(out.contains("[alice]"), "{out}");
        // Kept: nothing changes, and the warning is said again.
        let (r, out) = choose(&sys, &l, Some("alice"), "\n");
        assert_eq!(r.unwrap(), None);
        assert!(out.contains("alice is the account that ran sudo"), "{out}");
        // Chosen: another account that exists, and a boundary.
        sys.others.borrow_mut().push(other("carol", 4343));
        let (r, out) = choose(&sys, &l, Some("alice"), "carol\n");
        assert_eq!(r.unwrap(), chosen("carol", false));
        assert!(!out.contains("Warning"), "{out}");
        // Made: setup asks, then makes it.
        let (r, out) = choose(&sys, &l, Some("alice"), "bob\ny\n");
        assert_eq!(r.unwrap(), chosen("bob", true));
        assert!(out.contains("There is no account bob. Make it"), "{out}");
        assert!(sys.calls().contains(&"useradd bob /home/bob".to_string()));
        // Root: allowed, with the warning.
        let (r, out) = choose(&sys, &l, Some("alice"), "root\n");
        assert_eq!(r.unwrap(), chosen("root", false));
        assert!(
            out.contains("run as root") && out.contains("You are responsible"),
            "{out}"
        );
        // An account in a group that gets root: allowed, with a warning.
        sys.root_groups
            .borrow_mut()
            .push(("carol".into(), "docker".into()));
        let (r, out) = choose(
            &sys,
            &l,
            Some("alice"),
            "carol
",
        );
        assert_eq!(r.unwrap(), chosen("carol", false));
        assert!(out.contains("carol is in the group docker"), "{out}");
        assert!(out.contains("--create-user nerve-work"), "{out}");
        let (_, out) = choose(
            &sys,
            &l,
            Some("carol"),
            "alice
",
        );
        assert!(out.contains("alice is the account that ran sudo"), "{out}");
        // Refused: one that is not there and is not to be made, a name
        // useradd would not take, the node's own user.
        let made = sys.calls().len();
        let e = choose(&sys, &l, None, "dave\nn\n").0.unwrap_err();
        assert!(e.contains("there is no account dave"), "{e}");
        let e = choose(&sys, &l, None, "Dave.X\n").0.unwrap_err();
        assert!(e.contains("there is no account Dave.X"), "{e}");
        let e = choose(&sys, &l, None, "a:b\n").0.unwrap_err();
        assert!(e.contains("not an account name"), "{e}");
        assert_eq!(sys.calls().len(), made, "nothing was made");
        let e = choose(&sys, &l, None, "nerve\n").0.unwrap_err();
        assert!(e.contains("node's own user"), "{e}");
    }

    /// An account whose sudo asks for no password is warned about by
    /// install and by setup, kept or chosen, and neither stops.
    #[test]
    fn a_sudo_without_a_password_is_warned_about() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        sys.others.borrow_mut().push(other("carol", 4343));
        sys.sudo_without_password.borrow_mut().push("carol".into());
        // Install, for the account chosen before as for a new one.
        let l = layout(d.path());
        let install_as = |who: &str| {
            let mut out = Vec::new();
            install(&l, &sys, Path::new("/bin/true"), who, &mut out).unwrap();
            String::from_utf8(out).unwrap()
        };
        let out = install_as("carol");
        assert!(
            out.contains("carol may use sudo without a password"),
            "{out}"
        );
        assert!(
            out.contains("sudo nerve-node setup --create-user nerve-work"),
            "{out}"
        );
        assert!(out.contains("commands run as carol"), "{out}");
        let out = install_as("alice");
        assert!(
            out.contains("commands run as carol, as chosen before"),
            "{out}"
        );
        assert!(
            out.contains("carol may use sudo without a password"),
            "{out}"
        );
        assert!(!out.contains("alice is the account"), "{out}");
        // Setup: kept, chosen, and made with --create-user.
        let (r, out) = choose(&sys, &l, Some("carol"), "\n");
        assert_eq!(r.unwrap(), None);
        assert!(
            out.contains("carol may use sudo without a password"),
            "{out}"
        );
        let (r, out) = choose(&sys, &l, Some("bob"), "carol\n");
        assert!(r.unwrap().is_some());
        assert!(
            out.contains("carol may use sudo without a password"),
            "{out}"
        );
        let mut out = Vec::new();
        create_account(&sys, &l.paths, "carol", "alice", &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("carol may use sudo without a password"),
            "{out}"
        );
        // An account made for the node is a boundary.
        let mut out = Vec::new();
        create_account(&sys, &l.paths, "nerve-work", "alice", &mut out).unwrap();
        assert!(!String::from_utf8(out).unwrap().contains("Warning"));
    }

    /// The installed node is known by its folders, not by how it started.
    #[test]
    fn the_installed_folders_make_the_service_node() {
        assert!(is_service_node(&Layout::system().paths));
        let d = tempfile::tempdir().unwrap();
        assert!(!is_service_node(&NodePaths::new(
            d.path().join("c"),
            d.path().join("s")
        )));
    }

    /// `setup --create-user`: makes the account without a question, by the
    /// rules of the interactive step.
    #[test]
    fn create_user_makes_the_account_without_asking() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        let create = |name: &str| {
            let mut out = Vec::new();
            let r = create_account(&sys, &l.paths, name, "alice", &mut out);
            (r, String::from_utf8(out).unwrap())
        };
        let (r, out) = create("bob");
        assert_eq!(
            r.unwrap(),
            Chosen {
                name: "bob".into(),
                made: true
            }
        );
        assert!(out.contains("made the account bob"), "{out}");
        assert!(sys.calls().contains(&"useradd bob /home/bob".to_string()));
        let bob = sys.account("bob").unwrap().unwrap();
        assert_eq!(bob.home, Path::new("/home/bob"));
        assert_eq!(bob.comment, "Nerve user mode");
        // There already, and usable: taken, not made again.
        let made = sys.calls().len();
        assert!(!create("bob").0.unwrap().made);
        assert!(!create("alice").0.unwrap().made);
        // Refused, with nothing made: nerve, the node's user under another
        // name, and names useradd would not take.
        sys.others.borrow_mut().push(Account {
            name: "svc".into(),
            ..me()
        });
        for (name, why) in [
            ("nerve", "node's own user"),
            ("svc", "node's own user"),
            ("Bob", "not a name setup makes"),
            ("a:b", "not a name setup makes"),
            ("-x", "not a name setup makes"),
        ] {
            let e = create(name).0.unwrap_err();
            assert!(e.contains(why), "{name}: {e}");
        }
        assert_eq!(sys.calls().len(), made, "nothing was made");
    }

    /// The account of the commands cannot read the keys: they are 0600 in
    /// folders private to `nerve`. An account that could open those folders
    /// is refused.
    #[test]
    fn the_account_of_the_commands_cannot_read_the_keys() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        // Open down to the node's folders, as / and /etc are.
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        for open in ["etc", "var", "var/lib"] {
            std::fs::set_permissions(d.path().join(open), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        let key = l.paths.key_file("lab");
        nerve_transport::files::write_private(&key, b"key").unwrap();
        let cfg = SettingsStore::peek(&l.paths.config_file(), &l.paths.config_key()).unwrap();
        let name = cfg.machine.user.unwrap();
        let account = sys.account(&name).unwrap().unwrap();
        assert_ne!(account.uid, me().uid);
        for p in [
            key.clone(),
            l.paths.config_key(),
            l.paths.config_file(),
            l.paths.audit_log(),
        ] {
            assert!(p.exists(), "{p:?}");
            assert!(!crate::account::reaches(&p, &account), "{p:?}");
            assert!(crate::account::reaches(&p, &me()), "{p:?}");
        }
        assert_eq!(mode(&key), 0o600);
        usable_account(&sys, &l.paths, &name).unwrap();
        // Opened to others, the folder and the key are in its reach, and
        // the account is refused.
        std::fs::set_permissions(&l.paths.config_dir, std::fs::Permissions::from_mode(0o755))
            .unwrap();
        std::fs::set_permissions(
            key.parent().unwrap(),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(crate::account::reaches(&key, &account));
        let e = usable_account(&sys, &l.paths, &name).unwrap_err();
        assert!(e.contains("could open"), "{e}");
    }

    /// A link in place of one of the node's folders, as the node's user could
    /// leave one, is refused: install neither changes nor writes through it.
    #[test]
    fn install_follows_no_link_in_place_of_a_folder() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = layout(d.path());
        let elsewhere = d.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::create_dir_all(&l.home).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &l.paths.state_dir).unwrap();
        let mut out = Vec::new();
        let e = install(&l, &sys, Path::new("/bin/true"), "alice", &mut out).unwrap_err();
        assert!(e.contains("is a link"), "{e}");
        assert_eq!(mode(&elsewhere), 0o755);
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
        assert!(!l.unit.exists());
        // Nor is the audit entry written through it.
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("the audit log cannot be written"), "{out}");
    }

    /// The walk that gives the folders away changes a link itself and does
    /// not go through it.
    #[test]
    fn chown_tree_does_not_walk_through_links() {
        let d = tempfile::tempdir().unwrap();
        let tree = d.path().join("tree");
        let outside = d.path().join("outside");
        std::fs::create_dir_all(tree.join("sub")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(tree.join("sub/f"), "x").unwrap();
        std::os::unix::fs::symlink(&outside, tree.join("link")).unwrap();
        // A folder it may not read stops the walk with its name: the walk
        // reached it through `tree/sub`, and would through `link` if it
        // followed links.
        std::fs::create_dir(outside.join("closed")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            outside.join("closed"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        let me = me();
        let r = chown_tree(&tree, me.uid, me.gid);
        std::fs::set_permissions(
            outside.join("closed"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        r.unwrap();
        // The tree given as a link is changed as a link only.
        chown_tree(&tree.join("link"), me.uid, me.gid).unwrap();
    }

    /// A socket in the tree, as the control socket of a node that ran is in
    /// its state folder, and a FIFO are given away as a file is: neither is
    /// opened, which a socket refuses and a FIFO would wait on. The walk
    /// runs aside, so a FIFO that holds it fails the test instead of
    /// hanging it.
    #[test]
    fn chown_tree_gives_a_socket_and_a_fifo_away() {
        let d = tempfile::tempdir().unwrap();
        let tree = d.path().join("tree");
        std::fs::create_dir_all(tree.join("run")).unwrap();
        let _l = std::os::unix::net::UnixListener::bind(tree.join("run/ctl.sock")).unwrap();
        let fifo =
            std::ffi::CString::new(tree.join("run/fifo").into_os_string().into_encoded_bytes())
                .unwrap();
        // SAFETY: a valid C string.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let me = me();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || tx.send(chown_tree(&tree, me.uid, me.gid)));
        rx.recv_timeout(std::time::Duration::from_secs(10))
            .expect("the walk waits on the FIFO")
            .unwrap();
    }

    /// A file with a second name, which the node's user could have made to
    /// a file of root's, is not given away.
    #[cfg(target_os = "linux")]
    #[test]
    fn chown_tree_gives_no_hard_linked_file_away() {
        let d = tempfile::tempdir().unwrap();
        let tree = d.path().join("tree");
        std::fs::create_dir_all(tree.join("sub")).unwrap();
        let outside = d.path().join("shadow");
        std::fs::write(&outside, "x").unwrap();
        std::fs::hard_link(&outside, tree.join("sub/x")).unwrap();
        let me = me();
        let e = chown_tree(&tree, me.uid, me.gid).unwrap_err();
        assert!(e.contains("sub/x") && e.contains("hard link"), "{e}");
        std::fs::remove_file(&outside).unwrap();
        chown_tree(&tree, me.uid, me.gid).unwrap();
    }

    #[test]
    fn install_refuses_a_user_it_did_not_make_and_needs_root() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        *sys.user.borrow_mut() = Some(Account {
            comment: "someone".into(),
            ..me()
        });
        let l = layout(d.path());
        let e = install(&l, &sys, Path::new("/bin/true"), "alice", &mut Vec::new()).unwrap_err();
        assert!(e.contains("did not make it"), "{e}");
        assert!(!l.bin.exists() && !l.unit.exists());
        assert!(sys.calls().is_empty());

        struct NotRoot;
        impl System for NotRoot {
            fn is_root(&self) -> bool {
                false
            }
            fn has_systemd(&self) -> bool {
                true
            }
            fn account(&self, _: &str) -> Result<Option<Account>, String> {
                unreachable!()
            }
            fn root_groups(&self, _: &Account) -> Vec<String> {
                unreachable!()
            }
            fn add_user(&self, _: &str, _: &Path) -> Result<(), String> {
                unreachable!()
            }
            fn add_account(&self, _: &str, _: &Path) -> Result<(), String> {
                unreachable!()
            }
            fn remove_account(&self, _: &str) -> Result<(), String> {
                unreachable!()
            }
            fn systemctl(&self, _: &[&str]) -> Result<(), String> {
                unreachable!()
            }
            fn give(&self, _: &Path, _: u32, _: u32) -> Result<(), String> {
                unreachable!()
            }
            fn wait_running(&self, _: &NodePaths) -> Result<(), String> {
                unreachable!()
            }
            fn version_of(&self, _: &Path, _: &Account) -> Result<String, String> {
                unreachable!()
            }
            fn unit_state(&self) -> Result<ServiceState, String> {
                unreachable!()
            }
        }
        for (what, e) in [
            (
                "install",
                install(
                    &l,
                    &NotRoot,
                    Path::new("/bin/true"),
                    "alice",
                    &mut Vec::new(),
                ),
            ),
            ("uninstall", uninstall(&l, &NotRoot, false, &mut Vec::new())),
        ] {
            assert_eq!(
                e.unwrap_err(),
                format!("{what} needs root: run `sudo nerve-node {what}`")
            );
        }
        // Starting and stopping is polkit's to allow (the owners' rule), so
        // it is not refused for want of root here.
        let e = control(&l, &NotRoot, ServiceAction::Stop, &mut Vec::new()).unwrap_err();
        assert!(e.contains("not installed as a service"), "{e}");
    }

    #[test]
    fn uninstall_leaves_no_service_user_or_program_and_keeps_the_folders() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        std::fs::write(l.paths.config_file(), "version = 3\n").unwrap();
        let mut out = Vec::new();
        uninstall(&l, &sys, false, &mut out).unwrap();
        assert!(!l.unit.exists() && !l.bin.exists());
        assert!(sys.user.borrow().is_none());
        assert!(
            sys.calls().ends_with(&[
                format!("systemctl disable --now {UNIT_NAME}"),
                "systemctl daemon-reload".into(),
                format!("systemctl reset-failed {UNIT_NAME}"),
                "groupdel nerve-admin".into(),
                "userdel nerve".into(),
            ]),
            "{:?}",
            sys.calls()
        );
        assert!(!l.polkit_rule().exists());
        assert_eq!(sys.members(crate::owner::GROUP), None);
        // The config and state stay, and the audit log has both commands.
        assert_eq!(
            std::fs::read_to_string(l.paths.config_file()).unwrap(),
            "version = 3\n"
        );
        let events: Vec<_> = audit_events(&l)
            .iter()
            .map(|v| v["event"].clone())
            .collect();
        assert_eq!(events, ["install", "uninstall"]);
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("uninstall --purge"), "{out}");
        // No uid that may come to another user owns them: they are root's.
        let given = sys.given.borrow().clone();
        assert_eq!(
            given,
            [
                (l.paths.config_dir.clone(), 0),
                (l.home.clone(), 0),
                (l.paths.state_dir.clone(), 0)
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn uninstall_writes_no_audit_entry_through_a_link_or_a_second_name() {
        // Without --purge the folders are root's before the entry is
        // written, so it is written as root: a link or a hard link left in
        // place of the log must not lead that write outside the folders.
        for hard in [false, true] {
            let d = tempfile::tempdir().unwrap();
            let sys = Fake::new();
            let l = installed(d.path(), &sys, "1.0.0");
            let outside = d.path().join("outside");
            std::fs::write(&outside, "kept\n").unwrap();
            std::fs::remove_file(l.paths.audit_log()).unwrap();
            if hard {
                std::fs::hard_link(&outside, l.paths.audit_log()).unwrap();
            } else {
                std::os::unix::fs::symlink(&outside, l.paths.audit_log()).unwrap();
            }
            let mut out = Vec::new();
            uninstall(&l, &sys, false, &mut out).unwrap();
            assert_eq!(std::fs::read_to_string(&outside).unwrap(), "kept\n");
            let out = String::from_utf8(out).unwrap();
            assert!(out.contains("the audit log cannot be written"), "{out}");
            assert!(!l.bin.exists() && sys.user.borrow().is_none());
        }
    }

    #[test]
    fn uninstall_purge_deletes_the_folders_and_leaves_a_foreign_user() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        uninstall(&l, &sys, true, &mut Vec::new()).unwrap();
        for p in [
            &l.unit,
            &l.bin,
            &l.home,
            &l.paths.config_dir,
            &l.paths.state_dir,
        ] {
            assert!(!p.exists(), "{p:?}");
        }
        assert!(sys.user.borrow().is_none());
        let mut out = Vec::new();
        uninstall(&l, &sys, true, &mut out).unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .starts_with("nothing to uninstall"),
        );
        // A nerve user that install did not make stays.
        *sys.user.borrow_mut() = Some(Account {
            comment: "someone".into(),
            ..me()
        });
        let mut out = Vec::new();
        uninstall(&l, &sys, true, &mut out).unwrap();
        assert!(sys.user.borrow().is_some());
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("left the user nerve")
        );
    }

    /// What update must not touch: the config, a key and the audit log so far.
    fn kept(l: &Layout) -> Vec<(PathBuf, Vec<u8>)> {
        [
            l.paths.config_file(),
            l.paths.key_file("lab"),
            l.paths.config_key(),
            l.paths.audit_log(),
        ]
        .into_iter()
        .map(|p| {
            let b = std::fs::read(&p).unwrap();
            (p, b)
        })
        .collect()
    }

    fn with_files(l: &Layout) {
        std::fs::write(l.paths.config_file(), "version = 7\n").unwrap();
        std::fs::create_dir_all(l.paths.key_file("lab").parent().unwrap()).unwrap();
        std::fs::write(l.paths.key_file("lab"), "key").unwrap();
        std::fs::write(l.paths.config_key(), "mac key").unwrap();
    }

    /// An install from before the owners gets them at its update: the
    /// group with the one who updates in it, the polkit rule and the unit
    /// with the owners' runtime folder and their group for the owner token.
    /// An update after that changes no owner.
    #[tokio::test]
    async fn an_update_gives_an_earlier_install_its_owners() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        // As an install before them left it.
        sys.groups.borrow_mut().clear();
        std::fs::remove_file(l.polkit_rule()).unwrap();
        let old_unit = l
            .unit_text()
            .replace(
                "RuntimeDirectory=nerve-node\nRuntimeDirectoryMode=0755\n",
                "",
            )
            .replace("SupplementaryGroups=nerve-admin\n", "");
        std::fs::write(&l.unit, &old_unit).unwrap();
        let new = d.path().join("new");
        std::fs::write(&new, "nerve-node 1.2.0\n").unwrap();
        let mut out = Vec::new();
        update(&l, &sys, Some(&new), "alice", &mut out)
            .await
            .unwrap();
        let out = String::from_utf8(out).unwrap();
        assert_eq!(std::fs::read_to_string(&l.unit).unwrap(), l.unit_text());
        assert!(out.contains("wrote the service unit"), "{out}");
        assert_eq!(
            sys.members(crate::owner::GROUP),
            Some(vec!["alice".to_string()])
        );
        assert_eq!(
            std::fs::read_to_string(l.polkit_rule()).unwrap(),
            polkit_rule_text()
        );
        // The unit is read again before the restart that takes it.
        let calls = sys.calls();
        let reload = calls.iter().rposition(|c| c == "systemctl daemon-reload");
        let restart = calls
            .iter()
            .rposition(|c| *c == format!("systemctl restart {UNIT_NAME}"));
        assert!(reload < restart, "{calls:?}");
        // The next update keeps the owners as they are.
        let before = sys.calls().len();
        std::fs::write(&new, "nerve-node 1.3.0\n").unwrap();
        let mut out = Vec::new();
        update(&l, &sys, Some(&new), "root", &mut out)
            .await
            .unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(!out.contains("owner"), "{out}");
        assert!(!out.contains("polkit"), "{out}");
        assert!(
            !sys.calls()[before..]
                .iter()
                .any(|c| c.starts_with("usermod") || c.starts_with("groupadd")),
            "{:?}",
            sys.calls()
        );
    }

    /// Without polkit the owners are told that starting and stopping needs
    /// sudo; root alone installing makes no owner.
    #[test]
    fn install_says_what_polkit_and_the_owners_are_here() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        sys.polkit.set(Polkit::Missing);
        let l = layout(d.path());
        let exe = d.path().join("nerve-node-x86_64-linux");
        std::fs::write(&exe, "nerve-node 1.0.0\n").unwrap();
        let mut out = Vec::new();
        install(&l, &sys, &exe, "root", &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("Warning: polkit is not installed"), "{out}");
        for f in [
            l.polkit_rule(),
            l.polkit_pkla(),
            l.polkit_action(),
            l.service_helper(),
        ] {
            assert!(!f.exists(), "{}", f.display());
        }
        assert!(out.contains("no owner besides root"), "{out}");
        assert_eq!(sys.members(crate::owner::GROUP), Some(Vec::new()));
    }

    /// On polkit 0.105, which takes no rules, the owners get the service
    /// helper through its own action and a `.pkla` file for it, never one
    /// for systemd's `manage-units`; on a newer polkit through the rule.
    /// An update moves from one to the other, and uninstall removes them.
    #[tokio::test]
    async fn polkit_0105_gets_the_helper_and_a_pkla_file_and_newer_the_rule() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        sys.polkit.set(Polkit::Old);
        let l = installed(d.path(), &sys, "1.0.0");
        let helper = l.service_helper();
        assert_eq!(
            helper,
            d.path().join("usr/local/lib/nerve-node/service-control")
        );
        assert_eq!(
            std::fs::read_to_string(&helper).unwrap(),
            service_helper_text()
        );
        assert_eq!(mode(&helper), 0o755);
        let action = l.polkit_action();
        assert_eq!(
            action,
            d.path()
                .join("usr/share/polkit-1/actions/org.nerve-protocol.node.service-control.policy")
        );
        let policy = std::fs::read_to_string(&action).unwrap();
        assert_eq!(policy, polkit_action_text(&helper));
        assert!(
            policy.contains(&format!(
                "<annotate key=\"org.freedesktop.policykit.exec.path\">{}</annotate>",
                helper.display()
            )),
            "{policy}"
        );
        assert!(policy.contains("<allow_active>auth_admin</allow_active>"));
        let pkla = l.polkit_pkla();
        assert_eq!(
            pkla,
            d.path()
                .join("etc/polkit-1/localauthority/50-local.d/50-nerve-node.pkla")
        );
        let text = std::fs::read_to_string(&pkla).unwrap();
        assert_eq!(text, polkit_pkla_text());
        for line in [
            "Identity=unix-group:nerve-admin",
            "Action=org.nerve-protocol.node.service-control",
            "ResultActive=yes",
        ] {
            assert!(text.lines().any(|l| l == line), "{line}: {text}");
        }
        assert!(!text.contains("manage-units") && !text.contains("ResultAny"));
        assert!(!l.polkit_rule().exists());

        // The machine got a newer polkit: the rule takes the .pkla file's
        // place.
        sys.polkit.set(Polkit::Rules);
        let new = d.path().join("new");
        std::fs::write(&new, "nerve-node 1.1.0\n").unwrap();
        let mut out = Vec::new();
        update(&l, &sys, Some(&new), "alice", &mut out)
            .await
            .unwrap();
        let rule = std::fs::read_to_string(l.polkit_rule()).unwrap();
        assert!(rule.contains(POLKIT_ACTION), "{rule}");
        assert!(!pkla.exists());
        assert!(helper.is_file() && action.is_file());

        let mut out = Vec::new();
        uninstall(&l, &sys, false, &mut out).unwrap();
        for f in [l.polkit_rule(), pkla, action, helper.clone()] {
            assert!(!f.exists(), "{}", f.display());
        }
        assert!(!helper.parent().unwrap().exists());
    }

    /// The helper does what it says and nothing else: one of the three
    /// words, or it stops before systemctl.
    #[cfg(unix)]
    #[test]
    fn the_service_helper_takes_three_words_only() {
        let d = tempfile::tempdir().unwrap();
        let helper = d.path().join("service-control");
        std::fs::write(&helper, service_helper_text()).unwrap();
        let sh = |args: &[&str]| {
            std::process::Command::new("sh")
                .arg(&helper)
                .args(args)
                .output()
                .unwrap()
        };
        let checked = std::process::Command::new("sh")
            .arg("-n")
            .arg(&helper)
            .status()
            .unwrap();
        assert!(checked.success());
        for args in [
            &[][..],
            &["status"][..],
            &["start", "other.service"][..],
            &["enable"][..],
            &["start;id"][..],
        ] {
            let o = sh(args);
            assert_eq!(o.status.code(), Some(2), "{args:?}");
            assert!(
                String::from_utf8_lossy(&o.stderr).contains("usage"),
                "{args:?}"
            );
        }
        let text = service_helper_text();
        assert!(
            text.contains(&format!("exec systemctl \"$1\" {UNIT_NAME}")),
            "{text}"
        );
    }

    #[test]
    fn polkit_is_told_by_its_version() {
        for (said, kind) in [
            ("pkaction version 0.105\n", Some(Polkit::Old)),
            ("pkaction version 0.106", Some(Polkit::Rules)),
            ("pkaction version 0.116", Some(Polkit::Rules)),
            ("pkaction version 124\n", Some(Polkit::Rules)),
            ("pkaction version 122", Some(Polkit::Rules)),
            ("", None),
            ("pkaction version x", None),
        ] {
            assert_eq!(polkit_of_version(said), kind, "{said:?}");
        }
    }

    #[tokio::test]
    async fn update_replaces_the_program_and_keeps_config_keys_and_audit() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        with_files(&l);
        let before = kept(&l);
        let new = d.path().join("new");
        std::fs::write(&new, "nerve-node 1.2.0\n").unwrap();
        let mut out = Vec::new();
        update(&l, &sys, Some(&new), "alice", &mut out)
            .await
            .unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("replaced nerve-node 1.0.0 with 1.2.0"),
            "{out}"
        );
        assert_eq!(std::fs::read(&l.bin).unwrap(), b"nerve-node 1.2.0\n");
        assert_eq!(mode(&l.bin), 0o755);
        assert_eq!(
            sys.calls().last().unwrap(),
            &format!("systemctl restart {UNIT_NAME}")
        );
        // Everything else as it was; the audit log only grew.
        for (p, b) in before {
            let now = std::fs::read(&p).unwrap();
            if p == l.paths.audit_log() {
                assert!(now.starts_with(&b), "{p:?}");
            } else {
                assert_eq!(now, b, "{p:?}");
            }
        }
        let a = audit_events(&l);
        assert_eq!(a.last().unwrap()["event"], "update");
        assert!(!l.bin.with_file_name(".nerve-node.new").exists());
        // The same program again changes nothing.
        let calls = sys.calls().len();
        let mut out = Vec::new();
        update(&l, &sys, Some(&new), "alice", &mut out)
            .await
            .unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("nothing to update")
        );
        assert_eq!(sys.calls().len(), calls);
    }

    #[tokio::test]
    async fn update_refuses_an_older_or_foreign_program_and_puts_back_one_that_does_not_start() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.2.0");
        let new = d.path().join("new");
        for (text, why) in [
            ("nerve-node 1.1.9\n", "older than the installed 1.2.0"),
            ("something else\n", "is not nerve-node"),
        ] {
            std::fs::write(&new, text).unwrap();
            let e = update(&l, &sys, Some(&new), "alice", &mut Vec::new())
                .await
                .unwrap_err();
            assert!(e.contains(why), "{e}");
            assert_eq!(std::fs::read(&l.bin).unwrap(), b"nerve-node 1.2.0\n");
            assert!(!l.bin.with_file_name(".nerve-node.new").exists());
        }
        std::fs::write(&new, "nerve-node 2.0.0\n").unwrap();
        sys.starts.set(false);
        let e = update(&l, &sys, Some(&new), "alice", &mut Vec::new())
            .await
            .unwrap_err();
        assert!(e.contains("did not start"), "{e}");
        assert_eq!(std::fs::read(&l.bin).unwrap(), b"nerve-node 1.2.0\n");
        let a = audit_events(&l);
        let last = a.last().unwrap();
        assert_eq!(last["event"], "update");
        assert!(last["error"].as_str().unwrap().contains("did not start"));
        assert!(
            last["steps"]
                .to_string()
                .contains("put nerve-node 1.2.0 back")
        );
    }

    #[tokio::test]
    async fn update_needs_an_installed_node() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let e = update(&layout(d.path()), &sys, None, "alice", &mut Vec::new())
            .await
            .unwrap_err();
        assert!(e.contains("not installed"), "{e}");
    }

    /// A release on a local server: `SHA256SUMS` and the program, the
    /// program behind a redirect as GitHub has it.
    async fn release(program: &'static [u8], sums: String) -> String {
        use nerve_transport::http::{Response, read_request};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let asset = asset_name("nerve-node").unwrap();
        tokio::spawn(async move {
            while let Ok((mut io, _)) = listener.accept().await {
                let req = read_request(&mut io, 0).await.unwrap();
                let r = if req.path == "/rel/SHA256SUMS" {
                    Response::text(200, &sums)
                } else if req.path == format!("/rel/{asset}") {
                    Response::new(302, "text/plain", "").with_header("Location", "/blob?sig=x")
                } else if req.path == "/blob" && req.query_param("sig").as_deref() == Some("x") {
                    Response::new(200, "application/octet-stream", program)
                } else {
                    Response::text(404, "no")
                };
                let _ = r.write(&mut io).await;
            }
        });
        format!("http://127.0.0.1:{port}/rel")
    }

    /// The release download follows five redirects, as the node's own loop
    /// did before it moved to the shared downloader, and refuses a sixth
    /// (review r3, finding 7).
    #[tokio::test]
    async fn the_download_follows_five_redirects_and_no_more() {
        use nerve_transport::http::{Response, read_request};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // `/rN` redirects to `/r(N+1)` up to `/r6`, which answers.
        tokio::spawn(async move {
            while let Ok((mut io, _)) = listener.accept().await {
                let req = read_request(&mut io, 0).await.unwrap();
                let n: u8 = req.path.trim_start_matches("/r").parse().unwrap_or(9);
                let r = if n >= 6 {
                    Response::text(200, "end")
                } else {
                    Response::new(302, "text/plain", "")
                        .with_header("Location", &format!("/r{}", n + 1))
                };
                let _ = r.write(&mut io).await;
            }
        });
        let url = |n: u8| format!("http://127.0.0.1:{port}/r{n}");
        assert_eq!(download(&url(1), 1024).await.unwrap(), b"end");
        let e = download(&url(0), 1024).await.unwrap_err();
        assert!(e.contains("too many redirects"), "{e}");
    }

    fn sha(b: &[u8]) -> String {
        ring::digest::digest(&ring::digest::SHA256, b)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    #[tokio::test]
    async fn update_downloads_the_release_and_checks_it() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let mut l = installed(d.path(), &sys, "1.0.0");
        let program: &[u8] = b"nerve-node 1.3.0\n";
        let asset = asset_name("nerve-node").unwrap();
        l.release = release(
            program,
            format!("{}  other\n{} *{asset}\n", sha(b"x"), sha(program)),
        )
        .await;
        let mut out = Vec::new();
        update(&l, &sys, None, "alice", &mut out).await.unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("checked it against its SHA256SUMS"), "{out}");
        assert_eq!(std::fs::read(&l.bin).unwrap(), program);

        // A program that does not match its line is refused.
        let mut l2 = installed(&d.path().join("two"), &sys, "1.0.0");
        l2.release = release(program, format!("{}  {asset}\n", sha(b"other"))).await;
        let e = update(&l2, &sys, None, "alice", &mut Vec::new())
            .await
            .unwrap_err();
        assert!(e.contains("does not match"), "{e}");
        assert_eq!(std::fs::read(&l2.bin).unwrap(), b"nerve-node 1.0.0\n");
        // So is a release that does not list it.
        l2.release = release(program, format!("{}  other\n", sha(program))).await;
        let e = update(&l2, &sys, None, "alice", &mut Vec::new())
            .await
            .unwrap_err();
        assert!(e.contains("lists no"), "{e}");
    }

    #[test]
    fn versions_and_addresses() {
        assert_eq!(
            Version::parse("nerve-node 0.10.2\n"),
            Some(Version(0, 10, 2))
        );
        assert!(Version(0, 10, 0) > Version(0, 9, 9));
        for bad in [
            "nerve-center 1.0.0",
            "nerve-node 1.0",
            "nerve-node 1.0.0.1",
            "nerve-node x",
        ] {
            assert_eq!(Version::parse(bad), None, "{bad}");
        }
        let (at, target) = split_url("https://example.com/a/b?x=1").unwrap();
        assert_eq!(
            (at.host.as_str(), at.port, at.tls),
            ("example.com", 443, true)
        );
        assert_eq!(target, "/a/b?x=1");
        let (at, target) = split_url("http://127.0.0.1:8080?q").unwrap();
        assert_eq!((at.port, target.as_str()), (8080, "/?q"));
        assert!(split_url("ftp://x/y").is_err());
    }

    /// The desktop app's parts, as a file beside the program.
    struct Entry;

    impl crate::edition::Parts for Entry {
        fn install(&self, bin: &Path) -> Result<Vec<String>, String> {
            std::fs::write(bin.with_file_name("menu-entry"), "Exec").map_err(|e| e.to_string())?;
            Ok(vec!["put the menu entry in place".into()])
        }
        fn uninstall(&self, bin: &Path) -> Result<Vec<String>, String> {
            let entry = bin.with_file_name("menu-entry");
            if !entry.exists() {
                return Ok(Vec::new());
            }
            std::fs::remove_file(entry).map_err(|e| e.to_string())?;
            Ok(vec!["removed the menu entry".into()])
        }
    }

    static DESKTOP: crate::edition::Edition = crate::edition::Edition {
        program: "nerve-node-desktop",
        parts: Some(&Entry),
    };

    #[tokio::test]
    async fn the_desktop_app_installs_updates_and_uninstalls_its_parts_with_the_node() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = Layout {
            bin: d.path().join("usr/local/bin/nerve-node-desktop"),
            edition: &DESKTOP,
            ..layout(d.path())
        };
        let entry = l.bin.with_file_name("menu-entry");
        let exe = d.path().join("Downloads/nerve-node-desktop-x86_64-linux");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, "nerve-node-desktop 1.0.0\n").unwrap();
        let mut out = Vec::new();
        install(&l, &sys, &exe, "alice", &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("put the menu entry in place"), "{out}");
        assert!(entry.exists());
        assert!(
            std::fs::read_to_string(&l.unit)
                .unwrap()
                .contains(&format!("ExecStart={} --config-dir", l.bin.display())),
        );
        let step = |event: &str| {
            audit_events(&l)
                .iter()
                .rev()
                .find(|e| e["event"] == event)
                .unwrap()
                .to_string()
        };
        assert!(step("install").contains("menu entry"));

        // The node's program is not the app's, and the app's own goes in,
        // its parts put back.
        let new = d.path().join("new");
        std::fs::write(&new, "nerve-node 1.1.0\n").unwrap();
        let e = update(&l, &sys, Some(&new), "alice", &mut Vec::new())
            .await
            .unwrap_err();
        assert!(e.contains("is not nerve-node-desktop"), "{e}");
        std::fs::remove_file(&entry).unwrap();
        std::fs::write(&new, "nerve-node-desktop 1.1.0\n").unwrap();
        let mut out = Vec::new();
        update(&l, &sys, Some(&new), "alice", &mut out)
            .await
            .unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("replaced nerve-node-desktop 1.0.0 with 1.1.0"),
            "{out}"
        );
        assert!(entry.exists(), "{out}");
        assert!(!l.bin.with_file_name(".nerve-node-desktop.new").exists());

        let mut out = Vec::new();
        uninstall(&l, &sys, false, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("removed the menu entry"), "{out}");
        assert!(!entry.exists() && !l.bin.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_app_makes_the_node_installed_alone_a_link_to_it_and_removes_it() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        // A node installed with nerve-node.
        let node = installed(d.path(), &sys, "1.0.0");
        let l = Layout {
            bin: d.path().join("usr/local/bin/nerve-node-desktop"),
            edition: &DESKTOP,
            ..layout(d.path())
        };
        assert_eq!(node_beside(&l).as_ref(), Some(&node.bin));
        assert_eq!(node_beside(&node), None);
        let exe = d.path().join("Downloads/nerve-node-desktop-x86_64-linux");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, "nerve-node-desktop 1.0.0\n").unwrap();
        let mut out = Vec::new();
        install(&l, &sys, &exe, "alice", &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("nerve-node is a link to"), "{out}");
        assert_eq!(std::fs::read_link(&node.bin).unwrap(), l.bin);
        // The command runs the app's program.
        assert_eq!(
            std::fs::read_to_string(&node.bin).unwrap(),
            "nerve-node-desktop 1.0.0\n"
        );
        assert!(!node.bin.with_file_name(".nerve-node.link").exists());

        // Again, and after an update, the link stays as it is.
        let mut out = Vec::new();
        install(&l, &sys, &exe, "alice", &mut out).unwrap();
        assert!(!String::from_utf8(out).unwrap().contains("is a link"));
        let new = d.path().join("new");
        std::fs::write(&new, "nerve-node-desktop 1.1.0\n").unwrap();
        update(&l, &sys, Some(&new), "alice", &mut Vec::new())
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&node.bin).unwrap(),
            "nerve-node-desktop 1.1.0\n"
        );

        let mut out = Vec::new();
        uninstall(&l, &sys, false, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("removed the link"), "{out}");
        assert!(std::fs::symlink_metadata(&node.bin).is_err());
        assert!(!l.bin.exists());

        // No node alone was there: no link is made; a link of another's
        // stays.
        install(&l, &sys, &exe, "alice", &mut Vec::new()).unwrap();
        assert!(std::fs::symlink_metadata(&node.bin).is_err());
        let other = d.path().join("other");
        std::os::unix::fs::symlink(&other, &node.bin).unwrap();
        install(&l, &sys, &exe, "alice", &mut Vec::new()).unwrap();
        uninstall(&l, &sys, false, &mut Vec::new()).unwrap();
        assert_eq!(std::fs::read_link(&node.bin).unwrap(), other);
    }

    /// `nerve-node uninstall` of the node alone, after the app took the
    /// node over: the app's program, here a script that says what it was
    /// asked, does the uninstall, and what it says comes through.
    #[cfg(unix)]
    #[test]
    fn the_node_alone_hands_the_uninstall_of_a_takeover_to_the_app() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let node = layout(d.path());
        let app = Layout {
            bin: node.bin.with_file_name("nerve-node-desktop"),
            edition: &DESKTOP,
            ..layout(d.path())
        };
        assert_eq!(app_beside(&node), None);
        std::fs::create_dir_all(app.bin.parent().unwrap()).unwrap();
        let script = |code: u8| {
            std::fs::write(
                &app.bin,
                format!(
                    "#!/bin/sh\necho \"removed the program, asked: $*\"\necho \"a log line\" >&2\nexit {code}\n"
                ),
            )
            .unwrap();
            std::fs::set_permissions(&app.bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        script(0);
        assert_eq!(app_beside(&node).as_ref(), Some(&app.bin));
        // The app itself does its uninstall.
        assert_eq!(app_beside(&app), None);
        let mut out = Vec::new();
        hand_over_uninstall(&app_beside(&node).unwrap(), true, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("the desktop app is installed"), "{out}");
        assert!(
            out.contains("removed the program, asked: uninstall --purge"),
            "{out}"
        );
        let mut out = Vec::new();
        hand_over_uninstall(&app.bin, false, &mut out).unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("asked: uninstall\n")
        );
        script(3);
        let e = hand_over_uninstall(&app.bin, false, &mut Vec::new()).unwrap_err();
        assert!(e.contains("did not finish"), "{e}");
    }

    #[test]
    fn the_desktop_app_has_a_place_and_a_release_file_of_its_own() {
        let l = Layout::of(&DESKTOP);
        assert_eq!(l.bin, Path::new("/usr/local/bin/nerve-node-desktop"));
        assert_eq!(l.paths, Layout::system().paths);
        assert_eq!(Layout::system().bin, Path::new("/usr/local/bin/nerve-node"));
        if std::env::consts::ARCH == "x86_64" {
            assert_eq!(
                asset_name("nerve-node-desktop").unwrap(),
                "nerve-node-desktop-x86_64-linux"
            );
        }
        assert_eq!(
            Version::of_program(&l, "nerve-node-desktop 0.2.0\n"),
            Some(Version(0, 2, 0))
        );
        assert_eq!(Version::of_program(&l, "nerve-node 0.2.0"), None);
    }

    #[test]
    fn service_starts_stops_and_restarts_the_installed_unit() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = layout(d.path());
        assert_eq!(unit_status(&l, &sys).unwrap(), None);
        let e = control(&l, &sys, ServiceAction::Start, &mut Vec::new()).unwrap_err();
        assert!(e.contains("not installed as a service"), "{e}");
        let l = installed(d.path(), &sys, "1.0.0");
        let mut out = Vec::new();
        control(&l, &sys, ServiceAction::Stop, &mut out).unwrap();
        assert_eq!(
            sys.calls().last().unwrap(),
            &format!("systemctl stop {UNIT_NAME}")
        );
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("it starts again with the machine")
        );
        let state = unit_status(&l, &sys).unwrap().unwrap();
        assert_eq!(state.state, "stopped");
        assert_eq!(state.enabled, Some(true));
        let v = service_status(&l, Some(&state));
        assert_eq!(v["installed"], true);
        assert_eq!(v["state"], "stopped");
        assert_eq!(v["present"], true);
        assert_eq!(v["program"], l.bin.display().to_string());
        for (action, call) in [
            (ServiceAction::Start, "start"),
            (ServiceAction::Restart, "restart"),
        ] {
            let mut out = Vec::new();
            control(&l, &sys, action, &mut out).unwrap();
            assert_eq!(
                sys.calls().last().unwrap(),
                &format!("systemctl {call} {UNIT_NAME}")
            );
            assert!(String::from_utf8(out).unwrap().contains("the node answers"));
            assert_eq!(unit_status(&l, &sys).unwrap().unwrap().state, "running");
        }
        // An owner, not root, goes through the helper with pkexec; without
        // pkexec through systemctl, which the rule allows on a newer polkit.
        sys.root.set(false);
        let helper = l.service_helper();
        for (action, word) in [
            (ServiceAction::Stop, "stop"),
            (ServiceAction::Start, "start"),
            (ServiceAction::Restart, "restart"),
        ] {
            control(&l, &sys, action, &mut Vec::new()).unwrap();
            assert_eq!(
                sys.calls().last().unwrap(),
                &format!("pkexec {} {word}", helper.display())
            );
        }
        sys.pkexec_here.set(false);
        control(&l, &sys, ServiceAction::Restart, &mut Vec::new()).unwrap();
        assert_eq!(
            sys.calls().last().unwrap(),
            &format!("systemctl restart {UNIT_NAME}")
        );
        sys.root.set(true);
        // A node that does not come up is said.
        sys.starts.set(false);
        assert!(control(&l, &sys, ServiceAction::Restart, &mut Vec::new()).is_err());
        let none = service_status(&layout(&d.path().join("elsewhere")), None);
        assert_eq!(none["installed"], false);
        assert_eq!(none["state"], serde_json::Value::Null);
        assert_eq!(none["present"], false);
    }

    #[test]
    fn systemd_states_read_as_the_service_states() {
        let s = unit_state_of("ActiveState=active\nUnitFileState=enabled\n");
        assert_eq!((s.state.as_str(), s.enabled), ("running", Some(true)));
        let s = unit_state_of("ActiveState=failed\nUnitFileState=disabled\n");
        assert_eq!((s.state.as_str(), s.enabled), ("failed", Some(false)));
        let s = unit_state_of("ActiveState=activating\n");
        assert_eq!((s.state.as_str(), s.enabled), ("starting", None));
        assert_eq!(unit_state_of("ActiveState=inactive").state, "stopped");
    }
}
