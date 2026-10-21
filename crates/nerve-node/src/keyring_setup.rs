//! A system keyring for a node that keeps its keys there
//! (`machine.secret_storage = "keyring"`, docs/user/config.md).
//!
//! The node never falls back to files: where no keyring answers, it refuses.
//! On a Linux without a desktop there is usually none, so `setup` (and
//! `install`, run in a terminal) offers to install one, and does so only on
//! an explicit yes: GNOME Keyring through the distribution's package
//! manager, a session of the node's user that outlives logins and reboots
//! (`loginctl enable-linger`), in which D-Bus starts the keyring when the
//! node asks, and a login keyring that opens without a password. Where the
//! node's user has a desktop session, nothing is offered: such a keyring
//! would become the default of every program in that session.
//!
//! The kernel keyring (keyutils) needs no daemon, but its keys are gone
//! after a reboot, and with them the node's: so it is not offered. A keyring
//! that opens without anyone typing a password keeps its secrets unencrypted
//! on disk; the question says so.
//!
//! Whether a keyring answers is asked in a process of its own
//! ([`PROBE_ARG`]): the keyring crate keeps its first connection, or its
//! first failure, for the life of a process, and `install` runs as root but
//! must ask the keyring of the node's user.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use crate::service::Account;

/// The hidden first argument that makes `nerve-node` check the system
/// keyring of the user it runs as and exit: 0 when it answers.
pub const PROBE_ARG: &str = "__keyring-probe";

/// The entry the probe writes, reads and deletes.
const PROBE_ACCOUNT: &str = "probe";

/// `nerve-node __keyring-probe`: stores, reads and deletes an entry; the
/// exit code says whether that worked, stderr why not.
pub fn probe_main() -> i32 {
    let value = nerve_transport::keys::random_token(16);
    let r = (|| {
        crate::secrets::store::set(PROBE_ACCOUNT, &value)?;
        let back = crate::secrets::store::get(PROBE_ACCOUNT)?;
        crate::secrets::store::delete(PROBE_ACCOUNT)?;
        if back.as_deref() == Some(value.as_str()) {
            Ok(())
        } else {
            Err("an entry written to it does not read back".to_string())
        }
    })();
    match r {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

/// How a keyring would be installed here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    /// The package manager's commands, run as root in this order.
    pub commands: Vec<Vec<String>>,
}

impl Offer {
    /// The package commands for the package manager found in `bin` folders:
    /// apt (Debian, Ubuntu), dnf (Fedora, RHEL) or pacman (Arch). On Debian
    /// and Ubuntu the user's D-Bus session comes in a package of its own;
    /// the others have it already.
    pub fn for_system(has: impl Fn(&str) -> bool) -> Option<Offer> {
        let cmds: &[&[&str]] = if has("apt-get") {
            &[
                &["apt-get", "update"],
                &[
                    "apt-get",
                    "install",
                    "-y",
                    "gnome-keyring",
                    "dbus-user-session",
                ],
            ]
        } else if has("dnf") {
            &[&["dnf", "install", "-y", "gnome-keyring"]]
        } else if has("pacman") {
            &[&["pacman", "-S", "--needed", "--noconfirm", "gnome-keyring"]]
        } else {
            return None;
        };
        Some(Offer {
            commands: cmds
                .iter()
                .map(|c| c.iter().map(|s| s.to_string()).collect())
                .collect(),
        })
    }

    /// The commands as the question shows them.
    fn shown(&self, who: &str) -> String {
        self.commands
            .iter()
            .map(|c| c.join(" "))
            .chain([format!("loginctl enable-linger {who}")])
            .map(|c| format!("`{c}`"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// The system keyring as `setup` and `install` see it.
pub trait Keyring {
    /// `Ok` when the system keyring of `who` answers: an entry is stored,
    /// read back and deleted. Else why not.
    fn check(&self, who: &Account) -> Result<(), String>;
    /// How a keyring would be installed here; `None` where nerve-node cannot
    /// install one (not Linux, or no package manager it knows).
    fn offer(&self) -> Option<Offer>;
    /// Whether `who` has a graphical session: its desktop brings or chooses
    /// the keyring, and a password-less one of nerve-node's would become
    /// the default of every program there.
    fn desktop(&self, who: &Account) -> bool;
    /// Installs and starts a keyring for `who` as `offer` says.
    fn install(&self, offer: &Offer, who: &Account, out: &mut dyn Write) -> Result<(), String>;
}

/// Makes sure the system keyring of `who` answers: when it does not, says
/// why and, where nerve-node can install one, `who` has no desktop and
/// `input` is a terminal's, offers to. Anything but a yes leaves the
/// refusal. `Ok(true)` when a keyring was installed now.
pub fn ensure(
    keyring: &dyn Keyring,
    who: &Account,
    input: Option<&mut dyn BufRead>,
    out: &mut dyn Write,
) -> Result<bool, String> {
    let Err(why) = keyring.check(who) else {
        return Ok(false);
    };
    let name = &who.name;
    let refusal = format!(
        "no system keyring answers for {name} ({why}); with machine.secret_storage = \"keyring\" the node keeps its keys there and nowhere else"
    );
    let Some(offer) = keyring.offer() else {
        return Err(refusal);
    };
    if keyring.desktop(who) {
        return Err(format!(
            "{refusal}; {name} has a desktop session, so start the keyring of that desktop (GNOME Keyring, or KWallet with its Secret Service on)"
        ));
    }
    let Some(input) = input else {
        return Err(format!(
            "{refusal}; `nerve-node setup`, run in a terminal, offers to install one"
        ));
    };
    let store = who.home.join(".local/share/keyrings");
    let _ = writeln!(out, "No system keyring answers for {name}: {why}.");
    let _ = writeln!(
        out,
        "nerve-node can install GNOME Keyring: {}, so that {name} keeps a session after a reboot, and a login keyring for {name} that opens without a password.",
        offer.shown(name)
    );
    let _ = writeln!(
        out,
        "Without a desktop nobody types a password when the machine starts, so this keyring keeps the keys unencrypted in {}, readable by {name} as the key files are; the node keeps centers out of it as it does out of the key files, except a command you let a center run outside folder mode that asks the keyring itself (secret-tool and the like). It becomes the default keyring of {name}: any other program of {name} that keeps a secret in the system keyring keeps it there, unencrypted too.",
        store.display()
    );
    let yes = crate::cli::ask(input, out, "Install it now? [y/N] ")?;
    if !matches!(yes.as_str(), "y" | "Y" | "yes") {
        return Err(refusal);
    }
    keyring.install(&offer, who, out)?;
    keyring
        .check(who)
        .map_err(|e| format!("the keyring is installed, but it does not answer for {name}: {e}"))?;
    let _ = writeln!(out, "the system keyring answers for {name}");
    Ok(true)
}

/// The account this process runs as, from the system's account database.
pub fn me() -> Result<Account, String> {
    #[cfg(unix)]
    {
        let uid = nerve_transport::net::euid();
        let o = std::process::Command::new("getent")
            .args(["passwd", &uid.to_string()])
            .output()
            .map_err(|e| format!("getent: {e}"))?;
        let line = String::from_utf8_lossy(&o.stdout);
        crate::account::parse_passwd(&line)
            .filter(|_| o.status.success())
            .ok_or_else(|| format!("there is no account with the uid {uid}"))
    }
    #[cfg(not(unix))]
    {
        let name = std::env::var("USERNAME").unwrap_or_default();
        Ok(Account {
            name,
            uid: 0,
            gid: 0,
            comment: String::new(),
            home: crate::paths::home_dir(),
            groups: Vec::new(),
        })
    }
}

/// This machine's keyring, asked by `exe`, the program the node's user can
/// run: the installed one on the installed node.
pub struct HostKeyring {
    pub exe: PathBuf,
}

impl HostKeyring {
    /// Asked by this program.
    pub fn this_program() -> HostKeyring {
        HostKeyring {
            exe: std::env::current_exe().unwrap_or_else(|_| PathBuf::from("nerve-node")),
        }
    }
}

impl Keyring for HostKeyring {
    fn check(&self, who: &Account) -> Result<(), String> {
        let mut c = std::process::Command::new(&self.exe);
        c.arg(PROBE_ARG);
        #[cfg(unix)]
        if nerve_transport::net::euid() == 0 && who.uid != 0 {
            use std::os::unix::process::CommandExt;
            // install runs as root: the probe runs as the node's user, in
            // that user's session, never in root's.
            // std drops root's other groups along with the ids.
            c.uid(who.uid)
                .gid(who.gid)
                .env("HOME", &who.home)
                .env_remove("DBUS_SESSION_BUS_ADDRESS")
                .env_remove("XDG_RUNTIME_DIR");
        }
        #[cfg(not(unix))]
        let _ = who;
        let o = c.output().map_err(|e| format!("the keyring probe: {e}"))?;
        if o.status.success() {
            return Ok(());
        }
        let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
        Err(if err.is_empty() {
            o.status.to_string()
        } else {
            err
        })
    }

    fn offer(&self) -> Option<Offer> {
        if !cfg!(target_os = "linux") {
            return None;
        }
        Offer::for_system(|p| {
            ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
                .iter()
                .any(|d| Path::new(d).join(p).is_file())
        })
    }

    fn desktop(&self, who: &Account) -> bool {
        // Setup run in that user's own session: its environment says so.
        // Under sudo it is someone else's.
        #[cfg(unix)]
        if who.uid == nerve_transport::net::euid()
            && std::env::var_os("SUDO_UID").is_none()
            && graphical_env(|k| std::env::var_os(k))
        {
            return true;
        }
        // A graphical session of that user elsewhere: logind's display
        // session, when it is one.
        let loginctl = |args: &[&str]| {
            std::process::Command::new("loginctl")
                .args(args)
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default()
        };
        let uid = who.uid.to_string();
        let display = loginctl(&["show-user", &uid, "--property=Display", "--value"]);
        !display.is_empty()
            && graphical_type(&loginctl(&[
                "show-session",
                &display,
                "--property=Type",
                "--value",
            ]))
    }

    fn install(&self, offer: &Offer, who: &Account, out: &mut dyn Write) -> Result<(), String> {
        for cmd in &offer.commands {
            let _ = writeln!(out, "running {}", cmd.join(" "));
            as_root(cmd)?;
        }
        let linger = ["loginctl", "enable-linger", who.name.as_str()].map(String::from);
        let _ = writeln!(out, "running {}", linger.join(" "));
        as_root(&linger)?;
        wait_for_session(who)?;
        if make_login_keyring(who)? {
            let _ = writeln!(
                out,
                "made a login keyring for {} without a password",
                who.name
            );
            // A keyring daemon that started before the file was there does
            // not see it; D-Bus starts it again at the next question.
            let _ = std::process::Command::new("pkill")
                .args(["-U", &who.uid.to_string(), "-x", "gnome-keyring-d"])
                .status();
        }
        Ok(())
    }
}

/// Whether an environment is a graphical session's.
pub fn graphical_env(var: impl Fn(&str) -> Option<std::ffi::OsString>) -> bool {
    let set = |k: &str| var(k).is_some_and(|v| !v.is_empty());
    set("DISPLAY")
        || set("WAYLAND_DISPLAY")
        || set("XDG_CURRENT_DESKTOP")
        || var("XDG_SESSION_TYPE").is_some_and(|t| graphical_type(&t.to_string_lossy()))
}

/// Whether a logind session type is a graphical one.
fn graphical_type(t: &str) -> bool {
    matches!(t, "x11" | "wayland" | "mir")
}

/// Runs a system command as root: directly when this process is root; on
/// the installed node, where setup keeps root as its saved id (run with
/// sudo) or runs for the owner with the service's CAP_SETUID and CAP_SETGID
/// (crate::owner), as root by those; elsewhere through `sudo`, which asks
/// for the password.
fn as_root(cmd: &[String]) -> Result<(), String> {
    let (program, args) = cmd.split_first().ok_or("an empty command")?;
    let mut c;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        let (mut r, mut e, mut s) = (0, 0, 0);
        // SAFETY: getresuid writes the three ids it is given.
        unsafe { libc::getresuid(&mut r, &mut e, &mut s) };
        if e == 0 {
            c = std::process::Command::new(program);
        } else if s == 0 || crate::account::can_switch() {
            c = std::process::Command::new(program);
            // SAFETY: plain system calls between fork and exec.
            unsafe {
                c.pre_exec(|| {
                    // The user first: as root again the process has its
                    // capabilities in effect for the group and the groups.
                    if libc::setresuid(0, 0, 0) != 0
                        || libc::setresgid(0, 0, 0) != 0
                        || libc::setgroups(0, std::ptr::null()) != 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        } else {
            c = std::process::Command::new("sudo");
            c.arg("--").arg(program);
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        c = std::process::Command::new(program);
    }
    c.args(args);
    let status = c.status().map_err(|e| format!("{}: {e}", cmd.join(" ")))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{} failed: {status}", cmd.join(" ")))
    }
}

/// Waits until the session of `who`, which linger started, has its D-Bus.
fn wait_for_session(who: &Account) -> Result<(), String> {
    let bus = PathBuf::from(format!("/run/user/{}/bus", who.uid));
    for _ in 0..80 {
        if bus.exists() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    Err(format!(
        "the session of {} has no D-Bus at {} (on Debian and Ubuntu it comes with dbus-user-session)",
        who.name,
        bus.display()
    ))
}

/// The login keyring GNOME Keyring opens without a password: its plain text
/// format, with no item yet. A keyring that is there already is left as it
/// is. `Ok(true)` when it was made.
pub fn make_login_keyring(who: &Account) -> Result<bool, String> {
    let dir = who.home.join(".local/share/keyrings");
    let file = dir.join("login.keyring");
    if file.exists() {
        return Ok(false);
    }
    // Written as `who`, so a link in that home leads nowhere `who` could
    // not write anyway.
    #[cfg(target_os = "linux")]
    let _as = (nerve_transport::net::euid() == 0 && who.uid != 0)
        .then(|| crate::account::FsAs::new(who))
        .transpose()
        .map_err(|e| format!("cannot write as {}: {e}", who.name))?;
    let at = |p: &Path, e: std::io::Error| format!("{}: {e}", p.display());
    nerve_transport::files::create_private_dir(&dir).map_err(|e| at(&dir, e))?;
    nerve_transport::files::write_private(&file, LOGIN_KEYRING.as_bytes())
        .map_err(|e| at(&file, e))?;
    let default = dir.join("default");
    if !default.exists() {
        nerve_transport::files::write_private(&default, b"login").map_err(|e| at(&default, e))?;
    }
    Ok(true)
}

/// An empty keyring named `login` in GNOME Keyring's plain format: no
/// password, never locked.
const LOGIN_KEYRING: &str = "[keyring]
display-name=login
ctime=0
mtime=0
lock-on-idle=false
lock-after=false
";

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    /// A keyring that answers once it is installed, and records what was
    /// done.
    pub struct FakeKeyring {
        pub answers: Cell<bool>,
        pub offer: Option<Offer>,
        pub desktop: bool,
        pub installed: RefCell<Vec<String>>,
    }

    impl FakeKeyring {
        pub fn new(answers: bool) -> FakeKeyring {
            FakeKeyring {
                answers: Cell::new(answers),
                offer: Offer::for_system(|p| p == "apt-get"),
                desktop: false,
                installed: RefCell::new(Vec::new()),
            }
        }
    }

    impl Keyring for FakeKeyring {
        fn check(&self, _who: &Account) -> Result<(), String> {
            if self.answers.get() {
                Ok(())
            } else {
                Err("no Secret Service".into())
            }
        }

        fn offer(&self) -> Option<Offer> {
            self.offer.clone()
        }

        fn desktop(&self, _who: &Account) -> bool {
            self.desktop
        }

        fn install(
            &self,
            offer: &Offer,
            who: &Account,
            _out: &mut dyn Write,
        ) -> Result<(), String> {
            self.installed.borrow_mut().push(format!(
                "{} for {}",
                offer.shown(&who.name),
                who.name
            ));
            self.answers.set(true);
            // The test keyring answers as the real one would now.
            crate::secrets::store::set_unreachable(false);
            Ok(())
        }
    }

    pub fn nerve(home: &Path) -> Account {
        Account {
            name: "nerve".into(),
            uid: 990,
            gid: 990,
            comment: String::new(),
            home: home.to_path_buf(),
            groups: vec![990],
        }
    }

    fn run(k: &FakeKeyring, typed: Option<&str>) -> (Result<bool, String>, String) {
        let mut out = Vec::new();
        let mut input = typed.map(|t| std::io::Cursor::new(t.as_bytes().to_vec()));
        let r = ensure(
            k,
            &nerve(Path::new("/var/lib/nerve")),
            input.as_mut().map(|i| i as &mut dyn BufRead),
            &mut out,
        );
        (r, String::from_utf8(out).unwrap())
    }

    #[test]
    fn a_keyring_that_answers_is_not_asked_about() {
        let k = FakeKeyring::new(true);
        let (r, out) = run(&k, Some(""));
        assert_eq!(r, Ok(false));
        assert!(out.is_empty(), "{out}");
    }

    #[test]
    fn the_offer_names_each_package_manager_and_its_packages() {
        let apt = Offer::for_system(|p| p == "apt-get").unwrap();
        assert_eq!(
            apt.shown("nerve"),
            "`apt-get update`, `apt-get install -y gnome-keyring dbus-user-session`, `loginctl enable-linger nerve`"
        );
        let dnf = Offer::for_system(|p| p == "dnf").unwrap();
        assert_eq!(dnf.commands, [["dnf", "install", "-y", "gnome-keyring"]]);
        let pacman = Offer::for_system(|p| p == "pacman").unwrap();
        assert_eq!(
            pacman.commands,
            [["pacman", "-S", "--needed", "--noconfirm", "gnome-keyring"]]
        );
        assert_eq!(Offer::for_system(|_| false), None);
    }

    #[test]
    fn no_is_the_default_and_keeps_the_refusal() {
        for typed in ["\n", "n\n", "no\n"] {
            let k = FakeKeyring::new(false);
            let (r, out) = run(&k, Some(typed));
            let err = r.unwrap_err();
            assert!(err.contains("no system keyring answers for nerve"), "{err}");
            assert!(err.contains("nowhere else"), "{err}");
            assert!(k.installed.borrow().is_empty());
            // The question says what it would do, and what that keyring is.
            assert!(
                out.contains("apt-get install -y gnome-keyring dbus-user-session"),
                "{out}"
            );
            assert!(out.contains("loginctl enable-linger nerve"), "{out}");
            let store = Path::new("/var/lib/nerve").join(".local/share/keyrings");
            assert!(
                out.contains(&format!("unencrypted in {}", store.display())),
                "{out}"
            );
            assert!(out.contains("[y/N]"), "{out}");
        }
    }

    #[test]
    fn yes_installs_the_keyring_and_checks_it_answers() {
        let k = FakeKeyring::new(false);
        let (r, out) = run(&k, Some("y\n"));
        assert_eq!(r, Ok(true), "{out}");
        assert_eq!(
            *k.installed.borrow(),
            [
                "`apt-get update`, `apt-get install -y gnome-keyring dbus-user-session`, `loginctl enable-linger nerve` for nerve"
            ]
        );
        assert!(
            out.contains("the system keyring answers for nerve"),
            "{out}"
        );
    }

    /// On a desktop nothing is offered: the keyring would be the default of
    /// every program there. The question says that it becomes the default.
    #[test]
    fn a_user_with_a_desktop_is_offered_no_keyring() {
        let mut k = FakeKeyring::new(false);
        k.desktop = true;
        let (r, out) = run(&k, Some("y\n"));
        let e = r.unwrap_err();
        assert!(e.contains("no system keyring answers for nerve"), "{e}");
        assert!(e.contains("has a desktop session"), "{e}");
        assert!(out.is_empty(), "{out}");
        assert!(k.installed.borrow().is_empty());
        let k = FakeKeyring::new(false);
        let (_, out) = run(&k, Some("n\n"));
        assert!(out.contains("default keyring of nerve"), "{out}");
    }

    #[test]
    fn a_graphical_session_is_told_by_its_environment() {
        use std::ffi::OsString;
        let env = |vars: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                vars.iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| OsString::from(v))
            }
        };
        assert!(graphical_env(env(&[("WAYLAND_DISPLAY", "wayland-1")])));
        assert!(graphical_env(env(&[("DISPLAY", ":0")])));
        assert!(graphical_env(env(&[("XDG_CURRENT_DESKTOP", "sway")])));
        assert!(graphical_env(env(&[("XDG_SESSION_TYPE", "x11")])));
        assert!(!graphical_env(env(&[("XDG_SESSION_TYPE", "tty")])));
        assert!(!graphical_env(env(&[("DISPLAY", ""), ("HOME", "/root")])));
    }

    #[test]
    fn without_a_terminal_or_a_package_manager_nothing_is_asked() {
        let k = FakeKeyring::new(false);
        let (r, out) = run(&k, None);
        assert!(r.unwrap_err().contains("run in a terminal"));
        assert!(out.is_empty(), "{out}");
        let mut k = FakeKeyring::new(false);
        k.offer = None;
        let (r, out) = run(&k, Some("y\n"));
        assert!(r.is_err());
        assert!(out.is_empty(), "{out}");
        assert!(k.installed.borrow().is_empty());
    }

    #[test]
    fn the_login_keyring_is_made_once_and_never_replaced() {
        let d = tempfile::tempdir().unwrap();
        let who = Account {
            uid: nerve_transport::net::euid(),
            ..nerve(d.path())
        };
        assert_eq!(make_login_keyring(&who), Ok(true));
        let file = d.path().join(".local/share/keyrings/login.keyring");
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(
            text.starts_with("[keyring]\ndisplay-name=login\n"),
            "{text}"
        );
        assert!(text.contains("lock-on-idle=false"));
        assert_eq!(
            std::fs::read_to_string(d.path().join(".local/share/keyrings/default")).unwrap(),
            "login"
        );
        std::fs::write(&file, "someone's own keyring").unwrap();
        assert_eq!(make_login_keyring(&who), Ok(false));
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "someone's own keyring"
        );
    }
}
