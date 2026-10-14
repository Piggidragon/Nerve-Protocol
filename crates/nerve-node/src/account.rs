//! The account a center's commands run as on a node installed as a service
//! (docs/user/service.md). The service runs as `nerve`, which owns the
//! node's config, keys and state; every command, in every mode, and the
//! sudo switch run as the account `machine.user` names instead, so that
//! they cannot read them. Folder mode differs from user mode only by its
//! confinement. To switch to that account the service keeps CAP_SETUID and
//! CAP_SETGID, the one privilege it has, and every command it starts drops
//! both before it runs.

use std::path::{Path, PathBuf};

use crate::service::Account;

/// The comment `setup` gives an account it makes for the commands.
pub const MADE_MARK: &str = "Nerve user mode";

/// What a command of the installed node gets while no account is chosen.
#[cfg(not(windows))]
pub const NONE_CHOSEN: &str = "this node runs commands as an account of their own, and none is chosen: `sudo nerve-node setup` chooses one (machine.user)";
/// What a command of the installed node gets while no account is chosen:
/// on Windows `install` takes it, with its password.
#[cfg(windows)]
pub const NONE_CHOSEN: &str = "this node runs commands as an account of their own, and none is chosen: `nerve-node install`, run again as administrator by that account, sets it (machine.user)";

/// The warning for root as the account of the commands.
pub fn root_warning() -> String {
    "Warning: commands from a center then run as root, with every right on this machine, the node's keys included; in folder mode only Landlock still holds them. You are responsible for what they do.".into()
}

/// Groups whose members get root without a password and without a setuid
/// program, so `no_new_privs` does not hold them: a container or a VM with
/// the host's `/` in it, or the raw disks.
pub const ROOT_GROUPS: &[&str] = &["docker", "lxd", "incus-admin", "libvirt", "disk"];

/// The warning for an account in one of [`ROOT_GROUPS`].
pub fn group_warning(name: &str, groups: &[String]) -> String {
    format!(
        "Warning: {name} is in the group {}, which gets root without a password; a command from a center can then get root and read the node's keys. Choose an account outside it, or you are responsible for what commands do.",
        groups.join(", ")
    )
}

/// The warning for an account that gets root through its own sudo without
/// a password (`NOPASSWD`).
pub fn sudo_warning(name: &str) -> String {
    format!(
        "Warning: {name} may use sudo without a password, which gets root; a command from a center can then get root and read the node's keys. Choose an account that may not, or you are responsible for what commands do."
    )
}

/// The warning for the account that ran `sudo`: the account its owner logs
/// in as, whatever its sudo asks for.
pub fn invoker_warning(name: &str) -> String {
    format!(
        "Warning: {name} is the account that ran sudo, the one its owner logs in as; the commands of a center run as it, so they can use its own programs (a tmux or screen server, its systemd user session) to reach what its owner does with sudo, and every command is then root. You are responsible for what commands do."
    )
}

/// What `install` and `setup` suggest to anyone whose account is no
/// boundary and who runs them through `sudo`.
pub const CREATE_USER_HINT: &str = "An account only the node uses is the boundary: `sudo nerve-node setup --create-user nerve-work` makes one and runs commands as it.";

/// The same for whoever runs `install` or `setup` as root, with no `sudo`
/// (it may not even be installed).
pub const CREATE_USER_HINT_ROOT: &str = "An account only the node uses is the boundary: `nerve-node setup --create-user nerve-work` makes one and runs commands as it.";

/// Whether the rules `sudo -l -U <name>` lists may let the account use
/// sudo without a password, so that a probe is worth making: a rule that
/// grants every command (`ALL`) with `NOPASSWD`, `!authenticate` (not one
/// for a single command), or `exempt_group=` naming a group of the account
/// (`names` from `id -Gn`, `gids` from `id -G`). Such a list costs sudo no
/// failed login. It is a gate only: a later rule can still ask for the
/// password, and the probe decides. An account with `NOPASSWD` for single
/// commands, such as `apt`, is not probed.
pub fn lists_no_password(listing: &str, names: &[String], gids: &[u32]) -> bool {
    listing.lines().any(|line| {
        let line = line.trim();
        if let Some((_, cmds)) = line.split_once("NOPASSWD:") {
            return cmds.split(',').any(|c| {
                // Tags such as `SETENV:` come before the command.
                let c = c.trim();
                c.rsplit(' ').next() == Some("ALL")
            });
        }
        let Some(settings) = bound_settings(line) else {
            return false;
        };
        settings.split(',').any(|entry| {
            let entry = entry.trim();
            match entry.split_once('=') {
                Some(("exempt_group", g)) => {
                    let g = g.trim_matches('"').trim_start_matches('%');
                    // A gid is printed as `\#27`.
                    match g.trim_start_matches('\\').strip_prefix('#') {
                        Some(n) => n.parse().is_ok_and(|n| gids.contains(&n)),
                        None => names.iter().any(|x| x == g),
                    }
                }
                _ => entry == "!authenticate",
            }
        })
    })
}

/// The settings of a line of the listing that holds for this probe, which
/// runs `true` as root, or `None`. A default bound to commands
/// (`Defaults!/usr/bin/apt …`) or to a user to run as (`Defaults>postgres
/// …`) holds only when its binding names all commands or root. sudo
/// prints the members of a binding with a comma and a space
/// (`Defaults>nobody, root !authenticate`), and ends it at the first word
/// that does not follow a comma.
fn bound_settings(line: &str) -> Option<&str> {
    let Some(bound) = line.strip_prefix("Defaults") else {
        return Some(line);
    };
    let Some(kind @ ('!' | '>')) = bound.chars().next() else {
        return Some(line);
    };
    let mut rest = &bound[1..];
    let mut members = Vec::new();
    loop {
        let rest_trimmed = rest.trim_start();
        let end = rest_trimmed.find(' ').unwrap_or(rest_trimmed.len());
        let word = &rest_trimmed[..end];
        rest = &rest_trimmed[end..];
        members.extend(word.split(',').filter(|m| !m.is_empty()));
        if !word.ends_with(',') {
            break;
        }
    }
    let has = |n: &str| members.contains(&n);
    let all = has("ALL") || kind == '>' && (has("root") || has("#0"));
    // `!root` takes root out again.
    let out = kind == '>' && (has("!root") || has("!#0"));
    (all && !out).then_some(rest)
}

/// The names of the groups `account` is in, as `id -Gn` prints them.
pub fn group_names(account: &Account) -> Vec<String> {
    // `id` exits 1 when a group has no name and still prints the names it
    // found, with the number of that one: the names are all there.
    match plain("id").args(["-Gn", "--", &account.name]).output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout)
            .split_whitespace()
            .map(String::from)
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// The suggestion for whoever runs `install` or `setup`: root runs it
/// without `sudo`, anyone else through it.
fn hint(invoker: &str) -> &'static str {
    if invoker == "root" {
        CREATE_USER_HINT_ROOT
    } else {
        CREATE_USER_HINT
    }
}

/// The warnings for `account` as the account of the commands, none when
/// it is a boundary. Root has its own. Each comes with the suggestion,
/// as `invoker` runs it. Otherwise: it ran `sudo`
/// (`invoker`), it is in a group of [`ROOT_GROUPS`] (`groups`), or
/// `sudo_without_password` says its sudo needs no password; the reasons
/// share the suggestion at the end.
pub fn root_warnings(
    account: &Account,
    invoker: &str,
    groups: &[String],
    sudo_without_password: impl FnOnce() -> bool,
) -> Vec<String> {
    if account.uid == 0 {
        return vec![root_warning(), hint(invoker).into()];
    }
    let mut w = Vec::new();
    if account.name == invoker {
        w.push(invoker_warning(&account.name));
    }
    if !groups.is_empty() {
        w.push(group_warning(&account.name, groups));
    }
    if sudo_without_password() {
        w.push(sudo_warning(&account.name));
    }
    if !w.is_empty() {
        w.push(hint(invoker).into());
    }
    w
}

/// The groups of [`ROOT_GROUPS`] that `account` is in, by name.
pub fn root_groups(account: &Account) -> Vec<String> {
    // getent prints the groups it finds, and fails only for the others.
    match plain("getent").arg("group").args(ROOT_GROUPS).output() {
        Ok(o) => root_groups_in(&String::from_utf8_lossy(&o.stdout), &account.groups),
        Err(_) => Vec::new(),
    }
}

/// The groups in `getent group` lines whose id is one of `groups`.
pub fn root_groups_in(lines: &str, groups: &[u32]) -> Vec<String> {
    lines
        .lines()
        .filter_map(|l| {
            let mut f = l.split(':');
            let name = f.next()?;
            let gid: u32 = f.nth(1)?.parse().ok()?;
            (ROOT_GROUPS.contains(&name) && groups.contains(&gid)).then(|| name.to_string())
        })
        .collect()
}

/// The home `setup` gives an account it makes.
pub fn made_home(name: &str) -> PathBuf {
    Path::new("/home").join(name)
}

/// Whether `setup` may make an account of this name: what `useradd` takes
/// on every distribution.
pub fn makeable_name(name: &str) -> bool {
    let mut b = name.bytes();
    matches!(b.next(), Some(c) if c.is_ascii_lowercase() || c == b'_')
        && name.len() <= 32
        && b.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
}

/// Looks `name` up in the system's account database. `getent` and `id` ask
/// it through NSS, which the static program cannot do itself.
pub fn lookup(name: &str) -> Result<Option<Account>, String> {
    #[cfg(windows)]
    return crate::win_user::lookup(name);
    #[cfg(not(windows))]
    lookup_nss(name)
}

#[cfg(not(windows))]
fn lookup_nss(name: &str) -> Result<Option<Account>, String> {
    if !nerve_policy::config::valid_account_name(name) {
        return Err(format!("{name:?} is not an account name"));
    }
    let o = plain("getent")
        .args(["passwd", name])
        .output()
        .map_err(|e| format!("getent: {e}"))?;
    // 2: no such key.
    if o.status.code() == Some(2) {
        return Ok(None);
    }
    if !o.status.success() {
        return Err(format!("getent passwd {name}: {}", stderr_or_status(&o)));
    }
    let line = String::from_utf8_lossy(&o.stdout);
    let mut a =
        parse_passwd(&line).ok_or_else(|| format!("getent passwd {name}: cannot read {line:?}"))?;
    // The groups the account is in besides its own; without them a
    // command would lack what the account may do through a group.
    if let Ok(o) = plain("id").args(["-G", "--", name]).output()
        && o.status.success()
    {
        let groups: Vec<u32> = String::from_utf8_lossy(&o.stdout)
            .split_whitespace()
            .filter_map(|g| g.parse().ok())
            .collect();
        if !groups.is_empty() {
            a.groups = groups;
        }
    }
    Ok(Some(a))
}

/// One line of `getent passwd`.
pub fn parse_passwd(line: &str) -> Option<Account> {
    let f: Vec<&str> = line.trim_end_matches(['\n', '\r']).split(':').collect();
    let (uid, gid) = (f.get(2)?.parse().ok()?, f.get(3)?.parse().ok()?);
    Some(Account {
        name: f.first()?.to_string(),
        uid,
        gid,
        comment: f.get(4).unwrap_or(&"").to_string(),
        home: f.get(5).unwrap_or(&"/").into(),
        groups: vec![gid],
    })
}

#[cfg(not(windows))]
fn stderr_or_status(o: &std::process::Output) -> String {
    let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
    if err.is_empty() {
        o.status.to_string()
    } else {
        err
    }
}

/// A system tool started without the capabilities of the service.
fn plain(program: &str) -> std::process::Command {
    #[allow(unused_mut)]
    let mut c = std::process::Command::new(program);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: only plain system calls run between fork and exec.
        unsafe {
            c.pre_exec(|| {
                if nerve_transport::net::euid() != 0 {
                    drop_caps()?;
                }
                Ok(())
            });
        }
    }
    c
}

/// The account a command (and the sudo switch) runs as, from
/// `machine.user` (`user`): `None` runs it as the node's own user, as a
/// node that a person runs does. The installed service (`service`: its
/// folders or its user, however it was started), and any other node that
/// can switch accounts and is not root, runs no command until an account is
/// chosen, and none as itself, since it owns the keys. Root is allowed: the
/// owner chose it and was warned.
pub fn for_commands(
    user: Option<&str>,
    own_uid: u32,
    service: bool,
    can_switch: bool,
    lookup: impl Fn(&str) -> Result<Option<Account>, String>,
) -> Result<Option<Account>, String> {
    let Some(name) = user else {
        if (service || can_switch) && own_uid != 0 {
            return Err(NONE_CHOSEN.into());
        }
        return Ok(None);
    };
    let a = lookup(name)?.ok_or_else(|| {
        format!(
            "the account {name} that commands run as (machine.user) does not exist on this machine"
        )
    })?;
    if a.uid == own_uid {
        if own_uid == 0 {
            return Ok(None);
        }
        return Err(format!(
            "machine.user {name} is the node's own user, which can read the node's keys; no command runs as it"
        ));
    }
    if !can_switch && service {
        // Started by hand, or by a systemd without AmbientCapabilities=:
        // unsetting machine.user would run the commands as the keys' owner.
        return Err(if cfg!(windows) {
            format!(
                "machine.user is {name}, but this installed node runs without SeAssignPrimaryTokenPrivilege and cannot start a command as it; start it as the service: `Start-Service nerve-node`"
            )
        } else {
            format!(
                "machine.user is {name}, but this installed node runs as uid {own_uid} without CAP_SETUID and CAP_SETGID and cannot switch to it; start it as the service: `sudo systemctl start nerve-node`"
            )
        });
    }
    if !can_switch {
        return Err(format!(
            "machine.user is {name}, but the node runs as uid {own_uid} and cannot switch to it; unset machine.user or install the node as a service"
        ));
    }
    Ok(Some(a))
}

/// The number of the account this process runs as: its uid, on Windows the
/// last part of its SID (SYSTEM is 0, as root is).
pub fn own_uid() -> u32 {
    #[cfg(windows)]
    return crate::win_user::own_uid();
    #[cfg(not(windows))]
    nerve_transport::net::euid()
}

/// Whether this process may switch to another account: root, or a process
/// with CAP_SETUID and CAP_SETGID in effect, as the installed service. On
/// Windows: SYSTEM, or a process that holds the privileges to start a
/// process with another account's token, as the installed service.
pub fn can_switch() -> bool {
    #[cfg(windows)]
    return crate::win_user::can_switch();
    #[cfg(not(windows))]
    can_switch_unix()
}

#[cfg(not(windows))]
fn can_switch_unix() -> bool {
    if nerve_transport::net::euid() == 0 {
        return true;
    }
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        status
            .lines()
            .find_map(|l| l.strip_prefix("CapEff:"))
            .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
            .is_some_and(|caps| caps & SETID_CAPS == SETID_CAPS)
    }
    #[cfg(not(target_os = "linux"))]
    false
}

/// CAP_SETGID (6) and CAP_SETUID (7).
#[cfg(target_os = "linux")]
const SETID_CAPS: u64 = (1 << 6) | (1 << 7);

/// Whether `account` reaches `path` by its permission bits: it may search
/// every folder on the way, and read `path` (or search it, for a folder).
/// Root reaches everything. A path that is not there is not reached; one
/// whose bits cannot be read counts as reached. ACLs are not looked at:
/// the node's folders have none, and a command meets them anyway
/// ([`Switch::apply`] asks the kernel).
pub fn reaches(path: &Path, account: &Account) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if account.uid == 0 {
            return true;
        }
        let may = |m: &std::fs::Metadata, bits: u32| {
            let mode = m.mode();
            let class = if m.uid() == account.uid {
                mode >> 6
            } else if m.gid() == account.gid || account.groups.contains(&m.gid()) {
                mode >> 3
            } else {
                mode
            };
            class & bits != 0
        };
        let end = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return false,
            Err(_) => return true,
        };
        for dir in path
            .ancestors()
            .skip(1)
            .filter(|d| !d.as_os_str().is_empty())
        {
            match std::fs::metadata(dir) {
                Ok(m) if !may(&m, 0o1) => return false,
                Ok(_) => {}
                Err(_) => return true,
            }
        }
        may(&end, if end.is_dir() { 0o5 } else { 0o4 })
    }
    #[cfg(not(unix))]
    {
        let _ = (path, account);
        true
    }
}

/// The error a command gets when its account can reach the node's own
/// folders ([`Switch::apply`]).
#[cfg(target_os = "linux")]
pub const IN_REACH: i32 = libc::ENOTRECOVERABLE;

/// What a command needs to start as another account, made before the fork:
/// between fork and exec nothing may allocate.
#[cfg(target_os = "linux")]
pub struct Switch {
    uid: u32,
    gid: u32,
    groups: Vec<libc::gid_t>,
    cwd: Option<std::ffi::CString>,
    own: Vec<std::ffi::CString>,
}

#[cfg(target_os = "linux")]
impl Switch {
    /// `cwd` is entered as the account, after the switch, since the node's
    /// user may not see into it. `own` are the node's folders.
    pub fn new(account: &Account, cwd: Option<&Path>, own: &[PathBuf]) -> std::io::Result<Switch> {
        use std::os::unix::ffi::OsStrExt;
        let c = |p: &Path| {
            std::ffi::CString::new(p.as_os_str().as_bytes()).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "a path holds a NUL byte")
            })
        };
        let mut groups = account.groups.clone();
        if groups.is_empty() {
            groups.push(account.gid);
        }
        Ok(Switch {
            uid: account.uid,
            gid: account.gid,
            groups,
            cwd: cwd.map(c).transpose()?,
            own: own.iter().map(|p| c(p)).collect::<Result<_, _>>()?,
        })
    }

    /// In the forked child, before exec: the account's groups and ids, no
    /// capability left, a check that the node's own folders are out of its
    /// reach (root aside, which the owner chose knowing), then its working
    /// folder. Plain system calls only. A process that has the account's
    /// ids already keeps its groups.
    pub fn apply(&self) -> std::io::Result<()> {
        let last = std::io::Error::last_os_error;
        // SAFETY: plain system calls on memory this struct owns.
        unsafe {
            let same = libc::getuid() == self.uid
                && libc::geteuid() == self.uid
                && libc::getgid() == self.gid
                && libc::getegid() == self.gid;
            if !same
                && (libc::setgroups(self.groups.len(), self.groups.as_ptr()) != 0
                    || libc::setresgid(self.gid, self.gid, self.gid) != 0
                    || libc::setresuid(self.uid, self.uid, self.uid) != 0)
            {
                return Err(last());
            }
        }
        if self.uid != 0 {
            drop_caps()?;
            out_of_reach(&self.own)?;
        }
        // SAFETY: a NUL-terminated path this struct owns.
        if let Some(cwd) = &self.cwd
            && unsafe { libc::chdir(cwd.as_ptr()) } != 0
        {
            return Err(last());
        }
        Ok(())
    }
}

/// Fails with [`IN_REACH`] when this process may list or enter one of
/// `own`. The kernel decides, ACLs included.
#[cfg(target_os = "linux")]
pub fn out_of_reach(own: &[std::ffi::CString]) -> std::io::Result<()> {
    for p in own {
        // SAFETY: NUL-terminated paths.
        let open = unsafe {
            libc::access(p.as_ptr(), libc::R_OK) == 0 || libc::access(p.as_ptr(), libc::X_OK) == 0
        };
        if open {
            return Err(std::io::Error::from_raw_os_error(IN_REACH));
        }
    }
    Ok(())
}

/// Drops every capability this process holds, the ambient ones too, so a
/// program it runs next starts with none. The service holds CAP_SETUID and
/// CAP_SETGID; no command may keep them.
#[cfg(target_os = "linux")]
pub fn drop_caps() -> std::io::Result<()> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: libc::c_int,
    }
    #[repr(C)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const V3: u32 = 0x2008_0522;
    // SAFETY: prctl and capset with structs laid out as the kernel's.
    unsafe {
        if libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        ) != 0
        {
            let e = std::io::Error::last_os_error();
            // A kernel before 4.3 has no ambient set, so nothing to clear.
            if e.raw_os_error() != Some(libc::EINVAL) {
                return Err(e);
            }
        }
        let h = Header {
            version: V3,
            pid: 0,
        };
        let none = [
            Data {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
            Data {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
        ];
        if libc::syscall(libc::SYS_capset, &h as *const Header, none.as_ptr()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// The node's own file access as `account`, on this thread only: the `fs`
/// actions of a center and the path checks of its calls see what the
/// account sees, and files they make belong to it. The file system ids and
/// the groups are the thread's own in Linux (the C library's calls change
/// every thread's, so plain system calls are used); the service's
/// CAP_SETUID and CAP_SETGID allow the change. Dropped, the thread is the
/// node's again. It is not `Send`, so it cannot be held across an `.await`
/// and leak to another task.
#[cfg(target_os = "linux")]
pub struct FsAs {
    uid: u32,
    gid: u32,
    groups: Vec<libc::gid_t>,
    _thread: std::marker::PhantomData<*const ()>,
}

#[cfg(target_os = "linux")]
impl FsAs {
    pub fn new(account: &Account) -> std::io::Result<FsAs> {
        let last = std::io::Error::last_os_error;
        // SAFETY: getgroups into a buffer of the size it asked for, and plain
        // system calls with integers or that buffer.
        unsafe {
            let n = libc::getgroups(0, std::ptr::null_mut());
            if n < 0 {
                return Err(last());
            }
            let mut groups = vec![0; n as usize];
            if libc::getgroups(n, groups.as_mut_ptr()) < 0 {
                return Err(last());
            }
            let me = FsAs {
                uid: libc::geteuid(),
                gid: libc::getegid(),
                groups,
                _thread: std::marker::PhantomData,
            };
            let mut want = account.groups.clone();
            if want.is_empty() {
                want.push(account.gid);
            }
            if libc::syscall(libc::SYS_setgroups, want.len(), want.as_ptr()) != 0 {
                return Err(last());
            }
            // setfsuid answers with the old id whether it worked or not; a
            // second call with an impossible id reads the one in force.
            libc::setfsgid(account.gid);
            libc::setfsuid(account.uid);
            if libc::setfsuid(u32::MAX) as u32 != account.uid
                || libc::setfsgid(u32::MAX) as u32 != account.gid
            {
                drop(me);
                return Err(std::io::Error::from_raw_os_error(libc::EPERM));
            }
            Ok(me)
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for FsAs {
    fn drop(&mut self) {
        // SAFETY: as in `new`, back to the ids and groups read there.
        unsafe {
            libc::setfsuid(self.uid);
            libc::setfsgid(self.gid);
            libc::syscall(libc::SYS_setgroups, self.groups.len(), self.groups.as_ptr());
        }
    }
}

/// Signals the process group `pgid` as `uid`: the service's own user may
/// not signal another account's processes, and it has no CAP_KILL. A child
/// process takes the account as its effective id only and sends the
/// signal, so the node itself keeps its ids, and the account's processes
/// cannot signal the child (its real and saved ids stay the node's). The
/// node waits for it a short while at most.
#[cfg(target_os = "linux")]
pub fn kill_as(uid: u32, pgid: u32, sig: libc::c_int) {
    // SAFETY: the child of a process with many threads makes plain system
    // calls only and leaves with _exit.
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            if libc::syscall(libc::SYS_setresuid, u32::MAX, uid, u32::MAX) == 0 {
                libc::kill(-(pgid as libc::pid_t), sig);
            }
            libc::_exit(0);
        }
        if pid > 0 {
            let until = std::time::Instant::now() + std::time::Duration::from_secs(2);
            let mut status = 0;
            while libc::waitpid(pid, &mut status, libc::WNOHANG) == 0
                && std::time::Instant::now() < until
            {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(name: &str, uid: u32) -> Account {
        Account {
            name: name.into(),
            uid,
            gid: uid,
            comment: String::new(),
            home: format!("/home/{name}").into(),
            groups: vec![uid],
        }
    }

    fn db(name: &str) -> Result<Option<Account>, String> {
        Ok(match name {
            "alice" => Some(account("alice", 1000)),
            "root" => Some(account("root", 0)),
            "nerve" => Some(account("nerve", 990)),
            _ => None,
        })
    }

    #[test]
    fn the_account_of_the_commands() {
        // Chosen: the service (uid 990, may switch) runs the command as it.
        let a = for_commands(Some("alice"), 990, false, true, db)
            .unwrap()
            .unwrap();
        assert_eq!((a.name.as_str(), a.uid), ("alice", 1000));
        // Root is allowed; the owner was warned when choosing it.
        assert_eq!(
            for_commands(Some("root"), 990, false, true, db)
                .unwrap()
                .unwrap()
                .uid,
            0
        );
        // None chosen: the service runs none, a person's node runs it as itself.
        assert_eq!(
            for_commands(None, 990, false, true, db).unwrap_err(),
            NONE_CHOSEN
        );
        assert_eq!(for_commands(None, 1000, false, false, db).unwrap(), None);
        assert_eq!(for_commands(None, 0, false, true, db).unwrap(), None);
        // Refused: an account that does not exist, the node's own user, and
        // any switch the node cannot make.
        let e = for_commands(Some("bob"), 990, false, true, db).unwrap_err();
        assert!(e.contains("bob") && e.contains("does not exist"), "{e}");
        let e = for_commands(Some("nerve"), 990, false, true, db).unwrap_err();
        assert!(e.contains("node's own user"), "{e}");
        let e = for_commands(Some("alice"), 1001, false, false, db).unwrap_err();
        assert!(e.contains("cannot switch"), "{e}");
        // A root node asked to run as root just does.
        assert_eq!(
            for_commands(Some("root"), 0, false, true, db).unwrap(),
            None
        );
    }

    /// The installed node started without its two capabilities (by hand, as
    /// `nerve`) runs no command, and never as itself.
    #[test]
    fn the_installed_node_without_its_capabilities_runs_nothing() {
        assert_eq!(
            for_commands(None, 990, true, false, db).unwrap_err(),
            NONE_CHOSEN
        );
        let e = for_commands(Some("alice"), 990, true, false, db).unwrap_err();
        let start = if cfg!(windows) {
            "Start-Service nerve-node"
        } else {
            "systemctl start"
        };
        assert!(e.contains(start), "{e}");
        assert!(!e.contains("unset machine.user"), "{e}");
        // As root it runs as root, which `machine.allow_root` allowed.
        assert_eq!(for_commands(None, 0, true, false, db).unwrap(), None);
    }

    #[test]
    fn groups_that_get_root_are_found_by_their_id() {
        let lines = "docker:x:998:alice\ndisk:x:6:\nlibvirt:x:120:\nusers:x:100:\n";
        assert_eq!(root_groups_in(lines, &[1000, 998, 6]), ["docker", "disk"]);
        assert!(root_groups_in(lines, &[1000, 100]).is_empty());
        let w = group_warning("alice", &["docker".into()]);
        assert!(w.contains("alice is in the group docker"), "{w}");
    }

    /// The account of the commands gets a warning for every way it gets
    /// root, and the suggestion once; an account that is none of them gets
    /// nothing, and root is not probed.
    #[test]
    fn an_account_that_gets_root_is_warned_about() {
        let alice = account("alice", 1000);
        let docker = ["docker".to_string()];
        let no = || false;
        let yes = || true;
        // The account that ran sudo.
        let w = root_warnings(&alice, "alice", &[], no);
        assert_eq!(w.len(), 2, "{w:?}");
        assert!(w[0].contains("alice is the account that ran sudo"), "{w:?}");
        assert!(w[1].contains("setup --create-user nerve-work"), "{w:?}");
        // Another account that may use sudo without a password.
        let w = root_warnings(&alice, "bob", &[], yes);
        assert_eq!(w.len(), 2, "{w:?}");
        assert!(
            w[0].contains("alice may use sudo without a password"),
            "{w:?}"
        );
        // One of the groups that get root.
        let w = root_warnings(&alice, "bob", &docker, no);
        assert!(w[0].contains("alice is in the group docker"), "{w:?}");
        assert!(w[1].contains("--create-user nerve-work"), "{w:?}");
        // All three: three reasons, one suggestion.
        let w = root_warnings(&alice, "alice", &docker, yes);
        assert_eq!(w.len(), 4, "{w:?}");
        assert_eq!(w.iter().filter(|l| l.contains("--create-user")).count(), 1);
        // A boundary: no warning, no suggestion.
        assert!(root_warnings(&alice, "bob", &[], no).is_empty());
        // Root has its warning, and nothing asks sudo about it.
        let root = account("root", 0);
        let w = root_warnings(&root, "root", &[], || panic!("root is not probed"));
        assert_eq!(w, [root_warning(), CREATE_USER_HINT_ROOT.to_string()]);
        // The suggestion follows who runs the command, not the account:
        // root has no need of sudo, and may have none; anyone else has.
        assert!(!CREATE_USER_HINT_ROOT.contains("sudo"));
        let w = root_warnings(&root, "alice", &[], no);
        assert_eq!(w.last().map(String::as_str), Some(CREATE_USER_HINT));
        let w = root_warnings(&alice, "root", &docker, no);
        assert_eq!(w.last().map(String::as_str), Some(CREATE_USER_HINT_ROOT));
    }

    /// The rules sudo lists for an account say whether a probe is worth
    /// making: a password sudoer, a sudoer with `NOPASSWD` for single
    /// commands and an account without rules are not.
    #[test]
    fn a_sudo_listing_tells_whether_no_password_is_asked() {
        let wheel = ["alice".to_string(), "wheel".to_string()];
        let yes = |l: &str| lists_no_password(l, &wheel, &[27]);
        assert!(yes(
            "User alice may run the following commands on h:\n    (ALL) NOPASSWD: ALL\n"
        ));
        assert!(yes("    (root) NOPASSWD: SETENV: ALL\n"));
        assert!(yes(
            "    (ALL : ALL) ALL\n    (ALL) NOPASSWD: /usr/bin/id, ALL\n"
        ));
        assert!(yes(
            "Matching Defaults entries for alice on h:\n    env_reset, !authenticate\n"
        ));
        assert!(yes(
            "Runas and Command-specific defaults for alice:\n    Defaults>root !authenticate\n"
        ));
        assert!(yes("    env_reset, exempt_group=wheel\n"));
        // A few commands without a password: `true` is not one of them.
        assert!(!yes(
            "    (ALL : ALL) ALL\n    (root) NOPASSWD: /usr/bin/apt, /usr/bin/systemctl\n"
        ));
        assert!(yes(
            "Runas and Command-specific defaults for alice:\n    Defaults!ALL !authenticate\n"
        ));
        assert!(!yes(
            "Runas and Command-specific defaults for alice:\n    Defaults!/usr/bin/apt !authenticate\n"
        ));
        // Bound to a user to run as: only root or everyone counts, in
        // whatever place sudo prints it, and not when `!root` follows.
        assert!(yes("    Defaults>root,postgres !authenticate\n"));
        assert!(yes("    Defaults>root, nobody !authenticate\n"));
        assert!(yes("    Defaults>nobody, root !authenticate\n"));
        assert!(yes("    Defaults>#0 !authenticate\n"));
        assert!(yes("    Defaults!/usr/bin/apt, ALL !authenticate\n"));
        assert!(yes("    Defaults>ALL, !postgres !authenticate\n"));
        assert!(!yes("    Defaults>ALL, !root !authenticate\n"));
        assert!(!yes("    Defaults>nobody, postgres !authenticate\n"));
        assert!(yes("    Defaults>ALL !authenticate\n"));
        assert!(!yes("    Defaults>postgres !authenticate\n"));
        // A group by its gid is printed with an escaped `#`.
        assert!(yes("    env_reset, exempt_group=\\#27\n"));
        assert!(!yes("    env_reset, exempt_group=\\#28\n"));
        // Another group's exemption.
        assert!(!yes("    env_reset, exempt_group=admins\n"));
        assert!(!yes(
            "User alice may run the following commands on h:\n    (ALL : ALL) ALL\n"
        ));
        assert!(!yes("User bob is not allowed to run sudo on h.\n"));
        assert!(!yes(""));
    }

    #[test]
    fn names_and_passwd_lines() {
        for ok in ["alice", "_x", "a-b_9"] {
            assert!(makeable_name(ok), "{ok}");
        }
        for bad in ["", "Alice", "-a", "9a", "a.b", "a b", &"a".repeat(33)] {
            assert!(!makeable_name(bad), "{bad}");
        }
        let a = parse_passwd("alice:x:1000:1001:Alice A,,,:/home/alice:/bin/bash\n").unwrap();
        assert_eq!(
            a,
            Account {
                name: "alice".into(),
                uid: 1000,
                gid: 1001,
                comment: "Alice A,,,".into(),
                home: "/home/alice".into(),
                groups: vec![1001],
            }
        );
        assert!(parse_passwd("alice:x:y:1").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn reaches_follows_the_permission_bits() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("config");
        let key = dir.join("keys/lab.key");
        nerve_transport::files::write_private(&key, b"key").unwrap();
        let set = |p: &Path, m: u32| {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap()
        };
        set(&dir, 0o700);
        // SAFETY: plain getters.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let owner = Account {
            gid,
            groups: vec![gid],
            ..account("me", uid)
        };
        let other = account("other", uid.wrapping_add(4242));
        assert!(reaches(&key, &owner));
        assert!(!reaches(&key, &other));
        assert!(!reaches(&dir, &other));
        assert!(reaches(&key, &account("root", 0)));
        // A folder open to others lets them in, down to a key that is too.
        set(&dir, 0o711);
        set(&dir.join("keys"), 0o711);
        assert!(!reaches(&key, &other));
        set(&key, 0o604);
        assert!(reaches(&key, &other));
        assert!(!reaches(&dir.join("none"), &other));
    }

    /// The check a command makes as its account before it runs: the
    /// kernel's answer for this process.
    #[cfg(target_os = "linux")]
    #[test]
    fn out_of_reach_asks_the_kernel() {
        use std::os::unix::fs::PermissionsExt;
        if nerve_transport::net::euid() == 0 {
            return; // root reaches every folder
        }
        let d = tempfile::tempdir().unwrap();
        let own = d.path().join("state");
        std::fs::create_dir(&own).unwrap();
        let c = vec![std::ffi::CString::new(own.to_str().unwrap()).unwrap()];
        let e = out_of_reach(&c).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(IN_REACH));
        std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o000)).unwrap();
        out_of_reach(&c).unwrap();
        std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}
