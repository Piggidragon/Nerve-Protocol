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
    let _spawning = crate::spawn_gate::spawning();
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
