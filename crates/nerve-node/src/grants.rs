//! The folder grants of Windows folder mode (docs/user/modes.md). Each
//! center's commands run in an AppContainer of their own
//! (`nerve_sandbox::appcontainer`), which reaches only what carries a grant
//! for its SID. The node puts those grants on the center's folders, with the
//! rights of their flags (`exec::container_grants`), so the grants follow
//! the folders: a folder added gets one, a folder or center removed loses
//! it, and `uninstall` takes them all off. They follow the folders whatever
//! the mode; only folder mode runs commands in the container.
//!
//! The node keeps a record of the grants it put on (`grants.json` in its
//! state folder), so it finds them again to take them off, also after the
//! config changed while it did not run. It brings them in line when it
//! starts, when its config changes, and before each folder-mode command; the
//! CLI does when it writes the config itself, which it always does on
//! Windows (no control socket, `cli::edit`). The comparison and the record
//! are plain logic, tested on every platform; the change on a folder is the
//! caller's ([`Folders`]).
//!
//! A grant is an entry in the folder's own access list, so it goes where the
//! folder goes: the record keeps which object it is on (its file ID), and a
//! grant whose folder was moved or renamed comes off where the folder is
//! now. A folder made again in place of a granted one has no grant, so each
//! sync looks at every grant and puts a missing one on again.
//!
//! Commands move only what they read and write, and a granted folder only
//! out of another one they read and write (`nerve_sandbox::acl`), so taking
//! a grant off where a moved folder is now makes nothing readable that was
//! not. Where they write, though, they can put something in place of a
//! granted folder inside it, such as a junction to another folder; a grant
//! goes on there only on a folder of its own ([`Folders::set`]).

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use nerve_policy::config::{Access, NodeConfig};
use nerve_policy::paths::within;
use nerve_policy::protected::Platform;
pub use nerve_sandbox::acl::Found;
use serde::{Deserialize, Serialize};

use crate::paths::NodePaths;

/// One grant the node put on a folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    /// The AppContainer it is for ([`container`]).
    pub container: String,
    pub path: PathBuf,
    pub access: Access,
    /// The object that carries it ([`Folders::look`]), to find it again
    /// when it was moved. None in what the config wants, and where the
    /// volume names no object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

impl Grant {
    fn same_place(&self, other: &Grant) -> bool {
        self.container == other.container
            && within(&self.path, &other.path)
            && within(&other.path, &self.path)
    }
}

/// The record of the grants the node put on.
pub fn record_file(paths: &NodePaths) -> PathBuf {
    paths.state_dir.join("grants.json")
}

/// The AppContainer of `center`'s commands on the node at `paths`: one per
/// center and per node, so neither reaches another's folders. A name of 30
/// characters of `[a-z0-9.]`, within Windows' 64.
pub fn container(paths: &NodePaths, center: &str) -> String {
    let seed = format!("{}\n{center}", paths.state_dir.display());
    let d = ring::digest::digest(&ring::digest::SHA256, seed.as_bytes());
    let hex: String = d.as_ref()[..12]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("nerve.{hex}")
}

/// The grants the config asks for: every center's folders, each with the
/// flags of its sets (`exec::container_grants`). `home` is the `~` of the
/// rules, the home of the account commands run as. A folder inside one that
/// any center's commands may write gets its grant only where it is itself,
/// not where a link or junction there leads.
pub fn wanted(cfg: &NodeConfig, paths: &NodePaths, home: &Path, platform: &Platform) -> Vec<Grant> {
    let own = paths.own();
    let writable: Vec<PathBuf> = cfg
        .centers
        .iter()
        .flat_map(|c| &c.policy.folders)
        .filter(|f| f.access.write)
        .filter_map(|f| nerve_policy::protected::expand(home, &f.path))
        .collect();
    cfg.centers
        .iter()
        .flat_map(|c| {
            let name = container(paths, &c.name);
            crate::exec::container_grants(&c.policy, home, &own, platform, &writable)
                .into_iter()
                .filter(|(_, a)| *a != Access::NONE)
                .map(move |(path, access)| Grant {
                    container: name.clone(),
                    path,
                    access,
                    id: None,
                })
        })
        .collect()
}

/// The grants a node wants on this machine: [`wanted`], or none on the
/// installed service (`installed`), whose commands run as another account
/// and never in a container (crate::daemon), so their grants come off.
pub fn wanted_on(
    installed: bool,
    cfg: &NodeConfig,
    paths: &NodePaths,
    home: &Path,
    platform: &Platform,
) -> Vec<Grant> {
    if installed {
        return Vec::new();
    }
    wanted(cfg, paths, home, platform)
}

/// What [`sync`] left.
#[derive(Debug, Default)]
pub struct Synced {
    /// Each change that failed.
    pub errors: Vec<String>,
    /// Grants that may be on where the folders no longer give them: their
    /// removal failed, or the object they are on could not be found. The
    /// record keeps them to try again. A command of their container must
    /// not run while one is left.
    pub stale: Vec<Grant>,
    /// Why the record could not be read or held, when it could not: which
    /// grants are on is then not known, so no command may run in any
    /// container until it can.
    pub unknown: Option<String>,
    /// Grants on a volume that is not on the machine now: nothing reaches
    /// them while it is away, and the record keeps them until it is back.
    pub away: Vec<Grant>,
    /// Containers that had grants and have none now.
    pub emptied: Vec<String>,
    /// How many grants were taken off.
    pub removed: usize,
}

impl Synced {
    fn not_known(mut self, why: String) -> Synced {
        self.errors
            .push(format!("the record of the folder grants: {why}"));
        self.unknown = Some(why);
        self
    }

    /// Why a command of `container` must not run after this sync, if it
    /// must not: a grant of its own that should be off is on, or the grants
    /// are not known at all.
    pub fn refusal(&self, container: &str) -> Option<String> {
        if let Some(why) = &self.unknown {
            return Some(format!(
                "the command was not run: the node cannot tell which folders carry grants for the commands ({why})"
            ));
        }
        self.stale.iter().find(|g| g.container == container).map(|g| {
            format!(
                "the command was not run: {} keeps a grant for this center's commands that its folders no longer give, and it could not be taken off",
                nerve_policy::paths::to_wire(&g.path)
            )
        })
    }
}

/// What a sync looks at and changes on the folders: on Windows their
/// access lists (`nerve_sandbox::appcontainer`), in the tests a fake.
pub trait Folders {
    /// What is at `path`: `None` when nothing is there.
    fn look(&mut self, path: &Path, container: &str, access: Access) -> io::Result<Option<Look>>;
    /// Where the object `id` is now; `near` is a path it had.
    fn locate(&mut self, id: &str, near: &Path) -> io::Result<Found>;
    /// Puts `container`'s grant with `access` on `path` in place of any it
    /// had, or takes it off (`None`); NotFound when nothing is there. With
    /// `own`, a grant goes on only an object of its own at `path` (not a
    /// link or junction to elsewhere, not a file with other names, and with
    /// a list that inherits); otherwise it is refused (InvalidInput) and
    /// nothing changes. The id of the object it changed, when the volume
    /// names one.
    fn set(
        &mut self,
        path: &Path,
        container: &str,
        access: Option<Access>,
        own: bool,
    ) -> io::Result<Option<String>>;
}

/// What [`Folders::look`] saw at a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Look {
    /// The object there, when the volume names one.
    pub id: Option<String>,
    /// Whether it carries exactly the container's grant with the access
    /// asked about.
    pub granted: bool,
}

fn read_record(file: &Path) -> Result<Vec<Grant>, String> {
    match std::fs::read(file) {
        Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", file.display())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("{}: {e}", file.display())),
    }
}

fn write_record(file: &Path, grants: &[Grant]) -> Result<(), String> {
    let json = serde_json::to_vec_pretty(grants).expect("grants serialise");
    nerve_transport::files::write_private(file, &json).map_err(|e| {
        format!(
            "cannot write the record of the folder grants {}: {e}",
            file.display()
        )
    })
}

/// Whether commands may put something at `path`: it lies inside a folder
/// that a container may write, by a wanted or a recorded grant. What is
/// there may then be a junction to another folder, or a file linked to one
/// elsewhere, and a grant on it would reach that.
fn open_to_commands(path: &Path, want: &[Grant], record: &[Grant]) -> bool {
    want.iter()
        .chain(record)
        .any(|g| g.access.write && within(path, &g.path) && !within(&g.path, path))
}

/// One process changes grants at a time: commands of several centers, and
/// the daemon's own sync, may want it at once.
static SYNC: Mutex<()> = Mutex::new(());

/// The lock file beside the record (`grants.json.lock`).
fn lock_file(record: &Path) -> PathBuf {
    let mut s = record.as_os_str().to_owned();
    s.push(".lock");
    PathBuf::from(s)
}

/// Holds the record while it lives. Other processes change the grants too
/// (the CLI, while a node run by hand does), each reading the record,
/// changing folders and writing it back, so one must not write over what
/// another recorded meanwhile. The lock file is held with flock on Unix,
/// and on Windows by keeping it open for nobody else; both end with the
/// process.
struct RecordLock {
    _file: std::fs::File,
}

impl RecordLock {
    fn take(record: &Path) -> io::Result<RecordLock> {
        let path = lock_file(record);
        if let Some(dir) = path.parent() {
            nerve_transport::files::create_private_dir(dir)?;
        }
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
            let file = opts.open(&path)?;
            loop {
                // SAFETY: flock on a descriptor this function owns.
                if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                    return Ok(RecordLock { _file: file });
                }
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::Interrupted {
                    return Err(e);
                }
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const ERROR_SHARING_VIOLATION: i32 = 32;
            opts.share_mode(0);
            loop {
                match opts.open(&path) {
                    Ok(file) => return Ok(RecordLock { _file: file }),
                    Err(e) if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => {
                        std::thread::sleep(std::time::Duration::from_millis(50))
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        #[cfg(not(any(unix, windows)))]
        Ok(RecordLock {
            _file: opts.open(&path)?,
        })
    }
}

/// Brings the grants in line with `want`, holding the record meanwhile.
///
/// Each recorded grant is looked at where its object is now. One that is
/// not wanted is taken off; one whose object moved away from its path (a
/// rename, a move on the volume) is taken off where the object is now,
/// since it went along. A wanted one whose object is at its path with the
/// same flags stays when the grant is still on, and is put on again when it
/// is not (the object was made again, or its list changed); one with other
/// flags is replaced. Each wanted grant without a record is put on, and is
/// recorded before it is, so no failure can leave a grant on that the record
/// does not hold. A path that is gone gets no grant: it gets one at a later
/// sync. A path inside a folder commands may write gets one only on an
/// object of its own ([`open_to_commands`]). A grant that could not be taken
/// off, or whose object could not be found, stays recorded and is stale. A
/// record that cannot be read stops the sync, since the grants in it could
/// not be found again.
pub fn sync(file: &Path, want: &[Grant], folders: &mut impl Folders) -> Synced {
    let _one = SYNC.lock().unwrap_or_else(|p| p.into_inner());
    let out = Synced::default();
    // Without a state folder nothing is recorded, and with nothing wanted
    // there is nothing to do: no folder and no lock file are made for it
    // (uninstall on a machine where the node never ran).
    let dir = file.parent().unwrap_or(Path::new(""));
    if want.is_empty()
        && matches!(std::fs::metadata(dir), Err(e) if e.kind() == io::ErrorKind::NotFound)
    {
        return out;
    }
    let _held = match RecordLock::take(file) {
        Ok(l) => l,
        Err(e) => return out.not_known(format!("{}: {e}", lock_file(file).display())),
    };
    let record = match read_record(file) {
        Ok(r) => r,
        Err(e) => return out.not_known(e),
    };
    let mut out = out;
    let gone = |e: &io::Error| e.kind() == io::ErrorKind::NotFound;
    let mut kept: Vec<Grant> = Vec::new();
    let mut changed = false;
    // The wanted grants that are on as they should be.
    let mut done = vec![false; want.len()];
    // Recorded grants at their path that a wanted one replaces below.
    let mut replaced: Vec<Grant> = Vec::new();
    for old in &record {
        let wanted = want.iter().position(|w| w.same_place(old));
        let here = folders.look(&old.path, &old.container, old.access);
        // Whether the object with the grant is still at its path. A record
        // without the object's id takes the one there.
        let at_path = match &here {
            Ok(Some(l)) => old.id.is_none() || l.id.is_none() || old.id == l.id,
            Ok(None) => false,
            // Cannot tell: a change there fails in turn and keeps it.
            Err(_) => true,
        };
        if at_path {
            let look = here.ok().flatten();
            match wanted {
                // Another record of the same object holds the place.
                Some(i) if done[i] => changed = true,
                Some(i)
                    if want[i].access == old.access && look.as_ref().is_some_and(|l| l.granted) =>
                {
                    done[i] = true;
                    let id = old.id.clone().or_else(|| look.and_then(|l| l.id));
                    changed |= id != old.id;
                    kept.push(Grant { id, ..old.clone() });
                }
                Some(_) => replaced.push(old.clone()),
                None => match folders.set(&old.path, &old.container, None, false) {
                    Ok(_) => {
                        changed = true;
                        out.removed += 1;
                    }
                    Err(e) if gone(&e) => changed = true,
                    Err(e) => {
                        out.errors.push(format!(
                            "cannot take the grant off {}: {e}",
                            old.path.display()
                        ));
                        out.stale.push(old.clone());
                        kept.push(old.clone());
                    }
                },
            }
            continue;
        }
        // Moved, made again, or deleted: the grant is where the object is.
        let found = match &old.id {
            Some(id) => folders.locate(id, &old.path),
            None => Ok(Found::Gone),
        };
        match found {
            Ok(Found::Gone) => changed = true,
            // Nothing reaches it while its volume is away; a later sync
            // looks again.
            Ok(Found::Away) => {
                out.away.push(old.clone());
                kept.push(old.clone());
            }
            Ok(Found::At(now)) => match folders.set(&now, &old.container, None, false) {
                Ok(_) => {
                    changed = true;
                    out.removed += 1;
                }
                Err(e) if gone(&e) => changed = true,
                Err(e) => {
                    out.errors.push(format!(
                        "cannot take the grant off {}, which was {}: {e}",
                        now.display(),
                        old.path.display()
                    ));
                    out.stale.push(old.clone());
                    kept.push(old.clone());
                }
            },
            Err(e) => {
                out.errors.push(format!(
                    "cannot find what was {} again to take its grant off: {e}",
                    old.path.display()
                ));
                out.stale.push(old.clone());
                kept.push(old.clone());
            }
        }
    }
    // What was on at a place stays on when its replacement fails: stale
    // when its flags are not the wanted ones.
    let keep_replaced = |w: &Grant, out: &mut Synced, kept: &mut Vec<Grant>| {
        for o in replaced.iter().filter(|o| o.same_place(w)) {
            if o.access != w.access {
                out.stale.push(o.clone());
            }
            kept.push(o.clone());
        }
    };
    let todo: Vec<&Grant> = want
        .iter()
        .zip(&done)
        .filter(|(_, d)| !**d)
        .map(|(w, _)| w)
        .collect();
    if !todo.is_empty() {
        let mut ahead = kept.clone();
        ahead.extend(replaced.iter().cloned());
        ahead.extend(
            todo.iter()
                .filter(|w| !replaced.iter().any(|o| o.same_place(w)))
                .map(|w| (*w).clone()),
        );
        match write_record(file, &ahead) {
            Err(e) => {
                // Nothing goes on.
                out.errors.push(e);
                for w in &todo {
                    keep_replaced(w, &mut out, &mut kept);
                }
            }
            Ok(()) => {
                changed = true;
                for w in todo {
                    let own = open_to_commands(&w.path, want, &record);
                    match folders.set(&w.path, &w.container, Some(w.access), own) {
                        Ok(id) => kept.push(Grant { id, ..w.clone() }),
                        Err(e) if gone(&e) => {}
                        // Refused before anything changed: what was there
                        // stays.
                        Err(e) if e.kind() == io::ErrorKind::InvalidInput => {
                            out.errors.push(format!("{}: {e}", w.path.display()));
                            keep_replaced(w, &mut out, &mut kept);
                        }
                        Err(e) => {
                            out.errors.push(format!(
                                "cannot grant {} to the commands: {e}",
                                w.path.display()
                            ));
                            // It may be on in part, or what was there stays.
                            if !replaced.iter().any(|o| o.same_place(w)) {
                                kept.push(w.clone());
                            }
                            keep_replaced(w, &mut out, &mut kept);
                        }
                    }
                }
            }
        }
    }
    out.emptied = record
        .iter()
        .map(|g| g.container.clone())
        .filter(|c| !kept.iter().any(|k| &k.container == c))
        .collect();
    out.emptied.sort();
    out.emptied.dedup();
    if changed && let Err(e) = write_record(file, &kept) {
        out.errors.push(e);
    }
    out
}

/// Brings the grants on this machine in line with `cfg` ([`wanted`],
/// [`sync`]), and removes the profile of a container left without grants.
/// Nothing to do where commands are not confined by grants (Linux).
pub fn apply(paths: &NodePaths, cfg: &NodeConfig, home: &Path) -> Synced {
    #[cfg(windows)]
    {
        let installed = crate::service::is_service_node(paths);
        let want = wanted_on(installed, cfg, paths, home, &crate::paths::platform());
        windows_sync(paths, &want)
    }
    #[cfg(not(windows))]
    {
        let _ = (paths, cfg, home);
        Synced::default()
    }
}

/// Takes off every grant the node put on, and the profiles of its
/// containers: those in the record and those of `centers`. For uninstall.
pub fn remove_all(paths: &NodePaths, centers: &[String]) -> Synced {
    #[cfg(windows)]
    {
        let mut s = windows_sync(paths, &[]);
        for c in centers {
            let name = container(paths, c);
            if !s.emptied.contains(&name)
                && let Err(e) = nerve_sandbox::appcontainer::remove_profile(&name)
            {
                s.errors.push(e.to_string());
            }
        }
        s
    }
    #[cfg(not(windows))]
    {
        let _ = (paths, centers);
        Synced::default()
    }
}

/// The folders' access lists on Windows.
#[cfg(windows)]
struct Acls;

#[cfg(windows)]
impl Folders for Acls {
    fn look(&mut self, path: &Path, container: &str, access: Access) -> io::Result<Option<Look>> {
        use nerve_sandbox::{acl, appcontainer};
        let masks = acl::masks(access.read, access.write, access.execute);
        match appcontainer::look(path, container, masks) {
            Ok((id, granted)) => Ok(Some(Look {
                id: id.map(|i| i.to_string()),
                granted,
            })),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn locate(&mut self, id: &str, near: &Path) -> io::Result<Found> {
        let id = id.parse().map_err(io::Error::other)?;
        nerve_sandbox::appcontainer::locate(&id, near)
    }

    fn set(
        &mut self,
        path: &Path,
        container: &str,
        access: Option<Access>,
        own: bool,
    ) -> io::Result<Option<String>> {
        use nerve_sandbox::{acl, appcontainer};
        let masks = access.map(|a| acl::masks(a.read, a.write, a.execute));
        // The object changed, as its handle names it: the path may lead
        // elsewhere by now.
        let id = appcontainer::set(path, container, masks, own)?;
        Ok(id.map(|i| i.to_string()))
    }
}

#[cfg(windows)]
fn windows_sync(paths: &NodePaths, want: &[Grant]) -> Synced {
    let mut s = sync(&record_file(paths), want, &mut Acls);
    for c in &s.emptied {
        if let Err(e) = nerve_sandbox::appcontainer::remove_profile(c) {
            s.errors.push(e.to_string());
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(container: &str, path: &str, access: &str) -> Grant {
        Grant {
            container: container.into(),
            path: path.into(),
            access: Access::parse(access).unwrap(),
            id: None,
        }
    }

    /// A grant as the record holds it, without the object's id.
    fn plain(g: &Grant) -> Grant {
        Grant {
            id: None,
            ..g.clone()
        }
    }

    fn recorded(file: &Path) -> Vec<Grant> {
        read_record(file).unwrap().iter().map(plain).collect()
    }

    /// A fake volume: objects with ids at paths, as on NTFS, and the grants
    /// on each object, which go with it when it moves.
    #[derive(Default)]
    struct Fake {
        at: Vec<(PathBuf, String)>,
        /// (object, container, access)
        on: Vec<(String, String, Access)>,
        /// Paths whose access list cannot be changed.
        locked: Vec<PathBuf>,
        /// Paths whose object is not one of its own there: a junction to
        /// elsewhere, a file with other names.
        foreign: Vec<PathBuf>,
        /// The `own` of each grant put on, by path.
        asked: Vec<(PathBuf, bool)>,
        /// The volume is not on the machine.
        away: bool,
        /// How many changes were made or tried.
        sets: usize,
        /// The record, when a sync must have written it before a change.
        record: Option<PathBuf>,
        next: usize,
    }

    impl Fake {
        fn make(&mut self, path: &str) -> String {
            self.next += 1;
            let id = format!("id{}", self.next);
            self.at.push((path.into(), id.clone()));
            id
        }
        fn mv(&mut self, from: &str, to: &str) {
            for (p, _) in &mut self.at {
                if p == Path::new(from) {
                    *p = to.into();
                }
            }
        }
        fn rm(&mut self, path: &str) {
            let id = self.id(Path::new(path)).unwrap();
            self.at.retain(|(_, i)| *i != id);
            self.on.retain(|(i, _, _)| *i != id);
        }
        fn id(&self, path: &Path) -> Option<String> {
            self.at
                .iter()
                .find(|(p, _)| p == path)
                .map(|(_, i)| i.clone())
        }
        /// The grants on what is at `path`.
        fn on(&self, path: &str) -> Vec<(String, Access)> {
            let id = self.id(Path::new(path));
            self.on
                .iter()
                .filter(|(i, _, _)| Some(i) == id.as_ref())
                .map(|(_, c, a)| (c.clone(), *a))
                .collect()
        }
        /// Every grant on the volume, by the path of its object.
        fn all(&self) -> Vec<Grant> {
            let mut all: Vec<Grant> = self
                .on
                .iter()
                .map(|(i, c, a)| Grant {
                    container: c.clone(),
                    path: self.at.iter().find(|(_, j)| j == i).unwrap().0.clone(),
                    access: *a,
                    id: None,
                })
                .collect();
            all.sort_by(|a, b| a.path.cmp(&b.path));
            all
        }
    }

    impl Folders for Fake {
        fn look(
            &mut self,
            path: &Path,
            container: &str,
            access: Access,
        ) -> io::Result<Option<Look>> {
            Ok(self.id(path).map(|id| {
                let granted = self
                    .on
                    .iter()
                    .filter(|(i, c, _)| *i == id && c == container)
                    .map(|(_, _, a)| *a)
                    .eq([access]);
                Look {
                    id: Some(id),
                    granted,
                }
            }))
        }
        fn locate(&mut self, id: &str, _near: &Path) -> io::Result<Found> {
            if self.away {
                return Ok(Found::Away);
            }
            Ok(self
                .at
                .iter()
                .find(|(_, i)| i == id)
                .map_or(Found::Gone, |(p, _)| Found::At(p.clone())))
        }
        fn set(
            &mut self,
            path: &Path,
            container: &str,
            access: Option<Access>,
            own: bool,
        ) -> io::Result<Option<String>> {
            self.sets += 1;
            if access.is_some() {
                self.asked.push((path.into(), own));
                if own && self.foreign.iter().any(|m| m == path) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "not an object of its own",
                    ));
                }
            }
            if let (Some(file), Some(_)) = (&self.record, access) {
                assert!(
                    recorded(file).iter().any(|g| g.path == path),
                    "{} is put on before it is recorded",
                    path.display()
                );
            }
            let id = self.id(path).ok_or(io::ErrorKind::NotFound)?;
            if self.locked.iter().any(|m| m == path) {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            self.on.retain(|(i, c, _)| !(*i == id && c == container));
            if let Some(a) = access {
                self.on.push((id.clone(), container.into(), a));
            }
            Ok(Some(id))
        }
    }

    /// Folders added get their grant, one removed loses it, a changed flag
    /// replaces it, and a sync with nothing to do changes nothing.
    #[test]
    fn grants_follow_the_folders() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/a");
        f.make("/w/b");
        let (a, b) = (grant("c1", "/w/a", "rwx"), grant("c1", "/w/b", "r"));
        let s = sync(&file, &[a.clone(), b.clone()], &mut f);
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        assert_eq!(f.all(), [a.clone(), b.clone()]);
        assert_eq!(recorded(&file), [a.clone(), b.clone()]);

        f.sets = 0;
        sync(&file, &[a.clone(), b.clone()], &mut f);
        assert_eq!(f.sets, 0, "nothing to change");

        let b2 = grant("c1", "/w/b", "rw");
        let s = sync(&file, std::slice::from_ref(&b2), &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        assert_eq!(f.all(), std::slice::from_ref(&b2));
        assert_eq!(recorded(&file), [b2]);
        assert!(s.emptied.is_empty());

        let s = sync(&file, &[], &mut f);
        assert!(f.all().is_empty());
        assert!(recorded(&file).is_empty());
        assert_eq!(s.emptied, ["c1"]);
    }

    /// A grant that cannot be taken off stays recorded and is reported as
    /// stale, so its container's commands do not run; the next sync tries
    /// again. A folder that is gone loses its record.
    #[test]
    fn a_grant_that_stays_on_is_kept_and_reported() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/a");
        f.make("/w/b");
        let (a, b) = (grant("c1", "/w/a", "rwx"), grant("c2", "/w/b", "r"));
        sync(&file, &[a.clone(), b.clone()], &mut f);
        f.locked.push("/w/a".into());
        f.rm("/w/b");
        let s = sync(&file, &[], &mut f);
        assert_eq!(
            s.stale.iter().map(plain).collect::<Vec<_>>(),
            std::slice::from_ref(&a)
        );
        assert_eq!(s.errors.len(), 1, "{s:?}");
        assert_eq!(s.emptied, ["c2"]);
        assert_eq!(recorded(&file), std::slice::from_ref(&a));
        assert!(s.refusal(&a.container).is_some());
        assert!(s.refusal("c2").is_none());
        f.locked.clear();
        let s = sync(&file, &[], &mut f);
        assert!(s.stale.is_empty() && s.errors.is_empty(), "{s:?}");
        assert!(recorded(&file).is_empty());
        // A wanted folder that is not there yet gets no grant and no record.
        let c = grant("c1", "/w/b", "r");
        let s = sync(&file, &[c], &mut f);
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        assert!(recorded(&file).is_empty());
    }

    /// A changed flag that cannot be put on leaves the old grant recorded,
    /// since it is still on, and reports it as stale.
    #[test]
    fn a_failed_change_keeps_the_old_grant_recorded() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/a");
        let a = grant("c1", "/w/a", "rwx");
        sync(&file, std::slice::from_ref(&a), &mut f);
        f.locked.push("/w/a".into());
        let s = sync(&file, &[grant("c1", "/w/a", "r")], &mut f);
        assert_eq!(
            s.stale.iter().map(plain).collect::<Vec<_>>(),
            std::slice::from_ref(&a)
        );
        assert_eq!(recorded(&file), [a]);
    }

    /// A granted folder that was moved or renamed takes its grant along:
    /// the sync takes it off where the folder is now, also when a new
    /// folder took the old place. One that cannot be taken off there is
    /// stale; one on a volume that is away stays recorded until it is back.
    #[test]
    fn a_moved_folder_loses_its_grant_where_it_is_now() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/a");
        f.make("/w/b");
        let (a, b) = (grant("c1", "/w/a", "rwx"), grant("c1", "/w/b", "r"));
        sync(&file, &[a.clone(), b.clone()], &mut f);

        f.mv("/w/a", "/archive/a");
        let s = sync(&file, std::slice::from_ref(&b), &mut f);
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        assert_eq!(s.removed, 1);
        assert!(f.on("/archive/a").is_empty(), "{:?}", f.all());
        assert_eq!(recorded(&file), std::slice::from_ref(&b));

        // Moved away and made again: the grant leaves the old folder and
        // goes on the new one.
        f.mv("/w/b", "/archive/b");
        f.make("/w/b");
        let s = sync(&file, std::slice::from_ref(&b), &mut f);
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        assert!(f.on("/archive/b").is_empty(), "{:?}", f.all());
        assert_eq!(f.all(), std::slice::from_ref(&b));
        assert_eq!(read_record(&file).unwrap()[0].id, f.id(Path::new("/w/b")));

        // Where it cannot be taken off, the grant stays recorded and stops
        // the container's commands.
        f.mv("/w/b", "/archive/b2");
        f.locked.push("/archive/b2".into());
        let s = sync(&file, &[], &mut f);
        assert_eq!(
            s.stale.iter().map(plain).collect::<Vec<_>>(),
            std::slice::from_ref(&b)
        );
        assert!(s.refusal("c1").is_some());
        assert_eq!(recorded(&file), std::slice::from_ref(&b));

        // A volume that is away: nothing reaches the grant, so it neither
        // stops the commands nor leaves the record, and it is named.
        f.away = true;
        let s = sync(&file, &[], &mut f);
        assert!(s.stale.is_empty() && s.errors.is_empty(), "{s:?}");
        assert_eq!(
            s.away.iter().map(plain).collect::<Vec<_>>(),
            std::slice::from_ref(&b)
        );
        assert_eq!(recorded(&file), std::slice::from_ref(&b));
        f.away = false;
        f.locked.clear();
        let s = sync(&file, &[], &mut f);
        assert!(s.stale.is_empty() && s.errors.is_empty(), "{s:?}");
        assert!(f.all().is_empty() && recorded(&file).is_empty());
    }

    /// A granted folder or file that was deleted and made again, or whose
    /// grant went otherwise, gets it again at the next sync.
    #[test]
    fn a_folder_made_again_gets_its_grant_again() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        f.make("/w/a");
        f.make("/home/notes.txt");
        let want = [
            grant("c1", "/w/a", "rwx"),
            grant("c1", "/home/notes.txt", "rw"),
        ];
        sync(&file, &want, &mut f);
        f.rm("/w/a");
        f.make("/w/a");
        // Saved by an editor through a new file renamed over the old one.
        f.rm("/home/notes.txt");
        f.make("/home/notes.txt");
        let s = sync(&file, &want, &mut f);
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        let mut on = want.to_vec();
        on.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(f.all(), on);
        // Its own list changed: the grant goes on again too.
        f.on.clear();
        sync(&file, &want, &mut f);
        assert_eq!(f.all(), on);
    }

    /// Inside a folder that commands may write, a command can put a
    /// junction or a linked file in place of a granted folder: a grant goes
    /// on there only on an object of its own, and one refused leaves what
    /// was on as it was. Elsewhere, what the owner granted is taken as it is.
    #[test]
    fn inside_a_writable_folder_a_grant_goes_on_an_object_of_its_own() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake::default();
        for p in ["/w", "/w/p", "/w/z", "/x", "/r", "/r/q"] {
            f.make(p);
        }
        f.foreign = ["/w/p", "/x", "/r/q"].map(PathBuf::from).to_vec();
        let p = grant("c1", "/w/p", "r");
        let want = [
            grant("c1", "/w", "rw"),
            p.clone(),
            // Inside another container's writable folder too.
            grant("c2", "/w/z", "r"),
            // The owner's own junction, where no command writes.
            grant("c1", "/x", "r"),
            grant("c2", "/r", "r"),
            grant("c2", "/r/q", "rw"),
        ];
        let s = sync(&file, &want, &mut f);
        assert_eq!(s.errors.len(), 1, "{s:?}");
        assert!(s.errors[0].contains("/w/p"), "{s:?}");
        assert!(s.stale.is_empty() && s.refusal("c1").is_none(), "{s:?}");
        let mut asked = f.asked.clone();
        asked.sort();
        assert_eq!(
            asked,
            [
                ("/r".into(), false),
                ("/r/q".into(), false),
                ("/w".into(), false),
                ("/w/p".into(), true),
                ("/w/z".into(), true),
                ("/x".into(), false),
            ]
        );
        assert!(f.on("/w/p").is_empty(), "{:?}", f.all());
        assert!(!recorded(&file).contains(&p));
        // Once a folder of its own is there, it gets its grant.
        f.foreign.clear();
        let s = sync(&file, &want, &mut f);
        assert!(s.errors.is_empty(), "{s:?}");
        assert_eq!(f.on("/w/p"), [("c1".to_string(), p.access)]);
        // A refused change keeps the grant that is on, as stale.
        f.foreign.push("/w/p".into());
        let mut changed = want.to_vec();
        changed[1] = grant("c1", "/w/p", "rw");
        let s = sync(&file, &changed, &mut f);
        assert_eq!(s.errors.len(), 1, "{s:?}");
        assert_eq!(
            s.stale.iter().map(plain).collect::<Vec<_>>(),
            std::slice::from_ref(&p)
        );
        assert!(s.refusal("c1").is_some());
        assert!(recorded(&file).contains(&p));
        assert_eq!(f.on("/w/p"), [("c1".to_string(), p.access)]);
    }

    /// Without a state folder and with nothing wanted, a sync makes neither
    /// the folder nor its lock file: uninstall on a machine where no node
    /// ran leaves nothing behind. Something wanted makes them.
    #[test]
    fn a_sync_with_nothing_to_do_makes_no_state_folder() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("config"), d.path().join("state"));
        let file = record_file(&paths);
        let mut f = Fake::default();
        let s = sync(&file, &[], &mut f);
        assert!(s.errors.is_empty() && s.unknown.is_none(), "{s:?}");
        assert!(!paths.state_dir.exists());
        let s = remove_all(&paths, &[]);
        assert!(s.errors.is_empty() && s.unknown.is_none(), "{s:?}");
        assert!(!paths.state_dir.exists());
        f.make("/w/a");
        let a = grant("c1", "/w/a", "r");
        sync(&file, std::slice::from_ref(&a), &mut f);
        assert_eq!(recorded(&file), [a]);
    }

    /// Each grant is in the record before it goes on, and stays in it when
    /// putting it on failed, since part of it may be on.
    #[test]
    fn a_grant_is_recorded_before_it_goes_on() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Fake {
            record: Some(file.clone()),
            ..Default::default()
        };
        f.make("/w/a");
        f.make("/w/b");
        f.locked.push("/w/b".into());
        let (a, b) = (grant("c1", "/w/a", "rwx"), grant("c1", "/w/b", "r"));
        let s = sync(&file, &[a.clone(), b.clone()], &mut f);
        assert_eq!(s.errors.len(), 1, "{s:?}");
        assert!(s.stale.is_empty(), "{s:?}");
        assert_eq!(recorded(&file), [a.clone(), b.clone()]);
        // Not wanted any more, it is taken off as any other.
        f.locked.clear();
        sync(&file, std::slice::from_ref(&a), &mut f);
        assert_eq!(recorded(&file), [a]);
    }

    /// The record is held while a sync reads, changes and writes it: a sync
    /// waits while another process holds it, so neither writes over what the
    /// other recorded.
    #[test]
    fn a_sync_waits_while_the_record_is_held() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let held = RecordLock::take(&file).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let path = file.clone();
        let t = std::thread::spawn(move || {
            let mut f = Fake::default();
            f.make("/w/a");
            let s = sync(&path, &[grant("c1", "/w/a", "r")], &mut f);
            tx.send(()).unwrap();
            s
        });
        let wait = std::time::Duration::from_millis(300);
        assert!(rx.recv_timeout(wait).is_err(), "the sync did not wait");
        assert!(!file.exists());
        drop(held);
        rx.recv_timeout(std::time::Duration::from_secs(20)).unwrap();
        assert!(t.join().unwrap().errors.is_empty());
        assert_eq!(recorded(&file), [grant("c1", "/w/a", "r")]);
    }

    /// A record that cannot be read stops the sync, since the grants in it
    /// could not be found again, and stops every container's commands.
    #[test]
    fn an_unreadable_record_changes_nothing_and_stops_the_commands() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        std::fs::write(&file, "not json").unwrap();
        let mut f = Fake::default();
        f.make("/w/a");
        let s = sync(&file, &[grant("c1", "/w/a", "r")], &mut f);
        assert_eq!(s.errors.len(), 1, "{s:?}");
        assert_eq!(f.sets, 0);
        let why = s.refusal("any").unwrap();
        assert!(why.contains(&file.display().to_string()), "{why}");
    }

    /// Each center has a container of its own, and so has each node.
    #[test]
    fn containers_differ_by_center_and_node() {
        let p = NodePaths::new("/n1/config", "/n1/state");
        let q = NodePaths::new("/n2/config", "/n2/state");
        let a = container(&p, "lab");
        assert_eq!(a, container(&p, "lab"));
        assert_ne!(a, container(&p, "home"));
        assert_ne!(a, container(&q, "lab"));
        assert!(a.len() <= 64, "{a}");
        assert!(
            a.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.'),
            "{a}"
        );
    }

    /// The config's folders become grants per center; the node's own
    /// folders are in none, and a folder without flags gets none. With the
    /// Unix list; Windows has its own test below.
    #[cfg(unix)]
    #[test]
    fn the_config_wants_each_centers_folders() {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let (home, work, other) = (root.join("home"), root.join("work"), root.join("other"));
        for p in [&home, &work, &other] {
            std::fs::create_dir_all(p).unwrap();
        }
        let paths = NodePaths::new(work.join("cfg"), root.join("state"));
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        std::fs::write(work.join("file.txt"), "x").unwrap();
        let folder = |p: &Path, a: &str| nerve_policy::config::Folder {
            path: p.display().to_string(),
            access: Access::parse(a).unwrap(),
        };
        let mut cfg = NodeConfig::default();
        for (name, folders) in [
            ("lab", vec![folder(&work, "rwx")]),
            ("home", vec![folder(&other, "r"), folder(&home, "")]),
        ] {
            cfg.centers.push(nerve_policy::CenterEntry {
                name: name.into(),
                url: String::new(),
                pin: None,
                center_id: String::new(),
                node_id: String::new(),
                settings: Default::default(),
                paused: false,
                revoked: false,
                unknown: false,
                policy: nerve_policy::CenterPolicy {
                    folders,
                    ..Default::default()
                },
            });
        }
        let want = wanted(&cfg, &paths, &home, &Platform::Unix);
        let lab = container(&paths, "lab");
        let home_c = container(&paths, "home");
        // `work` holds the config folder: its other entries instead.
        assert!(
            want.contains(&Grant {
                container: lab.clone(),
                path: work.join("file.txt"),
                access: Access::ALL,
                id: None,
            }),
            "{want:?}"
        );
        assert!(
            !want.iter().any(|g| paths.config_dir.starts_with(&g.path)),
            "{want:?}"
        );
        assert_eq!(
            want.iter()
                .filter(|g| g.container == home_c)
                .collect::<Vec<_>>(),
            [&Grant {
                container: home_c.clone(),
                path: other.clone(),
                access: Access::parse("r").unwrap(),
                id: None,
            }]
        );
        // The installed service runs no command in a container, so it
        // wants none of these, and those it has come off.
        assert_eq!(wanted_on(false, &cfg, &paths, &home, &Platform::Unix), want);
        assert!(wanted_on(true, &cfg, &paths, &home, &Platform::Unix).is_empty());
    }

    /// A center named `name` with these folders.
    fn center(name: &str, folders: &[(&Path, &str)]) -> nerve_policy::CenterEntry {
        nerve_policy::CenterEntry {
            name: name.into(),
            url: String::new(),
            pin: None,
            center_id: String::new(),
            node_id: String::new(),
            settings: Default::default(),
            paused: false,
            revoked: false,
            unknown: false,
            policy: nerve_policy::CenterPolicy {
                folders: folders
                    .iter()
                    .map(|(p, a)| nerve_policy::config::Folder {
                        path: p.display().to_string(),
                        access: Access::parse(a).unwrap(),
                    })
                    .collect(),
                ..Default::default()
            },
        }
    }

    /// A folder granted inside a folder that commands may write (of its own
    /// center or another one) that a command replaced by a link to another
    /// folder gets no grant there: the folder it leads to keeps its own
    /// flags and gets none of the nested folder's. The link put there
    /// between `wanted` and the change is the Windows `set`'s to refuse
    /// (`a_junction_in_place_of_a_granted_folder_gets_no_grant`). A link the
    /// owner put above the writable folder is followed.
    #[cfg(unix)]
    #[test]
    fn a_link_put_in_place_of_a_nested_folder_gets_no_grant() {
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let (real_work, outbox) = (root.join("real-work"), root.join("outbox"));
        let work = root.join("work");
        let bin = work.join("bin");
        std::fs::create_dir_all(real_work.join("bin")).unwrap();
        std::fs::create_dir_all(&outbox).unwrap();
        // The owner's own link to the work folder.
        std::os::unix::fs::symlink(&real_work, &work).unwrap();
        let paths = NodePaths::new(root.join("cfg"), root.join("state"));
        let mut cfg = NodeConfig::default();
        cfg.centers.push(center(
            "lab",
            &[(&work, "rw"), (&bin, "rwx"), (&outbox, "w")],
        ));
        cfg.centers.push(center("home", &[(&bin, "r")]));
        let (lab, home) = (container(&paths, "lab"), container(&paths, "home"));
        let g = |c: &str, p: &Path, a: &str| Grant {
            container: c.into(),
            path: p.into(),
            access: Access::parse(a).unwrap(),
            id: None,
        };
        let sorted = |mut v: Vec<Grant>| {
            v.sort_by(|a, b| (&a.container, &a.path).cmp(&(&b.container, &b.path)));
            v
        };
        let want = wanted(&cfg, &paths, &root, &Platform::Unix);
        assert_eq!(
            sorted(want.clone()),
            sorted(vec![
                g(&lab, &real_work, "rw"),
                g(&lab, &real_work.join("bin"), "rwx"),
                g(&lab, &outbox, "w"),
                g(&home, &real_work.join("bin"), "r"),
            ])
        );

        std::fs::remove_dir(real_work.join("bin")).unwrap();
        std::os::unix::fs::symlink(&outbox, real_work.join("bin")).unwrap();
        let swapped = wanted(&cfg, &paths, &root, &Platform::Unix);
        assert_eq!(
            sorted(swapped.clone()),
            sorted(vec![g(&lab, &real_work, "rw"), g(&lab, &outbox, "w")])
        );
        // The sync puts nothing more on the outbox.
        let file = root.join("grants.json");
        let mut f = Fake::default();
        for p in [&real_work, &real_work.join("bin"), &outbox] {
            f.make(&p.display().to_string());
        }
        sync(&file, &want, &mut f);
        let s = sync(&file, &swapped, &mut f);
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        assert_eq!(
            f.on(&outbox.display().to_string()),
            [(lab.clone(), Access::parse("w").unwrap())]
        );
    }

    /// The access list of `path` as icacls prints it.
    #[cfg(windows)]
    fn icacls(path: &Path) -> String {
        let o = std::process::Command::new("icacls")
            .arg(path)
            .output()
            .unwrap();
        String::from_utf8_lossy(&o.stdout).into_owned()
    }

    /// On Windows: a grant lands on the folder for the container's SID, and
    /// `remove_all` (uninstall) takes it off and leaves the folder's access
    /// list as it was.
    #[cfg(windows)]
    #[test]
    fn remove_all_leaves_the_folders_as_they_were() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("config"), d.path().join("state"));
        let work = d.path().join("work");
        std::fs::create_dir_all(work.join("sub")).unwrap();
        let (before, root) = (icacls(&work.join("sub")), icacls(&work));
        let want = [Grant {
            container: container(&paths, "lab"),
            path: work.clone(),
            access: Access::ALL,
            id: None,
        }];
        let s = windows_sync(&paths, &want);
        assert!(s.errors.is_empty(), "{s:?}");
        // Inherited below the folder too.
        assert!(
            icacls(&work.join("sub")).contains("S-1-15-2-"),
            "{}",
            icacls(&work)
        );
        let s = remove_all(&paths, &["lab".into()]);
        assert!(s.errors.is_empty(), "{s:?}");
        assert_eq!(s.removed, 1);
        assert!(!icacls(&work).contains("S-1-15-2-"), "{}", icacls(&work));
        assert_eq!(icacls(&work), root, "the inherited entries stay");
        assert_eq!(icacls(&work.join("sub")), before);
        assert!(read_record(&record_file(&paths)).unwrap().is_empty());
    }

    /// The canonical form of a temporary folder, as the policy compares
    /// paths: long names, no `\\?\`.
    #[cfg(windows)]
    fn canonical(p: &Path) -> PathBuf {
        PathBuf::from(nerve_policy::paths::win::strip_verbatim(
            &std::fs::canonicalize(p).unwrap().display().to_string(),
        ))
    }

    /// Makes `link` a junction to `to`.
    #[cfg(windows)]
    fn junction(link: &Path, to: &Path) {
        let o = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(to)
            .output()
            .unwrap();
        assert!(o.status.success(), "{o:?}");
    }

    /// Whether `path` carries exactly `container`'s grant of `access`.
    #[cfg(windows)]
    fn carries(path: &Path, container: &str, access: &str) -> bool {
        let a = Access::parse(access).unwrap();
        let m = nerve_sandbox::acl::masks(a.read, a.write, a.execute);
        nerve_sandbox::appcontainer::look(path, container, m)
            .unwrap()
            .1
    }

    /// On Windows: a folder granted inside a folder with `w` that a command
    /// replaced by a junction to another folder gets no grant, and the
    /// folder it leads to keeps its own flags: `wanted` leaves it out when
    /// the junction is there already, and `set` refuses it when the junction
    /// comes between `wanted` and the change. A plain folder there again
    /// gets it.
    #[cfg(windows)]
    #[test]
    fn a_junction_in_place_of_a_granted_folder_gets_no_grant() {
        let d = tempfile::tempdir().unwrap();
        let root = canonical(d.path());
        let paths = NodePaths::new(root.join("config"), root.join("state"));
        let (work, outbox) = (root.join("work"), root.join("outbox"));
        let bin = work.join("bin");
        for p in [&bin, &outbox] {
            std::fs::create_dir_all(p).unwrap();
        }
        let mut cfg = NodeConfig::default();
        cfg.centers.push(center(
            "lab",
            &[(&work, "rw"), (&bin, "rwx"), (&outbox, "w")],
        ));
        let lab = container(&paths, "lab");
        let platform = crate::paths::platform();
        let want = wanted(&cfg, &paths, &root, &platform);
        assert_eq!(want.len(), 3, "{want:?}");
        let s = windows_sync(&paths, &want);
        assert!(s.errors.is_empty(), "{s:?}");
        std::fs::remove_dir(&bin).unwrap();
        junction(&bin, &outbox);

        let now = wanted(&cfg, &paths, &root, &platform);
        assert!(
            now.iter()
                .all(|g| !within(&g.path, &bin) && g.access != Access::ALL),
            "{now:?}"
        );
        let s = windows_sync(&paths, &now);
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        assert!(carries(&outbox, &lab, "w"), "{}", icacls(&outbox));

        let s = windows_sync(&paths, &want);
        assert_eq!(s.errors.len(), 1, "{s:?}");
        assert!(s.errors[0].contains("junction"), "{s:?}");
        assert!(carries(&outbox, &lab, "w"), "{}", icacls(&outbox));

        std::fs::remove_dir(&bin).unwrap();
        std::fs::create_dir(&bin).unwrap();
        let s = windows_sync(&paths, &wanted(&cfg, &paths, &root, &platform));
        assert!(s.errors.is_empty(), "{s:?}");
        assert!(carries(&bin, &lab, "rwx"), "{}", icacls(&bin));
        let s = remove_all(&paths, &["lab".into()]);
        assert!(s.errors.is_empty(), "{s:?}");
    }

    /// On Windows: a granted folder that was renamed takes its grant along,
    /// and the sync takes it off there; one deleted and made again gets its
    /// grant back.
    #[cfg(windows)]
    #[test]
    fn grants_follow_a_renamed_and_a_remade_folder() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("config"), d.path().join("state"));
        let (work, moved) = (d.path().join("work"), d.path().join("moved"));
        std::fs::create_dir_all(work.join("sub")).unwrap();
        let want = [Grant {
            container: container(&paths, "lab"),
            path: work.clone(),
            access: Access::ALL,
            id: None,
        }];
        let s = windows_sync(&paths, &want);
        assert!(s.errors.is_empty(), "{s:?}");
        std::fs::rename(&work, &moved).unwrap();
        assert!(icacls(&moved).contains("S-1-15-2-"), "{}", icacls(&moved));
        let s = windows_sync(&paths, &[]);
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        assert_eq!(s.removed, 1);
        assert!(!icacls(&moved).contains("S-1-15-2-"), "{}", icacls(&moved));
        assert!(
            !icacls(&moved.join("sub")).contains("S-1-15-2-"),
            "{}",
            icacls(&moved.join("sub"))
        );

        std::fs::create_dir_all(&work).unwrap();
        windows_sync(&paths, &want);
        std::fs::remove_dir_all(&work).unwrap();
        std::fs::create_dir_all(&work).unwrap();
        assert!(!icacls(&work).contains("S-1-15-2-"), "{}", icacls(&work));
        let s = windows_sync(&paths, &want);
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        assert!(icacls(&work).contains("S-1-15-2-"), "{}", icacls(&work));
        // The same folder, with its grant taken off by hand: it comes back.
        nerve_sandbox::appcontainer::set(&work, &want[0].container, None, false).unwrap();
        assert!(!icacls(&work).contains("S-1-15-2-"), "{}", icacls(&work));
        windows_sync(&paths, &want);
        assert!(icacls(&work).contains("S-1-15-2-"), "{}", icacls(&work));
        let s = remove_all(&paths, &["lab".into()]);
        assert!(s.errors.is_empty(), "{s:?}");
        assert!(!icacls(&work).contains("S-1-15-2-"), "{}", icacls(&work));
    }

    /// On Windows: a granted home gives neither the node's own folders in
    /// it nor its protected entries; the folders around them are split into
    /// their other entries, as for Landlock.
    #[cfg(windows)]
    #[test]
    fn a_granted_home_gives_neither_the_nodes_folders_nor_protected_ones() {
        let d = tempfile::tempdir().unwrap();
        let home = PathBuf::from(nerve_policy::paths::win::strip_verbatim(
            &std::fs::canonicalize(d.path())
                .unwrap()
                .display()
                .to_string(),
        ));
        let paths = NodePaths::new(
            home.join(".config\\nerve"),
            home.join(".local\\state\\nerve"),
        );
        for p in [
            ".config\\nerve",
            ".config\\other",
            ".local\\state\\nerve",
            ".ssh",
            "proj",
        ] {
            std::fs::create_dir_all(home.join(p)).unwrap();
        }
        let mut cfg = NodeConfig::default();
        cfg.centers.push(nerve_policy::CenterEntry {
            name: "lab".into(),
            url: String::new(),
            pin: None,
            center_id: String::new(),
            node_id: String::new(),
            settings: Default::default(),
            paused: false,
            revoked: false,
            unknown: false,
            policy: nerve_policy::CenterPolicy {
                folders: vec![nerve_policy::config::Folder {
                    path: home.display().to_string(),
                    access: Access::ALL,
                }],
                ..Default::default()
            },
        });
        let want = wanted(&cfg, &paths, &home, &crate::paths::platform());
        let granted = |p: &Path| want.iter().any(|g| within(p, &g.path));
        assert!(granted(&home.join("proj")), "{want:?}");
        assert!(granted(&home.join(".config\\other")), "{want:?}");
        for closed in [".config\\nerve", ".local\\state\\nerve", ".ssh"] {
            assert!(!granted(&home.join(closed)), "{closed}: {want:?}");
        }
    }
}
