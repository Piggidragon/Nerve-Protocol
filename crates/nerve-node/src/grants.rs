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
//! caller's.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use nerve_policy::config::{Access, NodeConfig};
use nerve_policy::paths::within;
use nerve_policy::protected::Platform;
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
/// rules, the home of the account commands run as.
pub fn wanted(cfg: &NodeConfig, paths: &NodePaths, home: &Path, platform: &Platform) -> Vec<Grant> {
    let own = paths.own();
    cfg.centers
        .iter()
        .flat_map(|c| {
            let name = container(paths, &c.name);
            crate::exec::container_grants(&c.policy, home, &own, platform)
                .into_iter()
                .filter(|(_, a)| *a != Access::NONE)
                .map(move |(path, access)| Grant {
                    container: name.clone(),
                    path,
                    access,
                })
        })
        .collect()
}

/// What [`sync`] left.
#[derive(Debug, Default)]
pub struct Synced {
    /// Each change that failed.
    pub errors: Vec<String>,
    /// Grants that are on and not wanted: their removal failed, and the
    /// record keeps them to try again. A command of their container must
    /// not run while one is left.
    pub stale: Vec<Grant>,
    /// Containers that had grants and have none now.
    pub emptied: Vec<String>,
    /// How many grants were taken off.
    pub removed: usize,
}

fn read_record(file: &Path) -> Result<Vec<Grant>, String> {
    match std::fs::read(file) {
        Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", file.display())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("{}: {e}", file.display())),
    }
}

/// One process changes grants at a time: commands of several centers, and
/// the daemon's own sync, may want it at once.
static SYNC: Mutex<()> = Mutex::new(());

/// Brings the grants in line with `want`. Each recorded grant that is not
/// wanted is taken off, each wanted one that is not recorded is put on, and
/// one wanted with other flags is replaced. `set` changes one path:
/// `Some(access)` puts the container's grant there in place of any it had,
/// `None` takes it off. A path that is gone (NotFound) loses its record: a
/// folder that does not exist yet gets its grant at a later sync. A grant
/// that could not be taken off stays recorded. The record is written when
/// something changed; a record that cannot be read stops the sync, since
/// the grants in it could not be found again.
pub fn sync(
    file: &Path,
    want: &[Grant],
    mut set: impl FnMut(&Path, &str, Option<Access>) -> io::Result<()>,
) -> Synced {
    let _one = SYNC.lock().unwrap_or_else(|p| p.into_inner());
    let mut out = Synced::default();
    let record = match read_record(file) {
        Ok(r) => r,
        Err(e) => {
            out.errors
                .push(format!("the record of the folder grants: {e}"));
            return out;
        }
    };
    let mut kept: Vec<Grant> = Vec::new();
    let mut changed = false;
    let gone = |e: &io::Error| e.kind() == io::ErrorKind::NotFound;
    for old in &record {
        let wanted = want.iter().find(|w| w.same_place(old));
        match wanted {
            Some(w) if w.access == old.access => kept.push(old.clone()),
            // Replaced below.
            Some(_) => {}
            None => match set(&old.path, &old.container, None) {
                Ok(()) => {
                    changed = true;
                    out.removed += 1;
                }
                Err(e) if gone(&e) => changed = true,
                Err(e) => {
                    out.errors.push(format!(
                        "cannot take the grant off {}: {e}",
                        old.path.display()
                    ));
                    kept.push(old.clone());
                }
            },
        }
    }
    for w in want {
        if kept.iter().any(|k| k.same_place(w)) {
            continue;
        }
        let old = record.iter().find(|o| o.same_place(w));
        match set(&w.path, &w.container, Some(w.access)) {
            Ok(()) => {
                kept.push(w.clone());
                changed = true;
            }
            Err(e) if gone(&e) => changed |= old.is_some(),
            Err(e) => {
                out.errors.push(format!(
                    "cannot grant {} to the commands: {e}",
                    w.path.display()
                ));
                // What was on stays on.
                kept.extend(old.cloned());
            }
        }
    }
    out.stale = kept.iter().filter(|k| !want.contains(k)).cloned().collect();
    out.emptied = record
        .iter()
        .map(|g| g.container.clone())
        .filter(|c| !kept.iter().any(|k| &k.container == c))
        .collect();
    out.emptied.sort();
    out.emptied.dedup();
    if changed {
        let json = serde_json::to_vec_pretty(&kept).expect("grants serialise");
        if let Err(e) = nerve_transport::files::write_private(file, &json) {
            out.errors.push(format!(
                "cannot write the record of the folder grants {}: {e}",
                file.display()
            ));
        }
    }
    out
}

/// Brings the grants on this machine in line with `cfg` ([`wanted`],
/// [`sync`]), and removes the profile of a container left without grants.
/// Nothing to do where commands are not confined by grants (Linux).
pub fn apply(paths: &NodePaths, cfg: &NodeConfig, home: &Path) -> Synced {
    #[cfg(windows)]
    {
        let want = wanted(cfg, paths, home, &crate::paths::platform());
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
            if !s.emptied.contains(&name) {
                if let Err(e) = nerve_sandbox::appcontainer::remove_profile(&name) {
                    s.errors.push(e.to_string());
                }
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

#[cfg(windows)]
fn windows_sync(paths: &NodePaths, want: &[Grant]) -> Synced {
    use nerve_sandbox::{acl, appcontainer};
    let mut s = sync(&record_file(paths), want, |path, container, access| {
        let masks = access.map(|a| acl::masks(a.read, a.write, a.execute));
        appcontainer::set(path, container, masks)
    });
    for c in &s.emptied {
        if let Err(e) = appcontainer::remove_profile(c) {
            s.errors.push(e.to_string());
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn grant(container: &str, path: &str, access: &str) -> Grant {
        Grant {
            container: container.into(),
            path: path.into(),
            access: Access::parse(access).unwrap(),
        }
    }

    /// A fake folder system: the grants on each path, and paths that fail.
    #[derive(Default)]
    struct Folders {
        on: RefCell<Vec<Grant>>,
        missing: Vec<PathBuf>,
        locked: Vec<PathBuf>,
        calls: RefCell<usize>,
    }

    impl Folders {
        fn set(&self, path: &Path, container: &str, access: Option<Access>) -> io::Result<()> {
            *self.calls.borrow_mut() += 1;
            if self.missing.iter().any(|m| m == path) {
                return Err(io::ErrorKind::NotFound.into());
            }
            if self.locked.iter().any(|m| m == path) {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            let mut on = self.on.borrow_mut();
            on.retain(|g| !(g.path == path && g.container == container));
            if let Some(access) = access {
                on.push(Grant {
                    container: container.into(),
                    path: path.into(),
                    access,
                });
            }
            Ok(())
        }
    }

    fn sync_with(file: &Path, want: &[Grant], f: &Folders) -> Synced {
        sync(file, want, |p, c, a| f.set(p, c, a))
    }

    /// Folders added get their grant, one removed loses it, a changed flag
    /// replaces it, and a sync with nothing to do changes nothing.
    #[test]
    fn grants_follow_the_folders() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let f = Folders::default();
        let (a, b) = (grant("c1", "/w/a", "rwx"), grant("c1", "/w/b", "r"));
        let s = sync_with(&file, &[a.clone(), b.clone()], &f);
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        assert_eq!(*f.on.borrow(), [a.clone(), b.clone()]);
        assert_eq!(read_record(&file).unwrap(), [a.clone(), b.clone()]);

        *f.calls.borrow_mut() = 0;
        sync_with(&file, &[a.clone(), b.clone()], &f);
        assert_eq!(*f.calls.borrow(), 0, "nothing to change");

        let b2 = grant("c1", "/w/b", "rw");
        let s = sync_with(&file, std::slice::from_ref(&b2), &f);
        assert!(s.errors.is_empty(), "{s:?}");
        assert_eq!(*f.on.borrow(), std::slice::from_ref(&b2));
        assert_eq!(read_record(&file).unwrap(), [b2]);
        assert!(s.emptied.is_empty());

        let s = sync_with(&file, &[], &f);
        assert!(f.on.borrow().is_empty());
        assert!(read_record(&file).unwrap().is_empty());
        assert_eq!(s.emptied, ["c1"]);
    }

    /// A grant that cannot be taken off stays recorded and is reported as
    /// stale, so its container's commands do not run; the next sync tries
    /// again. A folder that is gone loses its record.
    #[test]
    fn a_grant_that_stays_on_is_kept_and_reported() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Folders::default();
        let (a, b) = (grant("c1", "/w/a", "rwx"), grant("c2", "/w/b", "r"));
        sync_with(&file, &[a.clone(), b.clone()], &f);
        f.locked.push("/w/a".into());
        f.missing.push("/w/b".into());
        let s = sync_with(&file, &[], &f);
        assert_eq!(s.stale, std::slice::from_ref(&a));
        assert_eq!(s.errors.len(), 1, "{s:?}");
        assert_eq!(s.emptied, ["c2"]);
        assert_eq!(read_record(&file).unwrap(), std::slice::from_ref(&a));
        f.locked.clear();
        let s = sync_with(&file, &[], &f);
        assert!(s.stale.is_empty() && s.errors.is_empty(), "{s:?}");
        assert!(read_record(&file).unwrap().is_empty());
        // A wanted folder that is not there yet gets no grant and no record.
        let c = grant("c1", "/w/b", "r");
        let s = sync_with(&file, &[c], &f);
        assert!(s.errors.is_empty() && s.stale.is_empty(), "{s:?}");
        assert!(!file.exists() || read_record(&file).unwrap().is_empty());
    }

    /// A changed flag that cannot be put on leaves the old grant recorded,
    /// since it is still on, and reports it as stale.
    #[test]
    fn a_failed_change_keeps_the_old_grant_recorded() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        let mut f = Folders::default();
        let a = grant("c1", "/w/a", "rwx");
        sync_with(&file, std::slice::from_ref(&a), &f);
        f.locked.push("/w/a".into());
        let s = sync_with(&file, &[grant("c1", "/w/a", "r")], &f);
        assert_eq!(s.stale, std::slice::from_ref(&a));
        assert_eq!(read_record(&file).unwrap(), [a]);
    }

    /// A record that cannot be read stops the sync: the grants in it could
    /// not be found again.
    #[test]
    fn an_unreadable_record_changes_nothing() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("grants.json");
        std::fs::write(&file, "not json").unwrap();
        let f = Folders::default();
        let s = sync_with(&file, &[grant("c1", "/w/a", "r")], &f);
        assert_eq!(s.errors.len(), 1, "{s:?}");
        assert_eq!(*f.calls.borrow(), 0);
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
            }]
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
        let before = icacls(&work.join("sub"));
        let want = [Grant {
            container: container(&paths, "lab"),
            path: work.clone(),
            access: Access::ALL,
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
        assert_eq!(icacls(&work.join("sub")), before);
        assert!(read_record(&record_file(&paths)).unwrap().is_empty());
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
