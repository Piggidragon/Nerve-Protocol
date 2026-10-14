//! How a change of a folder's access list reaches what is below it.
//!
//! Windows writes the entries a file or folder inherits into its own list
//! when it is made. A later change of a folder's list reaches what is below
//! it only when that is written again: `SetSecurityInfo` does so for every
//! object below, as `icacls` does, so a grant on a large folder took as long
//! as the whole tree (#54). The node passes a change down itself
//! ([`pass_down`]), and only as far as it changes something: an object whose
//! list comes out as it was is left alone, and so is everything below it,
//! which inherits from that same list. A list that does not inherit keeps
//! the change out of itself and of what is below it.
//!
//! A folder's list is written after everything below it. So a folder whose
//! list is as it should be has everything below it as it should be too, also
//! when an earlier walk stopped half way. Taking a grant off walks through
//! every folder all the same ([`Walk::every`]): Windows' own walk, which
//! earlier nodes used, writes a folder before what is below it, so one that
//! stopped half way left folders without the grant above objects that still
//! carry it.
//!
//! Plain logic over [`Objects`], so it is tested on every platform; the
//! objects and their lists are Windows' (`appcontainer`).

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};

/// What the walk looks at and changes.
pub trait Objects {
    /// An object, open.
    type Obj;
    /// An access list, as the walk passes it down.
    type List;
    /// The names in the folder `dir`.
    fn names(&mut self, dir: &Self::Obj) -> io::Result<Vec<OsString>>;
    /// The object `name` in the folder `dir`, as itself: a link or junction
    /// is not followed. `None` when it is gone.
    fn open(&mut self, dir: &Self::Obj, name: &OsStr) -> io::Result<Option<Self::Obj>>;
    /// What `obj` is.
    fn kind(&mut self, obj: &Self::Obj) -> io::Result<Kind>;
    /// The list of `obj` (of `kind`) under a folder whose list is `parent`.
    fn derive(
        &mut self,
        parent: &Self::List,
        obj: &Self::Obj,
        kind: &Kind,
    ) -> io::Result<Derived<Self::List>>;
    /// Writes `list` as the list of `obj`, and nothing below it.
    fn write(&mut self, obj: &Self::Obj, list: &Self::List) -> io::Result<()>;
    /// Whether `path` leads to `obj` now, so that what is looked up by the
    /// path (the names of a file) is about `obj`.
    fn at(&mut self, obj: &Self::Obj, path: &Path) -> io::Result<bool>;
}

/// What an object is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kind {
    /// A folder (its list has the entries folders inherit), also a link or
    /// junction to one.
    pub folder: bool,
    /// A link or junction to elsewhere, which the walk does not go into.
    pub link: bool,
    /// How many names it has (hard links).
    pub names: u32,
}

impl Kind {
    /// Whether the walk goes into it.
    fn walked(&self) -> bool {
        self.folder && !self.link
    }
}

/// The list an object gets under its folder's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Derived<L> {
    /// Its list does not inherit: it stays, and so does what is below it.
    Kept,
    /// The same as it has (`List` is that).
    Same(L),
    /// Another one.
    Changed(L),
}

/// How far a walk is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Walked {
    /// Objects looked at.
    pub seen: u64,
    /// Objects whose list changed, or would change.
    pub changed: u64,
}

/// Whether a file with more than one name (hard links) may change
/// ([`Walk::links`]).
pub type Links<'a> = &'a mut dyn FnMut(&Path, u32) -> io::Result<bool>;

/// [`Walk::progress`] is told after every this many objects.
pub const STEP: u64 = 256;

/// How [`pass_down`] walks.
pub struct Walk<'a> {
    /// Write the lists; otherwise only look at what the change reaches.
    pub write: bool,
    /// Go into folders whose list stays as well (taking a grant off).
    pub every: bool,
    /// Whether a file with more than one name (hard links) may change: its
    /// path by the names walked, and how many names it has. Its list is
    /// shared by all of them. `None`: any may.
    pub links: Option<Links<'a>>,
    /// Told how far the walk is, now and then.
    pub progress: &'a mut dyn FnMut(Walked),
}

/// A folder on the way down.
struct Frame<O: Objects> {
    obj: O::Obj,
    /// Its list as it is to be.
    list: O::List,
    path: PathBuf,
    /// The names in it still to go, last first.
    todo: Vec<OsString>,
    /// Whether its list is written once what is below it is done.
    write: bool,
}

/// Passes the list `list` of the folder `top` (at `path`) down to what is
/// below it, as far as it changes something. The caller writes `top`'s own
/// list, after this returned with nothing found.
///
/// Stops at the first file with more than one name whose list would change
/// and that [`Walk::links`] refuses, also where its path no longer leads to
/// it (when it is asked at all), and gives it with its count of names: a walk that writes leaves what
/// it wrote and writes no folder above it. An object that is gone meanwhile
/// is skipped.
pub fn pass_down<O: Objects>(
    objects: &mut O,
    top: O::Obj,
    list: O::List,
    path: &Path,
    mut walk: Walk,
) -> io::Result<(Walked, Option<(PathBuf, u32)>)> {
    let gone = |e: &io::Error| e.kind() == io::ErrorKind::NotFound;
    let mut walked = Walked::default();
    let mut todo = objects.names(&top)?;
    todo.reverse();
    let mut stack: Vec<Frame<O>> = vec![Frame {
        obj: top,
        list,
        path: path.to_path_buf(),
        todo,
        write: false,
    }];
    while let Some(frame) = stack.last_mut() {
        let Some(name) = frame.todo.pop() else {
            let done = stack.pop().expect("a frame");
            if done.write && walk.write {
                match objects.write(&done.obj, &done.list) {
                    Err(e) if !gone(&e) => return Err(e),
                    _ => {}
                }
            }
            continue;
        };
        let path = frame.path.join(&name);
        let obj = match objects.open(&frame.obj, &name) {
            Ok(Some(o)) => o,
            Ok(None) => continue,
            Err(e) if gone(&e) => continue,
            Err(e) => return Err(e),
        };
        // Told when the objects so far are done.
        if walked.seen > 0 && walked.seen % STEP == 0 {
            (walk.progress)(walked);
        }
        walked.seen += 1;
        let derived = objects
            .kind(&obj)
            .and_then(|kind| Ok((kind, objects.derive(&frame.list, &obj, &kind)?)));
        let (kind, derived) = match derived {
            Ok(d) => d,
            Err(e) if gone(&e) => continue,
            Err(e) => return Err(e),
        };
        let (list, write) = match derived {
            Derived::Kept => continue,
            Derived::Same(l) if kind.walked() && walk.every => (l, false),
            Derived::Same(_) => continue,
            Derived::Changed(l) => {
                walked.changed += 1;
                (l, true)
            }
        };
        if kind.walked() {
            let mut todo = match objects.names(&obj) {
                Ok(t) => t,
                Err(e) if gone(&e) => Vec::new(),
                Err(e) => return Err(e),
            };
            todo.reverse();
            stack.push(Frame {
                obj,
                list,
                path,
                todo,
                write,
            });
            continue;
        }
        if kind.names > 1
            && let Some(links) = walk.links.as_mut()
            && !(objects.at(&obj, &path)? && links(&path, kind.names)?)
        {
            return Ok((walked, Some((path, kind.names))));
        }
        if walk.write {
            match objects.write(&obj, &list) {
                Err(e) if !gone(&e) => return Err(e),
                _ => {}
            }
        }
    }
    Ok((walked, None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// A fake volume: each object has its own entries and those it
    /// inherited; an object inherits all of its folder's.
    #[derive(Clone, Default)]
    struct Node {
        name: String,
        folder: bool,
        link: bool,
        names: u32,
        own: BTreeSet<String>,
        inherited: BTreeSet<String>,
        protected: bool,
        children: Vec<usize>,
    }

    /// The list as the fake passes it down: own and inherited entries.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct List {
        own: BTreeSet<String>,
        inherited: BTreeSet<String>,
    }

    #[derive(Default)]
    struct Fake {
        nodes: Vec<Node>,
        /// Every object opened, by its path below the root.
        opened: Vec<String>,
        /// Every object written, in order.
        written: Vec<String>,
        /// Objects gone by the time they are opened.
        vanished: Vec<String>,
        /// Files whose path leads elsewhere by the time it is checked.
        moved: Vec<String>,
    }

    impl Fake {
        /// A tree of `paths` below a root (`""`): a path ending in `/` is a
        /// folder, `@` a link to a folder, `=` a file with two names.
        fn new(paths: &[&str]) -> Fake {
            let mut f = Fake::default();
            f.nodes.push(Node {
                folder: true,
                names: 1,
                ..Default::default()
            });
            for p in paths {
                let (name, folder, link, names) = if let Some(n) = p.strip_suffix('/') {
                    (n, true, false, 1)
                } else if let Some(n) = p.strip_suffix('@') {
                    (n, true, true, 1)
                } else if let Some(n) = p.strip_suffix('=') {
                    (n, false, false, 2)
                } else {
                    (*p, false, false, 1)
                };
                let parent = match name.rsplit_once('/') {
                    Some((dir, _)) => f.find(dir),
                    None => 0,
                };
                f.nodes.push(Node {
                    name: name.into(),
                    folder,
                    link,
                    names,
                    ..Default::default()
                });
                let i = f.nodes.len() - 1;
                f.nodes[parent].children.push(i);
            }
            f
        }

        fn find(&self, name: &str) -> usize {
            self.nodes
                .iter()
                .position(|n| n.name == name)
                .unwrap_or_else(|| panic!("no {name}"))
        }

        fn node(&mut self, name: &str) -> &mut Node {
            let i = self.find(name);
            &mut self.nodes[i]
        }

        fn list(&self, i: usize) -> List {
            List {
                own: self.nodes[i].own.clone(),
                inherited: self.nodes[i].inherited.clone(),
            }
        }

        /// Gives the root its own `entries` and passes them down.
        fn grant(&mut self, entries: &[&str], every: bool) -> (Walked, Option<(PathBuf, u32)>) {
            self.grant_with(entries, every, true, None, &mut |_| {})
        }

        fn grant_with<'a>(
            &mut self,
            entries: &[&str],
            every: bool,
            write: bool,
            links: Option<Links<'a>>,
            progress: &'a mut dyn FnMut(Walked),
        ) -> (Walked, Option<(PathBuf, u32)>) {
            let list = List {
                own: entries.iter().map(|e| e.to_string()).collect(),
                inherited: self.nodes[0].inherited.clone(),
            };
            let r = pass_down(
                self,
                0,
                list.clone(),
                Path::new("/top"),
                Walk {
                    write,
                    every,
                    links,
                    progress,
                },
            )
            .unwrap();
            if write && r.1.is_none() {
                self.nodes[0].own = list.own;
            }
            r
        }

        /// The entries `name` inherited.
        fn has(&self, name: &str) -> Vec<String> {
            self.nodes[self.find(name)]
                .inherited
                .iter()
                .cloned()
                .collect()
        }
    }

    impl Objects for Fake {
        type Obj = usize;
        type List = List;

        fn names(&mut self, dir: &usize) -> io::Result<Vec<OsString>> {
            Ok(self.nodes[*dir]
                .children
                .iter()
                .map(|c| {
                    let n = &self.nodes[*c].name;
                    OsString::from(n.rsplit('/').next().unwrap())
                })
                .collect())
        }

        fn open(&mut self, dir: &usize, name: &OsStr) -> io::Result<Option<usize>> {
            let found = self.nodes[*dir]
                .children
                .iter()
                .copied()
                .find(|c| self.nodes[*c].name.rsplit('/').next().unwrap() == name);
            let Some(i) = found else {
                return Ok(None);
            };
            let full = self.nodes[i].name.clone();
            if self.vanished.contains(&full) {
                return Ok(None);
            }
            self.opened.push(full);
            Ok(Some(i))
        }

        fn kind(&mut self, obj: &usize) -> io::Result<Kind> {
            let n = &self.nodes[*obj];
            Ok(Kind {
                folder: n.folder,
                link: n.link,
                names: n.names,
            })
        }

        fn derive(&mut self, parent: &List, obj: &usize, _: &Kind) -> io::Result<Derived<List>> {
            if self.nodes[*obj].protected {
                return Ok(Derived::Kept);
            }
            let now = self.list(*obj);
            let inherited: BTreeSet<String> =
                parent.own.union(&parent.inherited).cloned().collect();
            Ok(if inherited == now.inherited {
                Derived::Same(now)
            } else {
                Derived::Changed(List { inherited, ..now })
            })
        }

        fn write(&mut self, obj: &usize, list: &List) -> io::Result<()> {
            let n = &mut self.nodes[*obj];
            n.inherited = list.inherited.clone();
            n.own = list.own.clone();
            self.written.push(n.name.clone());
            Ok(())
        }

        fn at(&mut self, obj: &usize, _: &Path) -> io::Result<bool> {
            Ok(!self.moved.contains(&self.nodes[*obj].name))
        }
    }

    const TREE: &[&str] = &["a/", "a/b/", "a/b/f", "a/g", "c/", "c/h", "i"];

    /// A grant reaches every object below its folder once, and each folder
    /// is written after everything below it.
    #[test]
    fn a_change_reaches_everything_below_and_folders_last() {
        let mut f = Fake::new(TREE);
        let (w, found) = f.grant(&["g"], false);
        assert_eq!(found, None);
        assert_eq!(
            w,
            Walked {
                seen: 7,
                changed: 7
            }
        );
        for n in ["a", "a/b", "a/b/f", "a/g", "c", "c/h", "i"] {
            assert_eq!(f.has(n), ["g"], "{n}");
        }
        let mut written = f.written.clone();
        written.sort();
        let mut all: Vec<String> = TREE
            .iter()
            .map(|p| p.trim_end_matches('/').into())
            .collect();
        all.sort();
        assert_eq!(written, all, "each once");
        let at = |n: &str| f.written.iter().position(|w| w == n).unwrap();
        assert!(at("a/b/f") < at("a/b") && at("a/b") < at("a") && at("a/g") < at("a"));
        assert!(at("c/h") < at("c"));
    }

    /// The same grant again changes nothing and looks only at what is right
    /// below the folder: everything further down inherits from lists that
    /// stay. A changed grant reaches everything again.
    #[test]
    fn what_stays_as_it_was_is_not_walked() {
        let mut f = Fake::new(TREE);
        f.grant(&["g"], false);
        f.opened.clear();
        f.written.clear();
        let (w, _) = f.grant(&["g"], false);
        assert_eq!(
            w,
            Walked {
                seen: 3,
                changed: 0
            }
        );
        assert_eq!(f.opened, ["a", "c", "i"]);
        assert!(f.written.is_empty());

        // A folder moved in that carries the grant already is left alone,
        // and so is what is below it.
        let mut f = Fake::new(TREE);
        for n in ["c", "c/h"] {
            f.node(n).inherited.insert("g".into());
        }
        f.grant(&["g"], false);
        assert!(!f.opened.contains(&"c/h".to_string()), "{:?}", f.opened);
        assert!(!f.written.contains(&"c".to_string()));

        let mut f = Fake::new(TREE);
        f.grant(&["g"], false);
        f.written.clear();
        let (w, _) = f.grant(&["g2"], false);
        assert_eq!(w.changed, 7);
        assert_eq!(f.has("a/b/f"), ["g2"]);
    }

    /// A list that does not inherit is not changed, and nothing below it is
    /// looked at.
    #[test]
    fn a_list_that_does_not_inherit_keeps_the_change_out() {
        let mut f = Fake::new(TREE);
        f.node("a").protected = true;
        f.grant(&["g"], false);
        for n in ["a", "a/b", "a/b/f", "a/g"] {
            assert!(f.has(n).is_empty(), "{n}");
            assert!(!f.opened.contains(&n.to_string()) || n == "a", "{n}");
        }
        assert_eq!(f.has("c/h"), ["g"]);
    }

    /// Taking a grant off goes into every folder: below a folder that lost
    /// it already (a walk that stopped half way), what still carries it
    /// loses it too. A walk that does not go into every folder leaves it.
    #[test]
    fn taking_off_goes_into_every_folder() {
        let half = || {
            let mut f = Fake::new(TREE);
            f.grant(&["g"], false);
            // Windows' own walk wrote the folder and `a` before it stopped.
            f.nodes[0].own.clear();
            f.node("a").inherited.clear();
            f.written.clear();
            f
        };
        let mut f = half();
        f.grant(&[], true);
        for n in ["a", "a/b", "a/b/f", "a/g", "c", "c/h", "i"] {
            assert!(f.has(n).is_empty(), "{n}");
        }
        assert!(!f.written.contains(&"a".to_string()), "it stayed as it was");
        let mut f = half();
        f.grant(&[], false);
        assert_eq!(f.has("a/b/f"), ["g"]);
    }

    /// Links and junctions get the change on their own list, and the walk
    /// does not follow them; an object gone meanwhile is skipped.
    #[test]
    fn links_are_not_followed_and_gone_objects_are_skipped() {
        let mut f = Fake::new(&["l@", "d/", "d/x", "d/y"]);
        // What a junction leads to does not show below it in the fake, so
        // give it an entry of its own there: it must not be opened.
        f.nodes.push(Node {
            name: "l/inside".into(),
            names: 1,
            ..Default::default()
        });
        let i = f.nodes.len() - 1;
        f.node("l").children.push(i);
        f.vanished.push("d/x".into());
        let (w, found) = f.grant(&["g"], false);
        assert_eq!(found, None);
        assert_eq!(f.has("l"), ["g"]);
        assert!(f.has("l/inside").is_empty());
        assert!(!f.opened.contains(&"l/inside".to_string()));
        assert!(f.has("d/x").is_empty() && f.has("d/y") == ["g"]);
        assert_eq!(w.seen, 3);
    }

    /// A file with a second name that the change reaches stops it, unless
    /// `links` lets it pass; one in a part that stays is not looked at. A
    /// walk that writes stops there and writes no folder above it, and the
    /// folder's own list is not written either. A path that no longer leads
    /// to the file passes nothing. Without `links`, every file passes and
    /// none is looked up by its path.
    #[test]
    fn a_file_with_a_second_name_stops_the_change() {
        let tree = &["a/", "a/x", "a/y=", "a/z", "b/", "b/l="];
        let asked = std::cell::RefCell::new(Vec::new());
        let mut refuse = |p: &Path, n: u32| {
            asked.borrow_mut().push((p.to_path_buf(), n));
            Ok(false)
        };

        // Looked at only.
        let mut f = Fake::new(tree);
        let (_, found) = f.grant_with(&["g"], false, false, Some(&mut refuse), &mut |_| {});
        assert_eq!(found, Some((PathBuf::from("/top/a/y"), 2)));
        assert!(f.written.is_empty() && f.has("a/x").is_empty());

        // Changed: what was written before stays, nothing above it.
        let mut f = Fake::new(tree);
        let (_, found) = f.grant_with(&["g"], false, true, Some(&mut refuse), &mut |_| {});
        assert_eq!(found, Some((PathBuf::from("/top/a/y"), 2)));
        assert_eq!(f.written, ["a/x"]);
        assert!(f.nodes[0].own.is_empty(), "the folder itself stays");

        // Let pass.
        let mut f = Fake::new(tree);
        let (w, found) = f.grant_with(&["g"], false, true, Some(&mut |_, _| Ok(true)), &mut |_| {});
        assert_eq!(found, None);
        assert_eq!(w.changed, 6);

        // Where the part with the links stays, they are not looked at.
        let mut f = Fake::new(tree);
        f.grant(&["g"], false);
        f.node("a").own.insert("mine".into());
        asked.borrow_mut().clear();
        let (_, found) = f.grant_with(&["g"], false, true, Some(&mut refuse), &mut |_| {});
        assert_eq!(found, None);
        assert!(asked.borrow().is_empty());

        // Moved meanwhile: refused without asking.
        let mut f = Fake::new(tree);
        f.moved.push("a/y".into());
        let (_, found) = f.grant_with(
            &["g"],
            false,
            false,
            Some(&mut |_, _| Ok(true)),
            &mut |_| {},
        );
        assert_eq!(found, Some((PathBuf::from("/top/a/y"), 2)));
        let (w, found) = f.grant_with(&["g"], false, true, None, &mut |_| {});
        assert_eq!(found, None);
        assert_eq!(w.changed, 6);
    }

    /// The progress is told every [`STEP`] objects.
    #[test]
    fn the_progress_is_told_now_and_then() {
        let names: Vec<String> = (0..STEP * 2 + 10).map(|i| format!("f{i}")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut f = Fake::new(&refs);
        let mut told = Vec::new();
        f.grant_with(&["g"], false, true, None, &mut |w| told.push(w));
        assert_eq!(
            told,
            [
                Walked {
                    seen: STEP,
                    changed: STEP
                },
                Walked {
                    seen: STEP * 2,
                    changed: STEP * 2
                }
            ]
        );
    }
}
