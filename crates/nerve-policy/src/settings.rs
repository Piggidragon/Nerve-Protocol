//! The settings store: `node.toml` with a version, written by the owner (CLI,
//! control socket) and, with the settings grant `write`, by a center for its
//! own [`CenterDocument`] (architecture §5.2, §5.3; spec §7.4).
//!
//! Every change is whole-document with `if_version`, so two writers never
//! overwrite each other unseen, is validated before it is saved, and lands in
//! the audit log with its old and new values and who made it.
//!
//! The node keeps the config in memory and signs every file it writes with a
//! MAC whose key no command of a center can read. The file is read at start-up
//! and when the owner asks for it; a file the node did not sign (one a command
//! rewrote, say) is refused, audited, and changes nothing.

use std::path::{Path, PathBuf};

use nerve_transport::keys::MacKey;
use serde_json::Value;

use crate::audit::{AuditLog, diff};
use crate::config::{
    Access, CapSetting, CenterDocument, Folder, NodeConfig, ProtectedOptions, SettingsGrant, Sudo,
};
use crate::paths::to_wire;
use crate::protected::Protected;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetError {
    /// `if_version` is not the current version.
    Conflict { current: u64 },
    /// A client-only field changed, or the center has no settings grant.
    Forbidden(String),
    /// The new document does not parse or validate.
    Invalid(String),
    /// Saving failed.
    Io(String),
}

impl std::fmt::Display for SetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SetError::Conflict { current } => {
                write!(f, "the settings changed; the current version is {current}")
            }
            SetError::Forbidden(s) | SetError::Invalid(s) | SetError::Io(s) => write!(f, "{s}"),
        }
    }
}

/// Who changes the settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Writer<'a> {
    Local,
    Center(&'a str),
}

impl Writer<'_> {
    pub fn label(&self) -> String {
        match self {
            Writer::Local => "local".into(),
            Writer::Center(n) => format!("center {n}"),
        }
    }
}

/// The first line of a `node.toml` the node wrote: the MAC over the rest of
/// the file, then a note for whoever opens it.
const MAC_LINE: &str = "# mac hmac-sha256 ";
const MAC_NOTE: &str = " (nerve-node refuses this file once it is changed outside nerve-node)";

/// Goes into the MAC before the text, so the key signs nothing but a config.
const MAC_CONTEXT: &[u8] = b"nerve node.toml\n";

fn mac_input(body: &str) -> Vec<u8> {
    [MAC_CONTEXT, body.as_bytes()].concat()
}

/// The file the node writes for `c`: the MAC line, then the TOML.
fn sealed(key: &MacKey, c: &NodeConfig) -> String {
    let body = c.to_toml();
    let mac = key.sign(&mac_input(&body));
    format!("{MAC_LINE}{mac}{MAC_NOTE}\n{body}")
}

/// A file's MAC (when its first line is a MAC line) and the TOML after it.
fn unseal(text: &str) -> (Option<&str>, &str) {
    match text.strip_prefix(MAC_LINE) {
        Some(rest) => {
            let (line, body) = rest.split_once('\n').unwrap_or((rest, ""));
            (Some(line.split(' ').next().unwrap_or_default()), body)
        }
        None => (None, text),
    }
}

/// `text` as a config, when the node signed it with `key`.
fn verified(text: &str, key: &MacKey) -> Result<NodeConfig, String> {
    match unseal(text) {
        (None, _) => Err("it carries no MAC, so nerve-node did not write it".into()),
        (Some(mac), body) if !key.verify(&mac_input(body), mac) => {
            Err("its MAC does not match, so it was changed outside nerve-node".into())
        }
        (Some(_), body) => NodeConfig::parse(body),
    }
}

/// The file's text; `None` when there is no file.
fn read_file(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(t) => Ok(Some(t)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

pub struct SettingsStore {
    path: PathBuf,
    key: MacKey,
    audit: AuditLog,
    config: NodeConfig,
}

impl SettingsStore {
    /// Loads `path` (a missing file is the default config) and checks its MAC
    /// with the key at `key_path`. A file whose MAC does not match is refused
    /// and audited. The key is made when there is none; a file from before
    /// the node kept a MAC is then taken once, as it is, and signed.
    pub fn open(
        path: impl Into<PathBuf>,
        key_path: impl AsRef<Path>,
        audit: AuditLog,
    ) -> Result<SettingsStore, String> {
        let path = path.into();
        let text = read_file(&path)?;
        let first = MacKey::load(key_path.as_ref())?.is_none();
        let key = MacKey::load_or_create(key_path.as_ref())?;
        let mut s = SettingsStore {
            path,
            key,
            audit,
            config: NodeConfig::default(),
        };
        let Some(text) = text else {
            return Ok(s);
        };
        if first && unseal(&text).0.is_none() {
            let c = NodeConfig::parse(&text).map_err(|e| format!("{}: {e}", s.path.display()))?;
            s.write(&c)?;
            s.config = c;
            let _ = s.audit.config(
                "signed",
                &s.path,
                "written before the node kept a MAC; signed as it was",
            );
            return Ok(s);
        }
        s.config = verified(&text, &s.key).map_err(|why| s.refuse(&why))?;
        Ok(s)
    }

    /// Opens the store for `nerve-node config accept` while no daemon runs:
    /// the file is taken as it is ([`SettingsStore::accept`]).
    pub fn open_accepting(
        path: impl Into<PathBuf>,
        key_path: impl AsRef<Path>,
        audit: AuditLog,
    ) -> Result<(SettingsStore, u64), String> {
        let mut s = SettingsStore {
            path: path.into(),
            key: MacKey::load_or_create(key_path.as_ref())?,
            audit,
            config: NodeConfig::default(),
        };
        let v = s.accept().map_err(|e| e.to_string())?;
        Ok((s, v))
    }

    /// The config at `path` as [`SettingsStore::open`] would take it, without
    /// writing anything (what the CLI shows while no daemon runs).
    pub fn peek(path: &Path, key_path: &Path) -> Result<NodeConfig, String> {
        let Some(text) = read_file(path)? else {
            return Ok(NodeConfig::default());
        };
        let refused = |why: String| {
            format!(
                "{} is refused: {why}; check it, then `nerve-node config accept` takes it as it is",
                path.display()
            )
        };
        match MacKey::load(key_path)? {
            Some(key) => verified(&text, &key).map_err(refused),
            // The node signs such a file the first time it opens it.
            None if unseal(&text).0.is_none() => {
                NodeConfig::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
            }
            None => Err(refused(
                "it is signed with a key this node does not have".into(),
            )),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    pub fn version(&self) -> u64 {
        self.config.version
    }

    /// Reads the file again because the owner asks (SIGHUP, the control
    /// socket's `reload`). Only a file the node signed is applied, and never
    /// an older version than the one in force; anything else is refused and
    /// audited, and the old config stays in force.
    pub fn reload(&mut self) -> Result<bool, String> {
        let text = read_file(&self.path)?.ok_or_else(|| self.refuse("the file is missing"))?;
        let fresh = verified(&text, &self.key).map_err(|why| self.refuse(&why))?;
        if fresh.version < self.config.version {
            return Err(self.refuse(&format!(
                "its version {} is older than the one in force ({})",
                fresh.version, self.config.version
            )));
        }
        let changed = fresh != self.config;
        self.config = fresh;
        Ok(changed)
    }

    /// Takes the file as it is now, after the node refused it (`nerve-node
    /// config accept`: the owner has looked at it). Its MAC is not checked;
    /// it must still parse and validate, and the node signs it.
    pub fn accept(&mut self) -> Result<u64, SetError> {
        let missing = || SetError::Invalid(format!("{} is missing", self.path.display()));
        let text = read_file(&self.path)
            .map_err(SetError::Io)?
            .ok_or_else(missing)?;
        let mut new = NodeConfig::parse(unseal(&text).1)
            .map_err(|e| SetError::Invalid(format!("{}: {e}", self.path.display())))?;
        new.version = self.config.version.max(new.version) + 1;
        self.write(&new).map_err(SetError::Io)?;
        let changes = diff(&to_json(&self.config), &to_json(&new));
        let version = new.version;
        self.config = new;
        let _ = self
            .audit
            .config("accepted", &self.path, "the owner took the file as it was");
        let _ = self
            .audit
            .settings(&Writer::Local.label(), version, &changes);
        Ok(version)
    }

    /// Audits a refused file and says why it was refused.
    fn refuse(&self, why: &str) -> String {
        // The refusal stands even when the audit log cannot be written.
        let _ = self.audit.config("refused", &self.path, why);
        format!(
            "{} is refused: {why}; check it, then `nerve-node config accept` takes it as it is",
            self.path.display()
        )
    }

    /// Writes `c` atomically, signed.
    fn write(&self, c: &NodeConfig) -> Result<(), String> {
        if let Some(dir) = self.path.parent() {
            nerve_transport::files::create_private_dir(dir)
                .map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        nerve_transport::files::write_private(&self.path, sealed(&self.key, c).as_bytes())
            .map_err(|e| format!("{}: {e}", self.path.display()))
    }

    /// Replaces the whole config as the owner; `if_version` guards against a
    /// concurrent writer.
    pub fn set_local(&mut self, new: NodeConfig, if_version: Option<u64>) -> Result<u64, SetError> {
        if let Some(v) = if_version
            && v != self.config.version
        {
            return Err(SetError::Conflict {
                current: self.config.version,
            });
        }
        self.commit(Writer::Local, new)
    }

    /// Changes the config as the owner through a closure (CLI commands).
    pub fn update(
        &mut self,
        f: impl FnOnce(&mut NodeConfig) -> Result<(), String>,
    ) -> Result<u64, SetError> {
        let mut new = self.config.clone();
        f(&mut new).map_err(SetError::Invalid)?;
        self.commit(Writer::Local, new)
    }

    /// Updates bookkeeping the node itself sets (revoked, unknown) without
    /// counting it as a settings change by anyone.
    pub fn mark(&mut self, f: impl FnOnce(&mut NodeConfig)) -> Result<(), String> {
        let mut new = self.config.clone();
        f(&mut new);
        if new == self.config {
            return Ok(());
        }
        new.version = self.config.version + 1;
        self.write(&new)?;
        self.config = new;
        Ok(())
    }

    /// The document `settings.get` shows `center`.
    pub fn center_document(&self, center: &str) -> Option<CenterDocument> {
        self.config.center(center).map(|c| CenterDocument {
            paused: c.paused,
            policy: c.policy.clone(),
        })
    }

    /// `settings.set` from `center`: the whole document, checked against
    /// `if_version`. `is_sense(cap)` says whether a capability senses
    /// (camera, microphone, screen): only the owner may turn those on.
    /// `protected(opts)` is this node's protected list with a center's
    /// options: only the owner may release an entry of it.
    pub fn set_center_document(
        &mut self,
        center: &str,
        document: Value,
        if_version: u64,
        is_sense: impl Fn(&str) -> bool,
        protected: impl Fn(&ProtectedOptions) -> Protected,
    ) -> Result<u64, SetError> {
        let entry = self
            .config
            .center(center)
            .ok_or_else(|| SetError::Forbidden(format!("no center {center}")))?;
        if entry.settings != SettingsGrant::Write {
            return Err(SetError::Forbidden(
                "this node does not let this center change its settings".into(),
            ));
        }
        if if_version != self.config.version {
            return Err(SetError::Conflict {
                current: self.config.version,
            });
        }
        let mut new: CenterDocument =
            serde_json::from_value(document).map_err(|e| SetError::Invalid(e.to_string()))?;
        new.policy
            .validate()
            .map_err(|e| SetError::Invalid(e.to_string()))?;
        let old = CenterDocument {
            paused: entry.paused,
            policy: entry.policy.clone(),
        };
        client_only(&old, &new, &is_sense, &protected).map_err(SetError::Forbidden)?;
        let mut cfg = self.config.clone();
        let e = cfg.center_mut(center).expect("checked above");
        e.paused = new.paused;
        e.policy = new.policy;
        self.commit(Writer::Center(center), cfg)
    }

    /// Sets the node's sudo switch: the one machine setting a center with the
    /// `write` grant may change. The caller has checked the password before
    /// it turns the switch on.
    pub fn set_sudo(&mut self, by: Writer, sudo: Sudo) -> Result<u64, SetError> {
        if let Writer::Center(center) = by {
            let entry = self
                .config
                .center(center)
                .ok_or_else(|| SetError::Forbidden(format!("no center {center}")))?;
            if entry.settings != SettingsGrant::Write {
                return Err(SetError::Forbidden(
                    "this node does not let this center change its settings".into(),
                ));
            }
        }
        let mut cfg = self.config.clone();
        cfg.machine.sudo = sudo;
        self.commit(by, cfg)
    }

    fn commit(&mut self, by: Writer, mut new: NodeConfig) -> Result<u64, SetError> {
        new.version = self.config.version;
        new.validate().map_err(SetError::Invalid)?;
        if new == self.config {
            return Ok(self.config.version);
        }
        new.version = self.config.version + 1;
        self.write(&new).map_err(SetError::Io)?;
        let changes = diff(&to_json(&self.config), &to_json(&new));
        let version = new.version;
        self.config = new;
        // The change is saved; an audit log that cannot be written is logged
        // by the caller's tracing, not a reason to undo it.
        let _ = self.audit.settings(&by.label(), version, &changes);
        Ok(version)
    }
}

fn to_json(c: &NodeConfig) -> Value {
    let mut v = serde_json::to_value(c).expect("the node config serializes");
    if let Some(o) = v.as_object_mut() {
        o.remove("version");
    }
    v
}

/// The fields of its own document a center may not change (architecture
/// §5.3). The whole document is refused, naming the first such field.
fn client_only(
    old: &CenterDocument,
    new: &CenterDocument,
    is_sense: &dyn Fn(&str) -> bool,
    protected: &dyn Fn(&ProtectedOptions) -> Protected,
) -> Result<(), String> {
    if old.paused && !new.paused {
        return Err("paused: only the owner can unpause".into());
    }
    let (o, n) = (&old.policy, &new.policy);
    for (key, setting) in &n.caps {
        let cap = key.split('.').next().unwrap_or(key);
        if *setting == CapSetting::On && o.caps.get(key) != Some(&CapSetting::On) && is_sense(cap) {
            return Err(format!(
                "policy.caps.{key}: only the owner can turn sensing on"
            ));
        }
    }
    // An allow rule would let a sense capability through in allowlist mode,
    // whatever `caps` says; so adding one for it is the owner's call as well.
    for rule in n.allow.iter().filter(|r| !o.allow.contains(r)) {
        let scope = rule.split(':').next().unwrap_or(rule);
        if is_sense(scope.split('.').next().unwrap_or(scope)) {
            return Err(format!(
                "policy.allow {rule}: only the owner can turn sensing on"
            ));
        }
    }
    if n.protected.allow != o.protected.allow {
        // Releasing a protected path is the owner's call; adding more is fine.
        return Err("policy.protected.allow: only the owner can release protected paths".into());
    }
    // Extra protected paths hold in User mode too: dropping one is a release
    // as well.
    if let Some(gone) = o
        .protected
        .extra
        .iter()
        .find(|p| !n.protected.extra.contains(p))
    {
        return Err(format!(
            "policy.protected.extra {gone}: only the owner can release protected paths"
        ));
    }
    // A folder at or inside a protected entry releases it (Protected::check),
    // and the deepest folder there gives that place its flags. So at every
    // place where the access may change, each old and each new folder, the
    // new folders may give a protected place no flag the old ones did not:
    // no release where the old folders released nothing, and no wider access
    // where they did. Places are compared by path with the list's own rules,
    // so neither another spelling of the owner's folder, nor a folder inside
    // it, nor dropping a narrower one inside it widens anything.
    let prot = protected(&n.protected);
    for place in n.folders.iter().chain(&o.folders) {
        let path = Path::new(&place.path);
        let Some(entry) = prot.check(path, true, &[]) else {
            continue;
        };
        // The flags the deepest folder at or inside the entry gives `path`.
        let given = |folders: &[Folder]| {
            prot.deepest(folders, path)
                .filter(|f| prot.holds(entry, Path::new(&f.path)))
                .map(|f| f.access)
        };
        // The node's own folders are never released, whatever a folder says.
        let before = given(&o.folders).filter(|_| prot.own(path).is_none());
        let why = match (before, given(&n.folders)) {
            (None, Some(_)) => "only the owner can release protected paths",
            (Some(old), Some(new)) if widens(old, new) => {
                "only the owner can widen the access of a folder there"
            }
            _ => continue,
        };
        return Err(format!(
            "policy.folders {}: {} is protected; {why}",
            place.path,
            to_wire(entry)
        ));
    }
    // Landlock follows a link, so a folder is also judged where it really
    // leads: a new or wider one that is, or passes through, a link into a
    // protected entry needs the owner's folders to release that place with
    // its flags. A folder the old document had with the same or more
    // access changes nothing here; one that became a link since is left
    // out of the command's sandbox (`exec::landlock_spec`).
    for f in &n.folders {
        let kept = o
            .folders
            .iter()
            .any(|g| g.path == f.path && !widens(g.access, f.access));
        if kept {
            continue;
        }
        if let Err(why) = prot.real_folder(f, &o.folders) {
            return Err(format!(
                "policy.folders {}: {why}; only the owner can release protected paths",
                f.path
            ));
        }
    }
    Ok(())
}

/// Whether `new` sets a flag `old` does not.
fn widens(old: Access, new: Access) -> bool {
    (new.read && !old.read) || (new.write && !old.write) || (new.execute && !old.execute)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CenterEntry, CenterPolicy, Mode};
    use serde_json::json;

    fn store(dir: &Path, grant: SettingsGrant) -> SettingsStore {
        let mut s = SettingsStore::open(
            dir.join("node.toml"),
            dir.join("config.key"),
            AuditLog::new(dir.join("audit.jsonl")),
        )
        .unwrap();
        s.update(|c| {
            c.centers.push(CenterEntry {
                name: "home".into(),
                url: "https://center.example".into(),
                pin: None,
                center_id: "c".into(),
                node_id: "n".into(),
                settings: grant,
                paused: false,
                revoked: false,
                unknown: false,
                policy: CenterPolicy::default(),
            });
            Ok(())
        })
        .unwrap();
        s
    }

    /// The protected list of a Unix node at `/home/u`.
    fn unix(opts: &ProtectedOptions) -> Protected {
        Protected::new(
            &crate::protected::Platform::Unix,
            Path::new("/home/u"),
            &[],
            opts,
        )
    }

    /// A home that is absolute on the platform the tests run on, so a
    /// folder below it passes validation there and reaches the check under
    /// test (Windows refuses `/home/u` as not absolute).
    fn host_home() -> PathBuf {
        PathBuf::from(if cfg!(windows) {
            "C:\\Users\\u"
        } else {
            "/home/u"
        })
    }

    /// `rel` (with `/`) below [`host_home`], in the platform's own form.
    fn at_home(rel: &str) -> PathBuf {
        rel.split('/').fold(host_home(), |p, seg| p.join(seg))
    }

    /// The protected list of a node at [`host_home`] on this platform.
    fn host(opts: &ProtectedOptions) -> Protected {
        let platform = if cfg!(windows) {
            crate::protected::Platform::Windows(Default::default())
        } else {
            crate::protected::Platform::Unix
        };
        Protected::new(&platform, &host_home(), &[], opts)
    }

    fn doc(s: &SettingsStore) -> Value {
        serde_json::to_value(s.center_document("home").unwrap()).unwrap()
    }

    #[test]
    fn only_a_writing_center_switches_sudo() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), SettingsGrant::Off);
        assert!(matches!(
            s.set_sudo(Writer::Center("home"), Sudo::On),
            Err(SetError::Forbidden(_))
        ));
        assert_eq!(s.config().machine.sudo, Sudo::Off);
        s.set_sudo(Writer::Local, Sudo::On).unwrap();
        assert_eq!(s.config().machine.sudo, Sudo::On);
        let mut s = store(&d.path().join("w"), SettingsGrant::Write);
        let v = s.set_sudo(Writer::Center("home"), Sudo::On).unwrap();
        assert_eq!(s.version(), v);
        let log = s.audit().read().unwrap();
        let last = log.last().unwrap();
        assert_eq!(last["by"], "center home");
        assert!(
            last["changes"].to_string().contains("machine.sudo"),
            "{last}"
        );
    }

    #[test]
    fn center_sets_with_version_and_audit() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), SettingsGrant::Write);
        let v = s.version();
        let mut new = doc(&s);
        new["policy"]["mode"] = json!("user");
        new["policy"]["until"] = json!(1000);
        let v2 = s
            .set_center_document("home", new.clone(), v, |_| false, unix)
            .unwrap();
        assert_eq!(v2, v + 1);
        assert_eq!(s.config().center("home").unwrap().policy.mode, Mode::User);
        // A stale version conflicts.
        assert_eq!(
            s.set_center_document("home", new, v, |_| false, unix),
            Err(SetError::Conflict { current: v2 })
        );
        // Saved and reloaded.
        let again = SettingsStore::open(
            d.path().join("node.toml"),
            d.path().join("config.key"),
            AuditLog::new(d.path().join("a")),
        )
        .unwrap();
        assert_eq!(again.version(), v2);
        let log = s.audit().read().unwrap();
        let last = log.last().unwrap();
        assert_eq!(last["by"], "center home");
        assert_eq!(last["changes"][0]["key"], "center");
    }

    #[test]
    fn refuses_client_only_fields_and_missing_grant() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), SettingsGrant::Write);
        let v = s.version();
        let mut new = doc(&s);
        new["policy"]["caps"] = json!({"camera": "on"});
        let e = s
            .set_center_document("home", new, v, |c| c == "camera", unix)
            .unwrap_err();
        assert!(matches!(&e, SetError::Forbidden(m) if m.contains("policy.caps.camera")));
        // An allow rule is no way round that.
        let mut new = doc(&s);
        new["policy"]["allow"] = json!(["camera.snap"]);
        let e = s
            .set_center_document("home", new, v, |c| c == "camera", unix)
            .unwrap_err();
        assert!(matches!(&e, SetError::Forbidden(m) if m.contains("policy.allow")));
        let mut new = doc(&s);
        new["policy"]["allow"] = json!(["fs.read:/a/*", "exec.run:ls"]);
        s.set_center_document("home", new, v, |c| c == "camera", unix)
            .unwrap();
        let v = s.version();
        let mut new = doc(&s);
        new["policy"]["protected"] = json!({"allow": ["~/.ssh"]});
        assert!(matches!(
            s.set_center_document("home", new, v, |_| false, unix),
            Err(SetError::Forbidden(_))
        ));
        let mut new = doc(&s);
        new["policy"]["nope"] = json!(1);
        assert!(matches!(
            s.set_center_document("home", new, v, |_| false, unix),
            Err(SetError::Invalid(_))
        ));
        // The center may pause, not unpause.
        let mut new = doc(&s);
        new["paused"] = json!(true);
        let v = s
            .set_center_document("home", new, v, |_| false, unix)
            .unwrap();
        let mut new = doc(&s);
        new["paused"] = json!(false);
        assert!(matches!(
            s.set_center_document("home", new, v, |_| false, unix),
            Err(SetError::Forbidden(_))
        ));
        assert_eq!(s.version(), v);

        let d2 = tempfile::tempdir().unwrap();
        let mut off = store(d2.path(), SettingsGrant::Off);
        let v = off.version();
        let new = doc(&off);
        assert!(matches!(
            off.set_center_document("home", new, v, |_| false, unix),
            Err(SetError::Forbidden(_))
        ));
    }

    /// The owner's extra protected paths hold in User mode too; a center may
    /// add one but never take one away.
    #[test]
    fn a_center_cannot_drop_an_owner_protected_path() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), SettingsGrant::Write);
        s.update(|c| {
            let p = &mut c.center_mut("home").unwrap().policy;
            p.mode = Mode::User;
            p.protected.extra = vec!["~/secret".into()];
            Ok(())
        })
        .unwrap();
        let v = s.version();
        let mut new = doc(&s);
        new["policy"]["protected"]["extra"] = json!([]);
        let e = s.set_center_document("home", new, v, |_| false, unix);
        assert!(
            matches!(&e, Err(SetError::Forbidden(m)) if m.contains("policy.protected.extra")),
            "{e:?}"
        );
        assert_eq!(
            s.config().center("home").unwrap().policy.protected.extra,
            ["~/secret"]
        );
        // Adding one more is fine.
        let mut new = doc(&s);
        new["policy"]["protected"]["extra"] = json!(["~/secret", "~/more"]);
        s.set_center_document("home", new, v, |_| false, unix)
            .unwrap();
        assert_eq!(
            s.config().center("home").unwrap().policy.protected.extra,
            ["~/secret", "~/more"]
        );
    }

    /// A folder at or inside a protected entry releases it, so adding one is
    /// a release as well: a center may not, the owner may (code review 2 of
    /// PR #19, finding 2). The paths are this platform's own, so the check
    /// runs on Windows as well (Windows review round 3, finding 1).
    #[test]
    fn a_center_cannot_release_a_protected_path_by_adding_a_folder() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), SettingsGrant::Write);
        s.update(|c| {
            let p = &mut c.center_mut("home").unwrap().policy;
            p.mode = Mode::User;
            p.protected.extra = vec!["~/secret".into()];
            Ok(())
        })
        .unwrap();
        let v = s.version();
        let shown = |rel: &str| to_wire(&at_home(rel)).to_lowercase();
        for (path, entry) in [
            ("secret", "secret"),
            ("secret/inner", "secret"),
            (".ssh", ".ssh"),
            (".local/bin", ".local/bin"),
        ] {
            let mut new = doc(&s);
            new["policy"]["folders"] = json!([{"path": at_home(path), "access": "r"}]);
            let e = s.set_center_document("home", new, v, |_| false, host);
            assert!(
                matches!(&e, Err(SetError::Forbidden(m))
                    if m.contains("policy.folders") && m.to_lowercase().contains(&shown(entry))),
                "{path}: {e:?}"
            );
        }
        assert!(s.config().center("home").unwrap().policy.folders.is_empty());
        // Spellings that would slip past the check and then match nothing
        // are no folder path at all (Windows review round 3, finding 5).
        let odd: &[&str] = if cfg!(windows) {
            &[
                "C:\\Users\\U~1\\.ssh",
                "C:\\Users\\u\\.ssh.",
                "C:\\Users\\u\\.ssh ",
                "C:\\Users\\u\\x\\..\\.ssh",
            ]
        } else {
            &["/home/u/x/../.ssh"]
        };
        for path in odd {
            let mut new = doc(&s);
            new["policy"]["folders"] = json!([{"path": path, "access": "r"}]);
            let e = s.set_center_document("home", new, v, |_| false, host);
            assert!(
                matches!(&e, Err(SetError::Invalid(m)) if m.contains("use the full name")),
                "{path}: {e:?}"
            );
        }
        // A folder that holds a protected entry releases nothing.
        let mut new = doc(&s);
        new["policy"]["folders"] = json!([{"path": host_home(), "access": "rw"}]);
        s.set_center_document("home", new, v, |_| false, host)
            .unwrap();
        // The owner may release it.
        s.update(|c| {
            let p = &mut c.center_mut("home").unwrap().policy;
            p.folders.push(crate::config::Folder {
                path: at_home("secret").to_string_lossy().into_owned(),
                access: crate::config::Access::parse("r").unwrap(),
            });
            Ok(())
        })
        .unwrap();
        // Inside what the owner released a center may add a folder, but it
        // may not widen the owner's folder there.
        let v = s.version();
        let mut new = doc(&s);
        new["policy"]["folders"]
            .as_array_mut()
            .unwrap()
            .push(json!({"path": at_home("secret/inner"), "access": "r"}));
        let v = s
            .set_center_document("home", new, v, |_| false, host)
            .unwrap();
        let mut new = doc(&s);
        new["policy"]["folders"][1]["access"] = json!("rw");
        let e = s.set_center_document("home", new, v, |_| false, host);
        let named = format!("policy.folders {}", at_home("secret").display());
        assert!(
            matches!(&e, Err(SetError::Forbidden(m)) if m.contains(&named)),
            "{e:?}"
        );
    }

    fn acc(s: &str) -> Access {
        Access::parse(s).unwrap()
    }

    fn folder(path: &str, access: &str) -> crate::config::Folder {
        crate::config::Folder {
            path: path.into(),
            access: acc(access),
        }
    }

    /// Folder mode, with the owner's `folders`.
    fn owner_folders(dir: &Path, folders: &[(&str, &str)]) -> SettingsStore {
        let mut s = store(dir, SettingsGrant::Write);
        s.update(|c| {
            let p = &mut c.center_mut("home").unwrap().policy;
            p.mode = Mode::Folder;
            p.folders = folders.iter().map(|(f, a)| folder(f, a)).collect();
            Ok(())
        })
        .unwrap();
        s
    }

    /// The decision on writing `file` under the center's policy now.
    fn write_to(s: &SettingsStore, file: &Path) -> crate::decide::Decision {
        let policy = &s.config().center("home").unwrap().policy;
        let prot = host(&policy.protected);
        let home = host_home();
        let env = crate::decide::Env {
            home: &home,
            protected: &prot,
            confined: true,
            sudo: false,
        };
        let targets = [crate::decide::Target {
            path: file.into(),
            write: true,
        }];
        let call = crate::decide::Call {
            cap: "fs",
            action: "write",
            effect: nerve_proto::Effect::Write,
            targets: &targets,
            command: None,
            cwd: None,
            now_ms: 0,
        };
        crate::decide::decide(policy, &env, &call)
    }

    fn with_folders(s: &SettingsStore, folders: Value) -> Value {
        let mut new = doc(s);
        new["policy"]["folders"] = folders;
        new
    }

    /// `rel` (with `/`) below [`host_home`], as the string a folder is
    /// given by. These tests use this platform's own paths, so the check
    /// under test runs on Windows as well (Windows final round, finding 1).
    fn home_str(rel: &str) -> String {
        at_home(rel).to_string_lossy().into_owned()
    }

    /// The owner released `~/.ssh` read-only; another spelling of that
    /// folder gives a center no more (security review 3 of PR #19,
    /// finding 1).
    #[test]
    fn a_center_cannot_widen_a_protected_folder_by_another_spelling() {
        let d = tempfile::tempdir().unwrap();
        let ssh = home_str(".ssh");
        let mut s = owner_folders(d.path(), &[(&ssh, "r")]);
        let keys = at_home(".ssh/authorized_keys");
        assert!(matches!(
            write_to(&s, &keys),
            crate::decide::Decision::Forbidden(_)
        ));
        let v = s.version();
        let home = host_home().to_string_lossy().into_owned();
        let mut spellings = vec![format!("{home}/.ssh/"), format!("{home}//.ssh")];
        if cfg!(windows) {
            // Windows ignores case and takes either separator; it refuses a
            // `.` part as a name that ends in a dot.
            spellings.push("c:/users/u/.SSH".into());
        } else {
            spellings.push(format!("{home}/./.ssh"));
        }
        for spelling in &spellings {
            // Next to the owner's folder ...
            let both = json!([{"path": ssh, "access": "r"},
                {"path": spelling, "access": "rw"}]);
            let e = s.set_center_document("home", with_folders(&s, both), v, |_| false, host);
            assert!(e.is_err(), "{spelling}: {e:?}");
            // ... or in its place.
            let only = json!([{"path": spelling, "access": "rw"}]);
            let e = s.set_center_document("home", with_folders(&s, only), v, |_| false, host);
            assert!(
                matches!(&e, Err(SetError::Forbidden(m)) if m.to_lowercase().contains(&ssh.to_lowercase())),
                "{spelling}: {e:?}"
            );
        }
        assert_eq!(s.version(), v);
        assert!(matches!(
            write_to(&s, &keys),
            crate::decide::Decision::Forbidden(_)
        ));
        // A folder elsewhere is the center's to add, in any spelling; it is
        // kept in one form, and the protected file stays refused.
        let work = home_str("work");
        let elsewhere = json!([{"path": ssh, "access": "r"},
            {"path": format!("{work}/"), "access": "rw"}]);
        let v = s
            .set_center_document("home", with_folders(&s, elsewhere), v, |_| false, host)
            .unwrap();
        let folders = &s.config().center("home").unwrap().policy.folders;
        assert_eq!(folders[1].path, work);
        assert_eq!(
            write_to(&s, &at_home("work/a")),
            crate::decide::Decision::Allow
        );
        assert!(matches!(
            write_to(&s, &keys),
            crate::decide::Decision::Forbidden(_)
        ));
        // The owner may widen it, in their own spelling.
        s.update(|c| {
            let p = &mut c.center_mut("home").unwrap().policy;
            p.folders[0] = folder(&format!("{ssh}/"), "rw");
            Ok(())
        })
        .unwrap();
        assert!(s.version() > v);
        let folders = &s.config().center("home").unwrap().policy.folders;
        assert_eq!(folders[0].path, ssh);
        assert_eq!(write_to(&s, &keys), crate::decide::Decision::Allow);
    }

    /// A folder inside the owner's read-only `~/.ssh` gets no flag the
    /// owner's folder lacks (security review 3 of PR #19, finding 1).
    #[test]
    fn a_center_cannot_widen_a_protected_folder_by_an_inner_one() {
        let d = tempfile::tempdir().unwrap();
        let (ssh, inner) = (home_str(".ssh"), home_str(".ssh/inner"));
        let mut s = owner_folders(d.path(), &[(&ssh, "r")]);
        let v = s.version();
        for access in ["rwx", "rw", "w", "x", "rx"] {
            let wider = json!([{"path": ssh, "access": "r"},
                {"path": inner, "access": access}]);
            let e = s.set_center_document("home", with_folders(&s, wider), v, |_| false, host);
            let named = format!("policy.folders {inner}");
            assert!(
                matches!(&e, Err(SetError::Forbidden(m)) if m.contains(&named)),
                "{access}: {e:?}"
            );
        }
        assert_eq!(s.version(), v);
        assert!(matches!(
            write_to(&s, &at_home(".ssh/inner/x")),
            crate::decide::Decision::Forbidden(_)
        ));
        // As narrow as the owner's folder, or narrower, is fine.
        let narrow = json!([{"path": ssh, "access": "r"},
            {"path": format!("{inner}/"), "access": "r"}]);
        s.set_center_document("home", with_folders(&s, narrow), v, |_| false, host)
            .unwrap();
        assert!(matches!(
            write_to(&s, &at_home(".ssh/inner/x")),
            crate::decide::Decision::Forbidden(_)
        ));
    }

    /// The owner's narrower folder inside a protected entry stays: dropping
    /// it would hand that place the wider access of the folder around it.
    #[test]
    fn a_center_cannot_widen_a_protected_place_by_dropping_a_folder() {
        let d = tempfile::tempdir().unwrap();
        let (ssh, keys) = (home_str(".ssh"), home_str(".ssh/keys"));
        let mut s = owner_folders(d.path(), &[(&ssh, "rw"), (&keys, "r")]);
        let v = s.version();
        let dropped = json!([{"path": ssh, "access": "rw"}]);
        let e = s.set_center_document("home", with_folders(&s, dropped), v, |_| false, host);
        let named = format!("policy.folders {keys}");
        assert!(
            matches!(&e, Err(SetError::Forbidden(m)) if m.contains(&named)),
            "{e:?}"
        );
        assert!(matches!(
            write_to(&s, &at_home(".ssh/keys/id")),
            crate::decide::Decision::Forbidden(_)
        ));
        // Dropping the outer one narrows.
        let outer = json!([{"path": keys, "access": "r"}]);
        s.set_center_document("home", with_folders(&s, outer), v, |_| false, host)
            .unwrap();
    }

    /// The same checks on Windows paths, which ignore case and take either
    /// separator. `client_only` goes by the protected list's platform, so
    /// this runs everywhere.
    #[test]
    fn windows_spellings_of_a_protected_folder_widen_nothing() {
        let win = |opts: &ProtectedOptions| {
            Protected::new(
                &crate::protected::Platform::Windows(Default::default()),
                Path::new("C:\\Users\\u"),
                &[],
                opts,
            )
        };
        let policy = |folders: &[(&str, &str)]| CenterDocument {
            paused: false,
            policy: CenterPolicy {
                mode: Mode::Folder,
                folders: folders.iter().map(|(f, a)| folder(f, a)).collect(),
                ..Default::default()
            },
        };
        let old = policy(&[("C:\\Users\\u\\.ssh", "r")]);
        let check = |new: &[(&str, &str)]| client_only(&old, &policy(new), &|_| false, &win);
        for new in [
            &[("C:\\Users\\u\\.ssh", "r"), ("C:\\Users\\u\\.ssh\\", "rw")][..],
            &[("c:/users/u/.ssh", "rw")][..],
            &[("C:\\Users\\u\\.SSH\\\\", "rw")][..],
            &[
                ("C:\\Users\\u\\.ssh", "r"),
                ("c:\\users\\U\\.ssh\\inner", "rwx"),
            ][..],
        ] {
            assert!(check(new).is_err(), "{new:?}");
        }
        assert_eq!(
            check(&[("C:\\Users\\u\\.ssh", "r"), ("C:/Users/u/.ssh/inner", "r")]),
            Ok(())
        );
        assert_eq!(
            check(&[("C:\\Users\\u\\.ssh", "r"), ("C:\\Users\\u\\work", "rwx")]),
            Ok(())
        );
    }

    fn reopen(dir: &Path) -> Result<SettingsStore, String> {
        SettingsStore::open(
            dir.join("node.toml"),
            dir.join("config.key"),
            AuditLog::new(dir.join("audit.jsonl")),
        )
    }

    fn refusals(s: &SettingsStore) -> usize {
        let log = s.audit().read().unwrap();
        log.iter().filter(|v| v["event"] == "refused").count()
    }

    #[test]
    fn a_file_from_before_the_mac_is_signed_once() {
        let d = tempfile::tempdir().unwrap();
        let mut old = NodeConfig::default();
        old.limits.max_running = 3;
        old.save(&d.path().join("node.toml")).unwrap();
        // Readable as it is before the node first opens it ...
        let peeked = SettingsStore::peek(&d.path().join("node.toml"), &d.path().join("config.key"));
        assert_eq!(peeked.unwrap(), old);
        // ... and signed when it does.
        let s = reopen(d.path()).unwrap();
        assert_eq!(s.config(), &old);
        let text = std::fs::read_to_string(s.path()).unwrap();
        assert!(text.starts_with(MAC_LINE), "{text}");
        let log = s.audit().read().unwrap();
        assert_eq!(log.last().unwrap()["event"], "signed");
        // Once there is a key, an unsigned file is refused.
        old.save(s.path()).unwrap();
        assert!(reopen(d.path()).err().unwrap().contains("refused"));
        let e = SettingsStore::peek(s.path(), &d.path().join("config.key")).unwrap_err();
        assert!(e.contains("nerve-node config accept"), "{e}");
    }

    #[test]
    fn reload_takes_only_a_newer_signed_file_in_reach() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), SettingsGrant::Off);
        let mut other = reopen(d.path()).unwrap();
        // Signed by the owner's path elsewhere (the CLI while no socket
        // answers): taken.
        other
            .update(|c| {
                c.limits.max_running = 2;
                Ok(())
            })
            .unwrap();
        assert_eq!(s.reload(), Ok(true));
        assert_eq!(s.config().limits.max_running, 2);
        assert_eq!(s.reload(), Ok(false));
        // An older signed file is refused: it would undo owner changes.
        let older = std::fs::read(s.path()).unwrap();
        s.update(|c| {
            c.limits.max_running = 5;
            Ok(())
        })
        .unwrap();
        std::fs::write(s.path(), older).unwrap();
        assert!(s.reload().unwrap_err().contains("older"));
        assert_eq!(s.config().limits.max_running, 5);
        // A missing file changes nothing either.
        std::fs::remove_file(s.path()).unwrap();
        assert!(s.reload().is_err());
        assert_eq!(s.config().limits.max_running, 5);
        assert_eq!(refusals(&s), 2);
    }

    #[test]
    fn a_time_limit_is_the_owners_choice_and_has_no_cap() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), SettingsGrant::Write);
        let now = nerve_proto::msg::now_ms();
        let year = 365 * 24 * 3_600_000;
        let set = |mode: Mode, until: Option<u64>| {
            move |c: &mut NodeConfig| {
                let p = &mut c.centers[0].policy;
                p.mode = mode;
                p.until = until;
                Ok(())
            }
        };
        // User mode with no limit, and with one a year ahead, are both fine.
        s.update(set(Mode::User, None)).unwrap();
        s.update(set(Mode::User, Some(now + year))).unwrap();
        s.update(set(Mode::Folder, Some(now + 10 * year))).unwrap();
        // A signed file that reaches far ahead is applied on reload as well.
        let mut far = s.config().clone();
        far.version += 1;
        far.centers[0].policy.mode = Mode::User;
        far.centers[0].policy.until = Some(now + 10 * year);
        std::fs::write(s.path(), sealed(&s.key, &far)).unwrap();
        assert_eq!(s.reload(), Ok(true));
        let p = &s.config().centers[0].policy;
        assert_eq!(p.until, Some(now + 10 * year));
        assert_eq!(p.mode_at(now), Mode::User);
        // A center may set the limit in its own document too.
        let v = s.version();
        let mut new = doc(&s);
        new["policy"]["mode"] = json!("user");
        new["policy"]["until"] = json!(now + year);
        s.set_center_document("home", new, v, |_| false, unix)
            .unwrap();
        // Once the limit has passed, the center is back in default deny.
        let past = s.config().centers[0].policy.clone();
        assert_eq!(past.mode_at(now + year), Mode::Allowlist);
        assert_eq!(refusals(&s), 0);
    }

    #[test]
    fn accept_takes_a_refused_file_and_signs_it() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), SettingsGrant::Off);
        let v = s.version();
        let mut edited = s.config().clone();
        edited.limits.max_running = 7;
        edited.save(s.path()).unwrap();
        assert!(s.reload().is_err());
        assert_eq!(s.accept().unwrap(), v + 1);
        assert_eq!(s.config().limits.max_running, 7);
        assert_eq!(reopen(d.path()).unwrap().config(), s.config());
        let log = s.audit().read().unwrap();
        assert!(log.iter().any(|e| e["event"] == "accepted"));
        assert!(
            log.last().unwrap()["changes"]
                .to_string()
                .contains("max_running")
        );
        // Without a running store: the file is taken as it is.
        let mut edited = s.config().clone();
        edited.limits.max_running = 9;
        edited.save(s.path()).unwrap();
        assert!(reopen(d.path()).is_err());
        let (t, v) = SettingsStore::open_accepting(
            s.path(),
            d.path().join("config.key"),
            AuditLog::new(d.path().join("audit.jsonl")),
        )
        .unwrap();
        assert_eq!(t.config().limits.max_running, 9);
        assert_eq!(reopen(d.path()).unwrap().version(), v);
        // What does not validate is not taken.
        std::fs::write(s.path(), "[limits]\nmax_running = 0\n").unwrap();
        assert!(matches!(s.accept(), Err(SetError::Invalid(_))));
    }

    /// A folder that is a link into a protected entry, or passes through
    /// one, is judged where it leads, since Landlock follows the link: a
    /// center may add it only where the owner's folders release that place
    /// with its flags. The protected entry is the `.ssh` of a home in a temp
    /// dir.
    #[cfg(unix)]
    #[test]
    fn a_center_cannot_reach_a_protected_path_through_a_link() {
        let d = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(d.path()).unwrap().join("home");
        let ssh = home.join(".ssh");
        let work = home.join("work");
        std::fs::create_dir_all(&ssh).unwrap();
        std::fs::create_dir_all(work.join("plain")).unwrap();
        std::os::unix::fs::symlink(&ssh, work.join("link")).unwrap();
        let at = |p: &Path| p.display().to_string();
        let prot =
            |o: &ProtectedOptions| Protected::new(&crate::protected::Platform::Unix, &home, &[], o);
        let mut s = owner_folders(d.path(), &[]);
        let refused = |s: &mut SettingsStore, path: &Path, access: &str| {
            let new = with_folders(s, json!([{"path": at(path), "access": access}]));
            let e = s.set_center_document("home", new, s.version(), |_| false, prot);
            matches!(&e, Err(SetError::Forbidden(m))
                if m.contains("policy.folders") && m.contains(&at(&ssh)))
        };
        assert!(refused(&mut s, &work.join("link"), "rw"));
        assert!(refused(&mut s, &work.join("link"), "r"));
        assert!(refused(&mut s, &work.join("link/not-yet"), "x"));
        assert!(!refused(&mut s, &work.join("plain"), "rwx"));
        // The owner released `.ssh` for reading: a link there may read, and
        // no more.
        s.update(|c| {
            c.center_mut("home").unwrap().policy.folders = vec![folder(&at(&ssh), "r")];
            Ok(())
        })
        .unwrap();
        let owner = json!({"path": at(&ssh), "access": "r"});
        for (access, ok) in [("r", true), ("rw", false), ("rx", false)] {
            let link = json!({"path": at(&work.join("link")), "access": access});
            let new = with_folders(&s, json!([owner.clone(), link]));
            let e = s.set_center_document("home", new, s.version(), |_| false, prot);
            assert_eq!(e.is_ok(), ok, "{access}: {e:?}");
        }
    }

    #[test]
    fn local_writes_check_version_and_validate() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), SettingsGrant::Off);
        let v = s.version();
        let mut c = s.config().clone();
        c.limits.max_running = 0;
        assert!(matches!(s.set_local(c, Some(v)), Err(SetError::Invalid(_))));
        let mut c = s.config().clone();
        c.limits.max_running = 2;
        assert_eq!(
            s.set_local(c.clone(), Some(v + 7)),
            Err(SetError::Conflict { current: v })
        );
        assert_eq!(s.set_local(c, Some(v)).unwrap(), v + 1);
        let log = s.audit().read().unwrap();
        assert_eq!(log.last().unwrap()["by"], "local");
        // An unchanged config is no new version.
        let same = s.config().clone();
        assert_eq!(s.set_local(same, None).unwrap(), v + 1);
    }
}
